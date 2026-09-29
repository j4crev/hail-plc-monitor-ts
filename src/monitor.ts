import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { isDeepStrictEqual } from "node:util";
import { cidForCbor } from "@atproto/common";
import { validateOperationLog, type DocumentData } from "@did-plc/lib";
import type { SQL } from "bun";
import type { MonitorPlcClient } from "./plc.js";
import type { MonitorSigner } from "./signing.js";

export interface MonitorPollResult {
  state: "current" | "unavailable" | "gap" | "invalid-log";
  lastSeq: number;
  inspected: number;
  alerts: number;
}

export class PlcMonitor {
  constructor(private readonly sql: SQL, private readonly plc: MonitorPlcClient,
    private readonly now: () => Date = () => new Date()) {}

  async enroll(did: string, expectedCid: string, alertWebhookUrl: string): Promise<void> {
    if (!/^did:plc:[a-z2-7]{24}$/.test(did) || !/^b[a-z2-7]+$/.test(expectedCid)) {
      throw new Error("Monitor DID or expected PLC CID is not canonical");
    }
    assertWebhookUrl(alertWebhookUrl);
    const current = await this.readState(did);
    if (current.cid !== expectedCid) throw new Error("Expected PLC CID does not match current valid state");
    const enrolledAt = this.now();
    await this.sql.begin(async (tx) => {
      await tx`INSERT INTO monitored_dids (did, expected_cid, expected_state, alert_webhook_url,
        enrolled_at, last_verified_cid, last_verified_at)
        VALUES (${did}, ${expectedCid}, ${JSON.stringify(current.state)}::jsonb,
          ${alertWebhookUrl}, ${enrolledAt}, ${expectedCid}, ${enrolledAt})`;
      await tx`UPDATE monitor_cursor SET last_healthy_at = COALESCE(last_healthy_at, ${enrolledAt})
        WHERE singleton = true`;
    });
  }

  async poll(count = 100): Promise<MonitorPollResult> {
    return this.sql.begin(async (tx): Promise<MonitorPollResult> => {
      const cursor = await tx<{ last_seq: number | string | bigint; last_healthy_at: Date | null }[]>`
        SELECT last_seq, last_healthy_at FROM monitor_cursor WHERE singleton = true FOR UPDATE`;
      const before = Number(cursor[0]?.last_seq);
      if (!Number.isSafeInteger(before)) throw new Error("Monitor cursor is unsafe");
      const now = this.now();
      let alerts = 0;
      const monitored = await tx<{ did: string }[]>`SELECT did FROM monitored_dids ORDER BY did`;
      if (cursor[0]?.last_healthy_at && now.getTime() - cursor[0].last_healthy_at.getTime() > 86_400_000) {
        for (const row of monitored) alerts += await this.alert(tx, row.did, "coverage-lost",
          `coverage:${row.did}:${cursor[0].last_healthy_at.toISOString()}`,
          { lastHealthyAt: cursor[0].last_healthy_at.toISOString(), observedAt: now.toISOString() });
      }
      let exported;
      try { exported = await this.plc.exportAfter(before, count); }
      catch { return { state: "unavailable", lastSeq: before, inspected: 0, alerts }; }
      let next = before;
      let inspected = 0;
      for (const entry of exported) {
        if (entry.seq !== next + 1) {
          for (const row of monitored) alerts += await this.alert(tx, row.did, "export-gap",
            `gap:${row.did}:${next}:${entry.seq}`,
            { expectedSeq: next + 1, receivedSeq: entry.seq });
          return { state: "gap", lastSeq: before, inspected, alerts };
        }
        const watched = await tx<{ expected_cid: string; expected_state: unknown }[]>`
          SELECT expected_cid, expected_state FROM monitored_dids WHERE did = ${entry.did}`;
        if (watched[0]) {
          try {
            if ((await cidForCbor(entry.operation)).toString() !== entry.cid) {
              throw new Error("Sequenced operation CID does not match its bytes");
            }
            const current = await this.readState(entry.did);
            const approvedState = typeof watched[0].expected_state === "string"
              ? JSON.parse(watched[0].expected_state) as DocumentData : watched[0].expected_state;
            const expected = current.cid === watched[0].expected_cid && isDeepStrictEqual(current.state, approvedState);
            await tx`INSERT INTO monitor_observations (did, cid, seq, operation, expected)
              VALUES (${entry.did}, ${entry.cid}, ${entry.seq}, ${JSON.stringify(entry.operation)}::jsonb,
                ${expected}) ON CONFLICT (did, cid) DO NOTHING`;
            if (!expected) {
              alerts += await this.alert(tx, entry.did, "unexpected-operation", `operation:${entry.did}:${entry.cid}`,
                { operationCid: entry.cid, currentCid: current.cid, expectedCid: watched[0].expected_cid });
            } else {
              await tx`UPDATE monitored_dids SET last_verified_cid = ${current.cid}, last_verified_at = ${now}
                WHERE did = ${entry.did}`;
            }
          } catch {
            alerts += await this.alert(tx, entry.did, "invalid-operation-log", `invalid:${entry.did}:${entry.cid}`,
              { operationCid: entry.cid });
            return { state: "invalid-log", lastSeq: before, inspected, alerts };
          }
          inspected += 1;
        }
        next = entry.seq;
      }
      await tx`UPDATE monitor_cursor SET last_seq = ${next}, last_healthy_at = ${now}, updated_at = ${now}
        WHERE singleton = true`;
      return { state: "current", lastSeq: next, inspected, alerts };
    });
  }

  // A user-run host's local operator approves the complete reviewed PLC state.
  // A provider-hosted bootstrap monitor cannot treat its own approval as
  // provider-independent user authorization.
  async approveExpected(did: string, cid: string, reviewed: DocumentData): Promise<void> {
    const current = await this.readState(did);
    if (current.cid !== cid || !isDeepStrictEqual(current.state, reviewed)) {
      throw new Error("Reviewed PLC CID or complete expected state does not match the validated log");
    }
    await this.sql.begin(async (tx) => {
      const rows = await tx<{ expected_cid: string }[]>`
        SELECT expected_cid FROM monitored_dids WHERE did = ${did} FOR UPDATE`;
      const previous = rows[0];
      if (!previous || previous.expected_cid === cid) throw new Error("No new monitored operation to approve");
      const observation = await tx<{ cid: string }[]>`
        SELECT cid FROM monitor_observations WHERE did = ${did} AND cid = ${cid}`;
      if (!observation.length) throw new Error("Operation has not been observed in the sequenced export");
      await tx`INSERT INTO monitor_approvals (did, operation_cid, previous_expected_cid, approved_state)
        VALUES (${did}, ${cid}, ${previous.expected_cid}, ${JSON.stringify(reviewed)}::jsonb)`;
      await tx`UPDATE monitored_dids SET expected_cid = ${cid}, expected_state = ${JSON.stringify(reviewed)}::jsonb,
        last_verified_cid = ${cid}, last_verified_at = ${this.now()} WHERE did = ${did}`;
    });
  }

  async attest(did: string, transferId: string, operationCid: string, origin: string,
    signer: MonitorSigner): Promise<{ payloadBytes: Uint8Array; signature: Uint8Array }> {
    const current = await this.readState(did);
    if (current.cid !== operationCid) throw new Error("Monitor cannot attest a noncurrent PLC operation");
    const rows = await this.sql<{ expected_cid: string; expected_state: unknown; enrolled_at: Date;
      last_healthy_at: Date | null; approved: number; notified: number; gaps: number }[]>`
      SELECT watched.expected_cid, watched.expected_state, watched.enrolled_at,
        cursor.last_healthy_at,
        (SELECT count(*)::int FROM monitor_approvals approved WHERE approved.did = ${did}
          AND approved.operation_cid = ${operationCid}) AS approved,
        (SELECT count(*)::int FROM monitor_alerts alert WHERE alert.did = ${did}
          AND alert.correlation = ${`operation:${did}:${operationCid}`} AND alert.sent_at IS NOT NULL) AS notified,
        (SELECT count(*)::int FROM monitor_alerts alert WHERE alert.did = ${did}
          AND alert.category IN ('coverage-lost', 'export-gap', 'invalid-operation-log')) AS gaps
      FROM monitored_dids watched CROSS JOIN monitor_cursor cursor
      WHERE watched.did = ${did} AND cursor.singleton = true
    `;
    const watched = rows[0];
    const expectation = typeof watched?.expected_state === "string"
      ? JSON.parse(watched.expected_state) as DocumentData : watched?.expected_state;
    const now = this.now();
    if (!watched || watched.expected_cid !== operationCid ||
      !isDeepStrictEqual(current.state, expectation) ||
      watched.approved !== 1 || watched.notified < 1 || watched.gaps !== 0 ||
      !watched.last_healthy_at || now.getTime() - watched.last_healthy_at.getTime() > 300_000) {
      throw new Error("Independent monitor approval or uninterrupted coverage is unavailable");
    }
    const url = new URL(origin);
    if (url.protocol !== "https:" || url.origin !== origin || url.username || url.password) {
      throw new Error("Monitor attestation origin must be canonical HTTPS");
    }
    return signer.signCoverage({ type: "hail.plc-monitor-attestation", version: 1,
      did, transfer_id: transferId, operation_cid: operationCid, monitor_origin: origin,
      coverage_since: Math.floor(watched.enrolled_at.getTime() / 1000),
      observed_at: Math.floor(now.getTime() / 1000) });
  }

  private async readState(did: string): Promise<{ cid: string; state: DocumentData }> {
    const [log, data, audit] = await Promise.all([
      this.plc.getOperationLog(did), this.plc.getDocumentData(did), this.plc.getAuditableLog(did),
    ]);
    const state = await validateOperationLog(did, log);
    const last = log[log.length - 1];
    if (!state || !last || !isDeepStrictEqual(state, data)) throw new Error("PLC log and complete current state disagree");
    const cid = (await cidForCbor(last)).toString();
    const current = audit[audit.length - 1];
    if (!current || current.did !== did || current.cid !== cid || current.nullified) {
      throw new Error("PLC audit does not confirm the current non-nullified operation");
    }
    return { cid, state };
  }

  private async alert(tx: SQL, did: string | null, category: string, correlation: string,
    detail: object): Promise<number> {
    const inserted = await tx<{ id: string }[]>`
      INSERT INTO monitor_alerts (id, did, category, correlation, detail)
      VALUES (${randomUUID()}, ${did}, ${category}, ${correlation}, ${JSON.stringify(detail)}::jsonb)
      ON CONFLICT (correlation) DO NOTHING RETURNING id`;
    return inserted.length;
  }
}

export function assertWebhookUrl(value: string): URL {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password || url.hash || url.search ||
    !url.hostname || url.hostname.endsWith(".") || isIP(url.hostname) !== 0 ||
    !/^[a-z0-9.-]+$/.test(url.hostname)) {
    throw new Error("Monitor alert destination must be a canonical HTTPS DNS URL");
  }
  return url;
}
