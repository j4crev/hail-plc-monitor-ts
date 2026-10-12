import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { isDeepStrictEqual } from "node:util";
import { cidForCbor } from "@atproto/common";
import { def, validateOperationLog, type DocumentData } from "@did-plc/lib";
import type { SQL } from "bun";
import { plcStateDigest, type MonitorPlcClient } from "./plc.js";
import type { MonitorSigner } from "./signing.js";

export interface MonitorPollResult {
  state: "current" | "backfilling" | "unavailable" | "gap" | "invalid-log";
  lastSeq: number;
  inspected: number;
  alerts: number;
}

export class PlcMonitor {
  constructor(private readonly sql: SQL, private readonly plc: MonitorPlcClient,
    private readonly now: () => Date = () => new Date()) {}

  async enroll(did: string, expectedCid: string, alertWebhookUrl: string, reviewed?: DocumentData): Promise<void> {
    if (!/^did:plc:[a-z2-7]{24}$/.test(did) || !/^b[a-z2-7]+$/.test(expectedCid)) {
      throw new Error("Monitor DID or expected PLC CID is not canonical");
    }
    assertWebhookUrl(alertWebhookUrl);
    const current = await this.readState(did);
    if (current.cid !== expectedCid) throw new Error("Expected PLC CID does not match current valid state");
    if (reviewed !== undefined && !isDeepStrictEqual(def.documentData.strict().parse(reviewed), current.state)) {
      throw new Error("Reviewed bootstrap checkpoint does not match the complete current PLC state");
    }
    const enrolledAt = this.now();
    await this.sql.begin(async (tx) => {
      await tx`SELECT singleton FROM monitor_cursor WHERE singleton = true FOR UPDATE`;
      await tx`INSERT INTO monitored_dids (did, expected_cid, expected_state, alert_webhook_url,
        enrolled_at, last_verified_cid, last_verified_at)
        VALUES (${did}, ${expectedCid}, ${JSON.stringify(current.state)}::jsonb,
          ${alertWebhookUrl}, ${enrolledAt}, ${expectedCid}, ${enrolledAt})`;
      if (reviewed !== undefined) {
        await tx`INSERT INTO monitor_bootstrap_checkpoints (did, operation_cid, reviewed_state, reviewed_at)
          VALUES (${did}, ${expectedCid}, ${JSON.stringify(current.state)}::jsonb, ${enrolledAt})`;
        await this.alert(tx, did, "onboarding-enrollment", `onboarding:${did}:${expectedCid}`,
          { operationCid: expectedCid, enrolledAt: enrolledAt.toISOString() });
        await tx`UPDATE monitor_cursor SET caught_up=false,last_healthy_at=NULL,updated_at=${enrolledAt} WHERE singleton=true`;
      }
    });
  }

  async poll(count = 100): Promise<MonitorPollResult> {
    if (!Number.isSafeInteger(count) || count < 1 || count > 100) throw new Error("Monitor poll count must be 1–100");
    return this.sql.begin(async (tx): Promise<MonitorPollResult> => {
      const cursor = await tx<{ last_seq: number | string | bigint; last_healthy_at: Date | null }[]>`
        SELECT last_seq, last_healthy_at FROM monitor_cursor WHERE singleton = true FOR UPDATE`;
      const before = Number(cursor[0]?.last_seq);
      if (!Number.isSafeInteger(before)) throw new Error("Monitor cursor is unsafe");
      const now = this.now();
      // Retain the last healthy time for downtime detection, but do not let a
      // failed/new partial batch preserve the previous readiness assertion.
      await tx`UPDATE monitor_cursor SET caught_up = false, updated_at = ${now} WHERE singleton = true`;
      let alerts = 0;
      const monitored = await tx<{ did: string; enrolled_at: Date }[]>`SELECT did, enrolled_at FROM monitored_dids ORDER BY did`;
      for (const row of monitored) {
        const lastHealthy = cursor[0]?.last_healthy_at;
        const baseline = lastHealthy && lastHealthy > row.enrolled_at ? lastHealthy : row.enrolled_at;
        if (now.getTime() - baseline.getTime() > 86_400_000) alerts += await this.alert(tx, row.did, "coverage-lost",
          `coverage:${row.did}:${baseline.toISOString()}`,
          { lastHealthyAt: lastHealthy?.toISOString() ?? null, enrolledAt: row.enrolled_at.toISOString(), observedAt: now.toISOString() });
      }
      let exported;
      try {
        exported = await this.plc.exportAfter(before, count);
        if (exported.length > count) throw new Error("PLC export exceeds requested page size");
      }
      catch { return { state: "unavailable", lastSeq: before, inspected: 0, alerts }; }
      let next = before;
      let inspected = 0;
      for (const entry of exported) {
        if (!Number.isSafeInteger(entry.seq) || entry.seq !== next + 1) {
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
      const caughtUp = exported.length < count;
      await tx`UPDATE monitor_cursor SET last_seq = ${next}, caught_up = ${caughtUp},
        last_healthy_at = CASE WHEN ${caughtUp} THEN ${now} ELSE last_healthy_at END, updated_at = ${now}
        WHERE singleton = true`;
      return { state: caughtUp ? "current" : "backfilling", lastSeq: next, inspected, alerts };
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
    if (!/^did:plc:[a-z2-7]{24}$/.test(did) || !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(transferId) ||
      !/^b[a-z2-7]+$/.test(operationCid) || assertWebhookUrl(origin).origin !== origin) {
      throw new Error("Monitor attestation needs a canonical DID, transfer ID, CID and HTTPS origin");
    }
    const current = await this.readState(did);
    if (current.cid !== operationCid) throw new Error("Monitor cannot attest a noncurrent PLC operation");
    return this.sql.begin(async tx => {
    // Same cursor-first lock order as poll: an in-flight failing poll cannot
    // race an attestation based on its previously committed readiness.
    await tx`SELECT singleton FROM monitor_cursor WHERE singleton = true FOR SHARE`;
    const rows = await tx<{ expected_cid: string; expected_state: unknown; enrolled_at: Date;
      last_healthy_at: Date | null; caught_up: boolean; last_seq: string | bigint | number;
      bootstrap_cid: string | null; bootstrap_state: unknown;
      approved: number; notified: number; gaps: number }[]>`
      SELECT watched.expected_cid, watched.expected_state, watched.enrolled_at,
        cursor.last_healthy_at, cursor.caught_up, cursor.last_seq,
        bootstrap.operation_cid AS bootstrap_cid, bootstrap.reviewed_state AS bootstrap_state,
        (SELECT count(*)::int FROM monitor_approvals approved WHERE approved.did = ${did}
          AND approved.operation_cid = ${operationCid}) AS approved,
        (SELECT count(*)::int FROM monitor_alerts alert WHERE alert.did = ${did}
          AND alert.correlation = ${`operation:${did}:${operationCid}`} AND alert.sent_at IS NOT NULL) AS notified,
        (SELECT count(*)::int FROM monitor_alerts alert WHERE alert.did = ${did}
          AND alert.category IN ('coverage-lost', 'export-gap', 'invalid-operation-log')) AS gaps
      FROM monitored_dids watched CROSS JOIN monitor_cursor cursor
      LEFT JOIN monitor_bootstrap_checkpoints bootstrap ON bootstrap.did = watched.did
      WHERE watched.did = ${did} AND cursor.singleton = true FOR SHARE OF watched
    `;
    const watched = rows[0];
    const expectation = typeof watched?.expected_state === "string"
      ? JSON.parse(watched.expected_state) as DocumentData : watched?.expected_state;
    const now = this.now();
    if (!watched || watched.expected_cid !== operationCid ||
      !isDeepStrictEqual(current.state, expectation) ||
      watched.approved !== 1 || watched.notified < 1 || watched.gaps !== 0 ||
      !watched.caught_up || !watched.last_healthy_at || now.getTime() - watched.last_healthy_at.getTime() > 300_000 ||
      watched.last_healthy_at.getTime() > now.getTime() + 300_000 || watched.enrolled_at.getTime() > now.getTime() + 300_000) {
      throw new Error("Independent monitor approval or uninterrupted coverage is unavailable");
    }
    const sequence = Number(watched.last_seq);
    if (!Number.isSafeInteger(sequence) || sequence < 1) throw new Error("Monitor export checkpoint is unsafe");
    const bootstrap = typeof watched.bootstrap_state === "string"
      ? JSON.parse(watched.bootstrap_state) as DocumentData : watched.bootstrap_state as DocumentData;
    return signer.signCoverage({ type: "hail.plc-monitor-attestation", version: watched.bootstrap_cid ? 2 : 1,
      did, transfer_id: transferId, operation_cid: operationCid, monitor_origin: origin,
      coverage_since: Math.floor(watched.enrolled_at.getTime() / 1000),
      observed_at: Math.floor(now.getTime() / 1000),
      ...(watched.bootstrap_cid ? { bootstrap_cid: watched.bootstrap_cid, bootstrap_state_digest: plcStateDigest(bootstrap), export_sequence: sequence } : {}) });
    });
  }

  async attestOnboarding(did: string, operationCid: string, origin: string,
    signer: MonitorSigner): Promise<{ payloadBytes: Uint8Array; signature: Uint8Array }> {
    if (!/^did:plc:[a-z2-7]{24}$/.test(did) || !/^b[a-z2-7]+$/.test(operationCid) ||
      assertWebhookUrl(origin).origin !== origin) throw new Error("Onboarding attestation needs a canonical DID, CID and HTTPS origin");
    const current = await this.readState(did);
    if (current.cid !== operationCid) throw new Error("Monitor cannot attest a noncurrent onboarding operation");
    return this.sql.begin(async tx => {
      await tx`SELECT singleton FROM monitor_cursor WHERE singleton = true FOR SHARE`;
      const watched = (await tx<{ expected_cid: string; expected_state: unknown; enrolled_at: Date;
        last_healthy_at: Date | null; caught_up: boolean; last_seq: string | bigint | number;
        bootstrap_cid: string | null; bootstrap_state: unknown; gaps: number; notified: number }[]>`
        SELECT watched.expected_cid, watched.expected_state, watched.enrolled_at,
          cursor.last_healthy_at, cursor.caught_up, cursor.last_seq,
          bootstrap.operation_cid AS bootstrap_cid, bootstrap.reviewed_state AS bootstrap_state,
          (SELECT count(*)::int FROM monitor_alerts alert WHERE alert.did = ${did}
            AND alert.category = 'onboarding-enrollment' AND alert.sent_at IS NOT NULL) AS notified,
          (SELECT count(*)::int FROM monitor_alerts alert WHERE alert.did = ${did}
            AND alert.category IN ('coverage-lost', 'export-gap', 'invalid-operation-log')) AS gaps
        FROM monitored_dids watched CROSS JOIN monitor_cursor cursor
        LEFT JOIN monitor_bootstrap_checkpoints bootstrap ON bootstrap.did = watched.did
        WHERE watched.did = ${did} AND cursor.singleton = true FOR SHARE OF watched
      `)[0];
      const expected = typeof watched?.expected_state === "string" ? JSON.parse(watched.expected_state) : watched?.expected_state;
      const bootstrap = typeof watched?.bootstrap_state === "string" ? JSON.parse(watched.bootstrap_state) : watched?.bootstrap_state;
      const now = this.now(), sequence = Number(watched?.last_seq);
      if (!watched || watched.expected_cid !== operationCid || watched.bootstrap_cid !== operationCid ||
        !isDeepStrictEqual(current.state, expected) || !isDeepStrictEqual(current.state, bootstrap) ||
        watched.gaps !== 0 || watched.notified !== 1 || !watched.caught_up || !watched.last_healthy_at ||
        watched.last_healthy_at.getTime() < watched.enrolled_at.getTime() ||
        now.getTime() - watched.last_healthy_at.getTime() > 300_000 ||
        watched.last_healthy_at.getTime() > now.getTime() + 300_000 || !Number.isSafeInteger(sequence) || sequence < 1) {
        throw new Error("Independent onboarding monitor coverage is unavailable");
      }
      return signer.signOnboardingCoverage({ type: "hail.plc-onboarding-monitor-attestation", version: 1,
        did, operation_cid: operationCid, monitor_origin: origin,
        coverage_since: Math.floor(watched.enrolled_at.getTime() / 1000),
        observed_at: Math.floor(now.getTime() / 1000), bootstrap_state_digest: plcStateDigest(current.state),
        export_sequence: sequence });
    });
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
    if (!current || current.did !== did || current.cid !== cid || current.nullified ||
      !isDeepStrictEqual(current.operation, last) ||
      !isDeepStrictEqual(audit.filter(entry => !entry.nullified).map(entry => entry.operation), log)) {
      throw new Error("PLC audit does not confirm the current non-nullified operation");
    }
    const seen = new Set<string>();
    for (const entry of audit) {
      if (entry.did !== did || seen.has(entry.cid) || !Number.isFinite(Date.parse(entry.createdAt)) ||
        (await cidForCbor(entry.operation)).toString() !== entry.cid) throw new Error("PLC audit bytes or annotations disagree with the log");
      seen.add(entry.cid);
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
    !url.hostname || isIP(url.hostname) !== 0 || url.hostname.length > 253 ||
    url.hostname.split(".").some(label => label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) {
    throw new Error("Monitor alert destination must be a canonical HTTPS DNS URL");
  }
  return url;
}
