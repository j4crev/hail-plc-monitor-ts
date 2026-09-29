import { cidForCbor } from "@atproto/common";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { P256Keypair } from "@atproto/crypto";
import { didForCreateOp, signOperation, validateOperationLog, type CompatibleOpOrTombstone,
  type ExportedOpWithSeq } from "@did-plc/lib";
import { base58btc } from "multiformats/bases/base58";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MonitorDatabase } from "../src/database.js";
import { PlcMonitor } from "../src/monitor.js";
import { MonitorNotifier, type AlertTransport } from "../src/notifier.js";
import type { MonitorPlcClient } from "../src/plc.js";
import { MonitorSigner } from "../src/signing.js";
import { verifyMonitorAttestation } from "../../hail-server-ts/src/migration/monitor-attestation.js";

const integration = process.env.DATABASE_URL ? describe : describe.skip;

async function identityKey() {
  const key = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  const bytes = new Uint8Array(34);
  bytes.set([0xed, 0x01]);
  bytes.set(new Uint8Array(await crypto.subtle.exportKey("raw", key.publicKey)), 2);
  return `did:key:${base58btc.encode(bytes)}`;
}

integration("independent monitor durable cursor", () => {
  let db: MonitorDatabase;
  let did: string;
  let key: P256Keypair;
  let genesis: CompatibleOpOrTombstone;
  let cid: string;
  let log: CompatibleOpOrTombstone[];
  let exported: ExportedOpWithSeq[];
  let tick = Date.now();
  let corrupt = false;
  const observed = () => new Date(tick);
  const client: MonitorPlcClient = {
    async exportAfter(after, count) { return exported.filter((entry) => entry.seq > after).slice(0, count); },
    async getOperationLog() { return log; },
    async getDocumentData() {
      const state = await validateOperationLog(did, log);
      if (!state) throw new Error("Invalid fixture log");
      return corrupt ? { ...state, alsoKnownAs: ["https://tampered.example.com"] } : state;
    },
    async getAuditableLog() {
      return Promise.all(log.map(async (operation) => ({ did, operation,
        cid: (await cidForCbor(operation)).toString(), nullified: false,
        createdAt: observed().toISOString() })));
    },
  };

  beforeAll(async () => {
    db = new MonitorDatabase(process.env.DATABASE_URL!);
    await db.migrate();
    const existing = await db.sql<{ count: number; last_seq: number | bigint | string }[]>`
      SELECT (SELECT count(*)::int FROM monitored_dids) AS count, last_seq
      FROM monitor_cursor WHERE singleton = true`;
    if (existing[0]?.count !== 0 || Number(existing[0].last_seq) !== 0) {
      throw new Error("Monitor integration requires an empty disposable database");
    }
    key = await P256Keypair.create({ exportable: true });
    const [identity, messaging] = await Promise.all([identityKey(), identityKey()]);
    const operation = await signOperation({ type: "plc_operation", rotationKeys: [key.did()],
      verificationMethods: { "hail-identity": identity, "hail-messaging": messaging },
      alsoKnownAs: [], services: { hail: { type: "HailMessaging", endpoint: "https://sender.example.com/hail" } },
      prev: null }, key);
    genesis = operation;
    did = await didForCreateOp(operation);
    cid = (await cidForCbor(operation)).toString();
    log = [operation];
    exported = [{ did, operation, cid, seq: 1, type: "sequenced_op", createdAt: observed().toISOString() }];
  });

  afterAll(async () => {
    if (!db) return;
    if (did) {
      await db.sql`DELETE FROM monitor_alerts WHERE did = ${did}`;
      await db.sql`DELETE FROM monitor_observations WHERE did = ${did}`;
      await db.sql`DELETE FROM monitor_approvals WHERE did = ${did}`;
      await db.sql`DELETE FROM monitored_dids WHERE did = ${did}`;
      const remaining = await db.sql<{ count: number }[]>`SELECT count(*)::int AS count FROM monitored_dids`;
      if (remaining[0]?.count === 0) {
        await db.sql`UPDATE monitor_cursor SET last_seq = 0, last_healthy_at = NULL WHERE singleton = true`;
      }
    }
    await db.close();
  });

  it("enrolls a validated DID, advances an exact sequence and alerts on unexpected changes", async () => {
    const monitor = new PlcMonitor(db.sql, client, observed);
    await monitor.enroll(did, cid, "https://user.example.com/alerts");
    expect(await monitor.poll()).toMatchObject({ state: "current", lastSeq: 1, inspected: 1, alerts: 0 });
    const updated = await signOperation({ type: "plc_operation", rotationKeys: [key.did()],
      verificationMethods: { "hail-identity": (genesis as { verificationMethods: Record<string, string> }).verificationMethods["hail-identity"]!,
        "hail-messaging": (genesis as { verificationMethods: Record<string, string> }).verificationMethods["hail-messaging"]! },
      alsoKnownAs: ["https://changed.example.com"],
      services: { hail: { type: "HailMessaging", endpoint: "https://sender.example.com/hail" } },
      prev: cid }, key);
    log = [genesis, updated];
    const updateCid = (await cidForCbor(updated)).toString();
    exported.push({ did, operation: updated, cid: updateCid, seq: 2, type: "sequenced_op",
      createdAt: observed().toISOString() });
    expect(await monitor.poll()).toMatchObject({ state: "current", lastSeq: 2, inspected: 1, alerts: 1 });
    const alerts = await db.sql<{ category: string; sent_at: Date | null }[]>`
      SELECT category, sent_at FROM monitor_alerts WHERE did = ${did}`;
    expect(alerts[0]?.category).toBe("unexpected-operation");
    expect(alerts[0]?.sent_at).toBeNull();
    expect(await monitor.poll()).toMatchObject({ state: "current", lastSeq: 2, alerts: 0 });
    expect((await db.sql`SELECT id FROM monitor_alerts WHERE did = ${did}`)).toHaveLength(1);
  });

  it("signs coverage only after user-run approval and out-of-band notification", async () => {
    const signer = new MonitorSigner(generateKeyPairSync("ed25519").privateKey);
    const monitor = new PlcMonitor(db.sql, client, observed);
    await expect(monitor.attest(did, randomUUID(), exported[1]!.cid,
      "https://monitor.example.com", signer)).rejects.toThrow("approval or uninterrupted coverage");
    const notifier = new MonitorNotifier(db.sql, signer, { async send() { return 204; } }, observed);
    expect(await notifier.sendOne()).toBe("sent");
    const reviewed = await validateOperationLog(did, log);
    expect(reviewed).not.toBeNull();
    await monitor.approveExpected(did, exported[1]!.cid, reviewed!);
    const signed = await monitor.attest(did, randomUUID(), exported[1]!.cid,
      "https://monitor.example.com", signer);
    expect((await verifyMonitorAttestation(signed, signer.publicDidKey, Math.floor(tick / 1000))).did).toBe(did);
    await expect(monitor.approveExpected(did, cid, reviewed!)).rejects.toThrow();
  });

  it("records lost coverage after downtime and preserves the cursor after a restart", async () => {
    tick += 25 * 3600 * 1000;
    const monitor = new PlcMonitor(db.sql, client, observed);
    expect(await monitor.poll()).toMatchObject({ state: "current", lastSeq: 2, alerts: 1 });
    const restarted = new PlcMonitor(db.sql, client, observed);
    expect(await restarted.poll()).toMatchObject({ state: "current", lastSeq: 2, alerts: 0 });
    expect((await db.sql`SELECT id FROM monitor_alerts WHERE category = 'coverage-lost'`)).toHaveLength(1);
  });

  it("does not skip an export gap or accept an inconsistent operation log", async () => {
    const current = await signOperation({ type: "plc_operation", rotationKeys: [key.did()],
      verificationMethods: (genesis as { verificationMethods: Record<string, string> }).verificationMethods,
      alsoKnownAs: ["https://again.example.com"],
      services: { hail: { type: "HailMessaging", endpoint: "https://sender.example.com/hail" } },
      prev: (await cidForCbor(log[log.length - 1])).toString() }, key);
    const newCid = (await cidForCbor(current)).toString();
    exported.push({ did, operation: current, cid: newCid, seq: 4, type: "sequenced_op",
      createdAt: observed().toISOString() });
    const monitor = new PlcMonitor(db.sql, client, observed);
    expect(await monitor.poll()).toMatchObject({ state: "gap", lastSeq: 2, alerts: 1 });
    exported[exported.length - 1]!.seq = 3;
    log = [...log, current];
    corrupt = true;
    expect(await monitor.poll()).toMatchObject({ state: "invalid-log", lastSeq: 2, alerts: 1 });
    const cursor = await db.sql<{ last_seq: number | string | bigint }[]>`
      SELECT last_seq FROM monitor_cursor WHERE singleton = true`;
    expect(Number(cursor[0]?.last_seq)).toBe(2);
  });

  it("durably retries signed user alerts and interoperates with provider monitor verification", async () => {
    const signer = new MonitorSigner(generateKeyPairSync("ed25519").privateKey);
    let sends = 0;
    const transport: AlertTransport = { async send(url, bytes, signature, publicDidKey) {
      sends += 1;
      expect(url).toBe("https://user.example.com/alerts");
      expect(bytes.length).toBeGreaterThan(0);
      expect(signature).toHaveLength(64);
      expect(publicDidKey).toBe(signer.publicDidKey);
      return sends === 1 ? 503 : 204;
    } };
    const notifier = new MonitorNotifier(db.sql, signer, transport, observed);
    expect(await notifier.sendOne()).toBe("retry");
    const pending = await db.sql<{ attempt_count: number; sent_at: Date | null }[]>`
      SELECT attempt_count, sent_at FROM monitor_alerts WHERE category = 'coverage-lost'`;
    expect(pending[0]?.attempt_count).toBe(1);
    expect(pending[0]?.sent_at).toBeNull();
    await db.sql`UPDATE monitor_alerts SET next_attempt_at = now() - interval '1 second'
      WHERE category = 'coverage-lost'`;
    expect(await notifier.sendOne()).toBe("sent");
    const acknowledged = await db.sql<{ sent_at: Date | null }[]>`
      SELECT sent_at FROM monitor_alerts WHERE category = 'coverage-lost'`;
    expect(acknowledged[0]?.sent_at).not.toBeNull();
    const signed = signer.signCoverage({ type: "hail.plc-monitor-attestation", version: 1,
      did, transfer_id: randomUUID(), operation_cid: exported[1]!.cid,
      monitor_origin: "https://monitor.example.com", coverage_since: Math.floor(tick / 1000) - 3600,
      observed_at: Math.floor(tick / 1000) });
    expect((await verifyMonitorAttestation(signed, signer.publicDidKey, Math.floor(tick / 1000))).did).toBe(did);
  });
});
