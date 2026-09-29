import { MonitorDatabase } from "../database.js";
import { PlcMonitor } from "../monitor.js";
import { BoundedMonitorPlcClient } from "../plc.js";
import { MonitorSigner } from "../signing.js";

const [did, expectedCid, alertUrl] = Bun.argv.slice(2);
if (!did || !expectedCid || !alertUrl || Bun.argv.length !== 5 ||
  !Bun.env.DATABASE_URL || !Bun.env.PLC_DIRECTORY_URL || !Bun.env.MONITOR_PRIVATE_KEY_FILE) {
  throw new Error("Usage: bun run monitor:enroll -- <did> <expected-operation-cid> <https-user-alert-webhook>; set monitor environment");
}
const signer = await MonitorSigner.fromPrivateFile(Bun.env.MONITOR_PRIVATE_KEY_FILE);
const database = new MonitorDatabase(Bun.env.DATABASE_URL);
try {
  await database.migrate();
  await new PlcMonitor(database.sql, new BoundedMonitorPlcClient(Bun.env.PLC_DIRECTORY_URL))
    .enroll(did, expectedCid, alertUrl);
  console.info(JSON.stringify({ did, expectedCid, monitorPublicKey: signer.publicDidKey, state: "enrolled" }));
} finally { await database.close(); }
