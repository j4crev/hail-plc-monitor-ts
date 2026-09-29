# Independent Hail PLC Monitor

Prototype of a user-run monitor for the Hail portable-custody profile. The
monitor validates DID operation logs, durably tracks the PLC export sequence,
records unexpected operations and lost coverage, and signs bounded coverage
attestations for a provider migration. Hosting it on infrastructure controlled
by a Hail provider is a **bootstrap convenience**, not independent coverage
under `../hailproto/spec/account-onboarding.md`.

This project is intentionally a sibling of `hailproto`, `hail-server-ts`, and
the pinned official `did-method-plc` checkout. It cannot monitor the live POC
DIDs via the public PLC registry because those DIDs exist only in its private
directory. The private-directory URL may be used only in isolated tests.

## Implemented Boundary

The monitor retains its PostgreSQL export-sequence cursor across restarts and
rejects a sequence gap rather than silently skipping events. For enrolled
DIDs, it validates the complete PLC operation log, resulting state, current
CID and non-nullified audit entry. Every unexpected operation creates a
durable alert without silently changing the user's expected state. A poll
after more than 24 hours without coverage records a separate lost-coverage
alert. Alerts are queued before a DNS-pinned, certificate-validating HTTPS
webhook attempt, and retry durably until a `2xx` response. The webhook
receives a domain-separated Ed25519 signature and the monitor public DID key.
No token is sent in a URL or ordinary log.

On a **user-run host**, the user reviews a complete PLC document-data JSON
snapshot and explicitly approves an observed new CID via the local
`monitor:approve` command. After the unexpected-operation alert has reached
the user's webhook and no coverage-gap alert exists, `monitor:attest` can sign
the current operation and coverage period. The signed CBOR payload verifies
with the provider-side `verifyMonitorAttestation` implementation, but the
provider never receives the monitor private key. A provider-operated bootstrap
instance does **not** satisfy independent-monitor requirements because its
operator can suppress coverage or alerts.

## Local Commands

Build the pinned sibling library and codec, then install dependencies:

```bash
bun run --cwd ../hailproto/packages/hail-codec-ts build
pnpm --dir ../did-method-plc build
bun install
```

Create a private monitor Ed25519 key file outside this repository. The
command creates a new mode-`0600` PKCS8 file without printing the private
bytes; record its printed public `did:key` for the provider's user-controlled
monitor evidence:

```bash
bun run monitor:keygen -- /secure/user-controlled/monitor-ed25519.pkcs8
```

Set `DATABASE_URL`, `PLC_DIRECTORY_URL`, `MONITOR_PRIVATE_KEY_FILE`, and
`MONITOR_ORIGIN` on the independent host. Never commit populated environment
files. Use a durable PostgreSQL database, not one of the provider databases.
After independently verifying a DID's current full state and expected CID:

```bash
bun run monitor:migrate
bun run monitor:enroll -- "$did" "$current_operation_cid" "$user_https_webhook"
bun run monitor:run
```

The process polls the official sequenced PLC export every minute and attempts
one due webhook notification every five seconds. For an isolated attempt use
`monitor:poll` or `monitor:notify`. For a user-reviewed update, supply the
*complete* reviewed PLC document-data JSON and the exact observed CID:

```bash
bun run monitor:approve -- "$did" "$new_operation_cid" reviewed-plc-data.json
bun run monitor:attest -- "$did" "$transfer_id" "$new_operation_cid"
```

The monitor refuses an attestation if notification has not completed, the
operation is not current/approved, the last healthy poll is stale, or it has
detected a coverage or export gap. It prints only the signed attestation and
the public monitor key, never provider or user identity private keys.

## Production Work Still Required

`/export?after=<seq>` is a global PLC sequence. This prototype starts at
sequence zero and requires contiguous results. A large public directory
requires a **verified bootstrap checkpoint** or complete backfill before it
can assert coverage; an arbitrary late cursor is not proof of monitoring.
The POC has not selected independently operated PLC mirrors, deployed this
project on a separate user-owned host, or proven webhook delivery outside its
test fixtures. Review and operation approval are local commands rather than a
cross-device user interface. A service hosted by the Hail provider may help
users bootstrap but cannot satisfy the portable-custody rule that the monitor
be outside the provider's administrative control.

The remaining portable migration prerequisites are recorded in
`../hailproto/docs/production-portable-custody.md`. Test the monitor against a
fresh disposable PostgreSQL 14.4 database with:

```bash
DATABASE_URL=postgresql://monitor:password@127.0.0.1:5432/hail_monitor_test \
  bun --bun vitest run test/monitor.integration.test.ts
```
