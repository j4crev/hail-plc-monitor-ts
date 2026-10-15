# Independent Hail PLC Monitor

Prototype of a user-run monitor for the Hail portable-custody profile. The
monitor validates DID operation logs, durably tracks the PLC export sequence,
records unexpected operations and lost coverage, and signs bounded coverage
attestations for a provider migration. Migration 3 adds reviewed bootstrap
checkpoint retention and durable backfill readiness; see the candidate
[PLC read-evidence policy](https://github.com/j4crev/hailproto/blob/main/spec/plc-read-evidence.md).
Hosting it on infrastructure controlled
by a Hail provider is a **bootstrap convenience**, not independent coverage
under `../hailproto/spec/account-onboarding.md`.

The prepared same-host public bootstrap profile is documented in
[`deploy/public`](deploy/public/README.md). It is intentionally not started while
the PLC replica is consuming the VPS for its initial backfill.

This project is intentionally a sibling of `hailproto`, `hail-server-ts`, and
the pinned official `did-method-plc` checkout. It cannot monitor the live POC
DIDs via the public PLC registry because those DIDs exist only in its private
directory. The private-directory URL is used in isolated tests and the
explicitly non-independent [same-VPS POC deployment](deploy/poc/README.md).

## Implemented Boundary

The monitor retains its PostgreSQL export-sequence cursor across restarts and
rejects a sequence gap rather than silently skipping events. For enrolled
DIDs, it validates the complete PLC operation log, resulting state, current
CID and non-nullified audit entry. Every unexpected operation creates a
durable alert without silently changing the user's expected state. A poll
after more than 24 hours without coverage records a separate lost-coverage
alert, including enrollment that never completed its first healthy backfill.
A full export page reports `backfilling`, not healthy coverage; failed/gapped
polls clear readiness. Only a short/empty contiguous page establishes catch-up.
Alerts are queued before a DNS-pinned, certificate-validating HTTPS
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
bun run monitor:enroll -- "$did" "$current_operation_cid" "$user_https_webhook" reviewed-plc-data.json
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

For a newly registered DID whose reviewed bootstrap is still the current genesis,
complete contiguous backfill, deliver the enrollment notification and complete a
fresh healthy poll, then produce the separate onboarding artifact:

```bash
umask 077
bun run monitor:attest-onboarding -- "$did" "$genesis_cid" > onboarding-attestation.json
```

This attestation has no transfer ID or prior checkpoint. It binds the reviewed
genesis state digest and export sequence under
`hail.independent-plc-onboarding-monitor.v1\0`. It refuses stale health, incomplete
backfill, changed state or any recorded coverage/export/invalid-log gap.

The monitor refuses an attestation if notification has not completed, the
operation is not current/approved, the last healthy poll is stale, or it has
detected a coverage or export gap. It prints only the signed attestation and
the public monitor key, never provider or user identity private keys.

HTTPS-directory enrollment requires the reviewed state file before key/database/
network access. It is bounded at 1 MiB, uses strict JSON/PLC state validation and
must match the exact CID and complete validated state. The original bootstrap
CID/state/time is retained separately; later approval does not overwrite it.
The three-argument form remains private-HTTP-POC convenience, not reviewed public
bootstrap evidence. Existing enrollments are not retroactively relabeled.

Reviewed enrollment plus completed contiguous backfill produces **v2** coverage,
using `hail.independent-plc-monitor.v2\0`: the existing fields plus original
bootstrap CID, SHA-256/deterministic-CBOR full-state digest and processed export
sequence. Public cutover requires v2, a canonical pre-cutover checkpoint matching
both readers, and observation within five minutes. Legacy enrollments produce
the original v1 payload/context, which remains verifiable but is rejected by the
public gate. The export sequence is a monitor assertion, not a cryptographic
directory checkpoint. There is no command to skip to an arbitrary late cursor.

### Migrations 3-4 and rollback

Stop the old monitor/attestation processes before upgrading; deploy one consistent
runtime before using v2 evidence. Mixed-version production attestation is not a
supported rollout. `monitor:migrate` preserves all existing cursors, enrollment,
observation, alert and approval rows and starts `caught_up=false`. It creates no
reviewed bootstrap records for old enrollments. Repeated migration is checksum
checked and does not reset a later successful catch-up.

With all processes stopped, `migrations/rollback/0003_backfill_readiness.sql`
permits a legacy rollback only when enrolled monitors are caught up, no later
migration exists and no reviewed checkpoint would be lost. It refuses incomplete
backfill and any sole reviewed-bootstrap record. Re-upgrade preserves legacy
rows but requires new catch-up; rollback is not production-readiness proof.
Preserve old enrollment history when planning any new reviewed ceremony rather
than deleting it to manufacture a v2 label.

Migration 4 expands the closed alert category set for the delivered onboarding
enrollment notification. Its guarded rollback refuses while any such notification
evidence exists or a later monitor migration is installed.

## Production Work Still Required

`/export?after=<seq>` is a global PLC sequence. This prototype starts at
sequence zero and requires contiguous results. A large public directory
requires a **verified bootstrap checkpoint** or complete backfill before it
can assert coverage; an arbitrary late cursor is not proof of monitoring.
The reference now implements reviewed per-DID checkpoints plus complete-backfill
readiness. Fast bootstrap from an independently verified late global checkpoint
remains unimplemented. External health supervision is also needed to alert while
the monitor process itself is offline. The POC has not selected independently
operated PLC mirrors or deployed this
project on a separate user-owned host. The same-VPS private-directory
deployment has proven signed HTTPS webhook delivery and durable restart
behavior with a disposable DID; it does not prove host independence.
Review and operation approval are local commands rather than a
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
