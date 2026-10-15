# Provider-bootstrap public monitor

This profile runs the monitor worker and its private PostgreSQL database. It
consumes the canonical `https://plc.directory/export` feed directly; it does not
use the read replica because the official replica has no export endpoint.

Hosting this stack beside a Hail provider or its replica is useful for pre-alpha
testing but is not independent monitoring.

## Prepare, but do not start yet

Keep sibling `hailproto`, `did-method-plc` and `hail-plc-monitor-ts` checkouts in
one workspace because the image build uses pinned local libraries.

```bash
cd hail-plc-monitor-ts/deploy/public
cp .env.example .env
chmod 600 .env
install -d -m 700 secrets
install -d -m 700 reviewed
docker compose --env-file .env build monitor
docker run --rm --network none --user root \
  --mount "type=bind,src=$(pwd)/secrets,dst=/keys" \
  hail-plc-monitor-ts:public bun src/cli/generate-key.ts /keys/monitor.pkcs8
chown -R 1000:1000 secrets
```

Store the printed public `did:key` and an encrypted copy of
`secrets/monitor.pkcs8` away from the VPS. Set `MONITOR_ORIGIN` to the reviewed
HTTPS operator identifier. The worker itself exposes no public port; enrolled
alert destinations are outbound HTTPS webhooks.

## Start and inspect

Start after the PLC replica backfill no longer needs the host's full CPU capacity:

```bash
docker compose --env-file .env up -d --wait
docker compose --env-file .env logs -f monitor
docker compose --env-file .env exec db \
  psql -U monitor -d monitor -c 'SELECT last_seq,caught_up,last_healthy_at FROM monitor_cursor'
```

The monitor starts at sequence zero. A full export page remains `backfilling`;
only a short or empty contiguous page marks it caught up.

## Enroll the canary

After the first `hailp account create` call returns the DID and genesis CID,
derive a public reviewed state file from the private signup state on the user
workstation:

```bash
jq '{did,rotationKeys:.operation.rotationKeys,verificationMethods:.operation.verificationMethods,
  alsoKnownAs:.operation.alsoKnownAs,services:.operation.services}' \
  /secure/hail-canary/signup.json > reviewed-plc-data.json
```

Copy only `reviewed-plc-data.json` to `deploy/public/reviewed/` on the monitor
host, then run:

```bash
docker compose --env-file .env exec monitor bun src/cli/enroll.ts \
  "$DID" "$GENESIS_CID" "$ALERT_WEBHOOK" /reviewed/reviewed-plc-data.json
```

After complete catch-up, healthy polling and delivery of the enrollment alert:

```bash
docker compose --env-file .env exec monitor bun src/cli/attest-onboarding.ts \
  "$DID" "$GENESIS_CID" > onboarding-attestation.json
```

Copy the attestation to the user workstation and resume the exact saved `hailp`
signup command. Do not copy the monitor private key, database password, user vault,
recovery secret or provider credential between trust domains.
