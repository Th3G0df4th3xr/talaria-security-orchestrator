# TALARIA operations runbook

This runbook documents the current single-VM Compose baseline. It is not a
substitute for a tested deployment, on-call monitoring, or an incident response
plan approved for a specific organization. Keep the API and dashboard behind a
trusted TLS boundary. The default Compose stack is loopback-only; use the
optional Caddy overlay from [CONTAINER.md](CONTAINER.md) for the VM TLS
topology, and verify DNS, firewall, certificate, and proxy trust on the host.

## Start, inspect, and stop

Before first start, follow [CONTAINER.md](CONTAINER.md) to create owner-only
secret files, set the host repository and backup paths, and review `.env`.
Then use:

```bash
docker compose config
docker compose up --build -d
docker compose ps
docker compose logs --tail=100 talaria-api talaria-dashboard postgres
```

For the VM TLS topology, use the overlay command in `CONTAINER.md`, then
include `caddy` when inspecting status and logs.

The API container validates its runtime configuration before running
`talaria upgrade-db`, then starts Uvicorn. Invalid security or integration
settings therefore stop startup before the container changes the database.
Migration initializes an empty PostgreSQL schema or applies available
migrations; an existing PostgreSQL upgrade requires a pre-upgrade dump path.
Confirm both API and dashboard health checks before allowing users to connect.
Stop with `docker compose down`; do not add `--volumes` during routine
maintenance.

## PostgreSQL transport

PostgreSQL connections must use `sslmode=require`, `verify-ca`, or
`verify-full`. Prefer `verify-full` with the database provider's CA certificate
mounted into the API and backup environment; `require` encrypts traffic but does
not authenticate the server certificate. Plaintext `sslmode=disable` is
rejected unless the exact hostname is listed in
`TALARIA_DATABASE_TRUSTED_HOSTS`. The Compose file lists only its `postgres`
service hostname, which is reachable over the internal-only database network
and is not published on a host port. The exception requires explicit host
settings and rejects hostaddr, service-file, and PGHOST routing overrides. Do
not add a remote database hostname to that exception; use TLS instead.

## Upgrade procedure

1. Review the release notes and migration source; test the same migration on a
   disposable database first.
2. Stop API and dashboard writers: `docker compose stop talaria-api
   talaria-dashboard`.
3. Build the reviewed application image with `docker compose build talaria-api`.
4. For an existing PostgreSQL schema, run the one-off migration command. It
   creates and verifies the required custom-format backup before applying
   migrations; choose a new, unused output path:

   ```bash
   docker compose run --rm talaria-api talaria upgrade-db \
     --backup-output /backups/pre-upgrade-$(date -u +%Y%m%dT%H%M%SZ).dump
   ```

   The command may be omitted for a fresh empty database, whose schema is
   initialized on API startup. Do not run multiple migration processes at once.
5. Start services with `docker compose up -d`.
6. Check `docker compose ps`, API readiness, logs, and a representative
   authenticated read. Do not manually edit migration records or checksums.

Rollback means restoring the pre-upgrade backup to a separate empty database
and switching the deployment configuration after validation. There is no
automatic reverse migration. Preserve the failed database for investigation;
never restore over the only copy.

## Backups and restore

The PostgreSQL backup command is documented in
[CONTAINER.md](CONTAINER.md). Archives contain account and security finding
data. Restrict filesystem access, encrypt before off-host transfer, set a
retention policy, and keep encryption keys separately. No automated encryption,
off-site transfer, retention cleanup, or restore drill is implemented here.

Restore only to a new, empty target. The CLI checks that a PostgreSQL target is
not the active database and contains no tables. After restore, verify schema
readiness, row counts relevant to your service, and application behavior before
switching traffic. Record the restore time and source archive in your own
change/audit process.

## Secret rotation

1. Prepare replacement secret files outside the repository with owner-only
   permissions and the required container ownership.
2. For JWT signing-key rotation, expect existing access tokens to become
   invalid. Restart the API after replacing the mounted file and require users
   to authenticate again if their refresh flow cannot proceed.
3. For database credentials, coordinate the PostgreSQL role password and
   mounted secret update before restarting TALARIA.
4. Rotate GitHub App credentials and webhook secrets in the provider and local
   secret store together. Verify signed webhook delivery after rotation.
5. Rotate the AI provider key at the provider, update the file, and keep AI
   disabled until a local configuration check succeeds.
6. Remove superseded credentials from the secret store and review access logs.

TALARIA has no automated secret-rotation controller. Do not put secret values
in shell history, tickets, logs, or Git.

## Incident response and recovery

If credentials or repository data may have been exposed:

1. Restrict access at the TLS proxy or host firewall and stop affected services
   if continued operation could worsen the incident.
2. Preserve logs, database files, backups, and container metadata for review;
   do not delete or overwrite evidence.
3. Revoke affected user sessions and provider credentials using the relevant
   identity/provider controls. Rotate the TALARIA JWT key if token signing
   material may be exposed.
4. Restore service only from a verified clean backup after the cause and
   affected time window are understood.
5. Record actions, data exposure, and follow-up controls in the operator's
   incident system. TALARIA does not currently provide a complete incident
   case-management or alerting workflow.

For suspected database corruption, stop writers and make a filesystem-level
copy before recovery. Use `talaria backup-db`, `talaria restore-db`, or
`talaria recover-legacy-db` only with a separate output path; these tools are
designed not to overwrite the source. Validate the result before changing the
active database configuration.

## Current operational gaps

- TLS configuration is included as an optional Caddy overlay, but domain/DNS,
  firewall rules, certificate issuance/renewal, and forwarded-header trust
  still require live operator validation.
- The protected `/metrics` endpoint reports bounded process-local request and
  scan metrics. Alert definitions and centralized log shipping are not
  included; shared database-backed rate limiting still needs live PostgreSQL
  concurrency acceptance.
- Docker and Kubernetes deployment acceptance, PostgreSQL restore drills,
  capacity testing, and independent security review remain required.
- GitHub and AI external acceptance were not run; this workspace is limited to
  local and mocked checks.
