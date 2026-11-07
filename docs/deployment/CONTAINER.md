# Container deployment baseline

The Docker Compose topology uses a separate PostgreSQL 17 service with a
persistent volume, a private database network, and no published database port.
The API image runs as UID 10001, exposes its HTTP port only on loopback, and
uses Compose secrets for its database password and optional GitHub key. The
optional Caddy overlay provides automatic HTTPS for the API and dashboard on a
Docker host. This is a deployment baseline, not production certification;
encrypted off-host backups, alerting, host hardening, and live acceptance remain
required before shared production use.

## Docker Compose on a VM

1. Install Docker Engine and the Compose plugin. Copy `.env.example` to `.env`.
2. Generate local secrets without adding them to Git:

   ```bash
   umask 077
   python -c 'import secrets; print(secrets.token_urlsafe(48))' > secrets/postgres-password.txt
   python -c 'import secrets; print(secrets.token_urlsafe(48))' > secrets/jwt-secret.txt
   ```

   Set `TALARIA_JWT_SECRET_FILE` and `TALARIA_POSTGRES_PASSWORD_FILE` in
   `.env` to the secret file paths. Keep the bootstrap token file empty to
   disable the HTTP bootstrap route. Secret files read by the API must be owned
   by its container UID 10001 with mode `0400`. Treat them as credentials.
   Apply the same UID and restrictive mode to the GitHub private key and LLM
   API key and webhook signing secret files when those integrations are enabled.

3. Select the host directory TALARIA may scan with
   `TALARIA_HOST_REPOSITORY_ROOT`. It is mounted read-only.
   Create the backup directory and grant the API container UID 10001 access:

   ```bash
   mkdir -p backups
   sudo chown 10001:10001 backups
   chmod 0700 backups
   ```

   Set `TALARIA_BACKUP_DIR` if you use another host path. Backup archives are
   created with mode `0600` inside this directory.
4. Start the stack with `docker compose up --build -d`. The container validates
   runtime configuration before running `talaria upgrade-db` and starting the
   API, so invalid security or integration settings fail before schema changes.
   On an empty PostgreSQL database, this creates the checksummed PostgreSQL v11
   baseline and applies v12 through v16. An existing older PostgreSQL schema
   requires a verified backup before migration. With the API container stopped,
   run
   `docker compose run --rm talaria-api talaria upgrade-db --backup-output /backups/pre-upgrade.dump`,
   then restart the stack. The backup directory is mounted at `/backups` from
   `TALARIA_BACKUP_DIR` (default `./backups`). TALARIA refuses to adopt a
   non-empty unmanaged schema or silently change a mismatched schema.
5. Create the initial administrator once:

   ```bash
   docker compose exec talaria-api talaria bootstrap-admin \
     --email admin@example.com --organization "Example"
   ```

6. For local-only access, keep the default loopback bindings. For remote access,
   configure a DNS name whose A/AAAA records point to this host, allow inbound
   TCP ports 80 and 443 (and UDP 443 for HTTP/3), and check that the configured
   Docker edge subnet does not overlap a host or existing Docker network. Set
   `TALARIA_DOMAIN`, `TALARIA_EDGE_SUBNET`, and `TALARIA_CADDY_IP` in `.env` so
   the subnet and proxy address agree, then start the TLS overlay:

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.tls.yml up --build -d
   ```

   Caddy obtains and renews the public certificate and persists its certificate
   state in the `caddy-data` volume. It routes application API and webhook paths
   to FastAPI and other paths to Streamlit. The API trusts forwarded client
   addresses only from the configured Caddy address; keep that address reserved
   for Caddy on the edge network. The API and dashboard remain loopback-bound on
   the host. Do not place another proxy in front unless its trusted-proxy chain
   is separately configured and reviewed.

The Streamlit dashboard is published on `127.0.0.1:8501` for local access. The
dashboard container sends requests to the API over the private edge network and
has no database or provider secrets.

PostgreSQL is not published to the host. The API reaches it through a private
Compose network. The API also joins a separate network for outbound GitHub or
AI provider calls. No provider access occurs unless its feature and credentials
are configured.

## Moving recovered SQLite data

The schema-v0 source database remains untouched. The supplied recovered SQLite
copy is schema v12; make a verified backup and upgrade that copy to the current
schema before import. Set `TALARIA_DATABASE` to the copy's path when running
`talaria upgrade-db`. Import accepts only a ready schema-v16 SQLite copy and an
empty initialized PostgreSQL database. Mount the upgraded file read-only for a
one-off container and run:

```bash
docker compose run --rm \
  -v "$PWD/.talaria/talaria-recovered-v10.db:/import/recovered.db:ro" \
  talaria-api talaria import-sqlite-db --source /import/recovered.db
```

The command verifies SQLite readiness, refuses a non-empty PostgreSQL target,
copies rows in foreign-key order in one transaction, verifies row counts,
updates identity sequences, and records an audit event. It never writes to the
SQLite source. Take and verify a separate backup before making the imported
database the active service database.

## PostgreSQL backup and restore

The API image includes PostgreSQL 17 client utilities (`pg_dump` and
`pg_restore`) for the Compose PostgreSQL 17 server. Create and verify a
custom-format backup from the API container:

```bash
docker compose exec talaria-api talaria backup-db \
  --output /backups/talaria-$(date -u +%Y%m%dT%H%M%SZ).dump
docker compose exec talaria-api pg_restore --list /backups/talaria-<timestamp>.dump
```

The CLI also verifies the archive, writes with owner-only permissions, and
refuses to overwrite a destination. Encrypt the archive before off-host
storage; the dump contains sensitive finding and account data.

For restore, create a separate empty PostgreSQL database first. Run the restore
from the API image, whose PostgreSQL client tools and active-database safety
check are already configured:

```bash
docker compose run --rm talaria-api talaria restore-db \
  --source /backups/talaria-<timestamp>.dump \
  --target-url 'postgresql://talaria@restore-host:5432/talaria_restore?sslmode=require'
```

The target URL omits its password. The command reads the password from the
configured secret file. If the restore target uses a different password, mount
that password file into the one-off container and set
`TALARIA_POSTGRES_PASSWORD_FILE` to its in-container path.

The restore path refuses the active database and any target with tables, uses
`pg_restore --single-transaction --exit-on-error`, then checks TALARIA schema
readiness. It never uses `--clean` or overwrites existing objects. Keep an
encrypted pre-upgrade dump and a rollback plan for every PostgreSQL schema
migration. TALARIA applies checksummed PostgreSQL migrations in version order
and requires a verified pre-upgrade dump for an existing database. A live
restore drill remains required before routine production upgrades.

## Kubernetes example

The Kubernetes manifests remain an SQLite-oriented example with one replica and
one persistent volume. They are not the selected PostgreSQL deployment and
have not been applied to a live cluster. Do not use them for the selected
shared production topology without adding a PostgreSQL service or managed
database, encrypted backups, TLS ingress, network policies, and a restore plan.

## Operational limits

- The container image and Compose stack have not been started in this
  environment because Docker is unavailable.
- The database password and GitHub App secret are not configured in this
  environment, so provider acceptance has not run.
- The API has no TLS listener; the optional Caddy overlay terminates TLS.
- Rate limits use the forwarded client address only when the request comes
  from the configured trusted proxy; multi-worker rate limits still require
  shared PostgreSQL acceptance.
- GitHub webhooks persist sanitized delivery metadata but do not yet trigger a
  complete scan-to-approved-PR workflow.
- PostgreSQL backup/restore commands and a checksummed incremental migration
  exist, but live PostgreSQL/Docker acceptance and a restore drill remain.
