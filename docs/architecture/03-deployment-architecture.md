# Deployment Architecture

## 1. Current deployment model

TALARIA is currently a local-first Python application. The operator runs the CLI or starts the FastAPI process on the same workstation that can access the authorized Git repository. SQLite stores application state locally.

```text
Operator workstation
  ├── CLI
  ├── FastAPI (loopback only)
  ├── TALARIA service packages
  ├── Local authorized Git repositories (read-only scan intent)
  └── .talaria/talaria.db (local SQLite)
```

The default local Compose topology uses PostgreSQL and keeps the API and
dashboard bound to host loopback. An optional Compose overlay adds Caddy for a
single-VM HTTPS topology. Neither topology has been accepted on a live host.

## 2. Runtime prerequisites

- Python 3.11 or newer.
- Project dependencies installed from `pyproject.toml`.
- Access to the local repositories explicitly approved for scanning.
- Write access to the TALARIA state directory and SQLite database.
- A supported operating system and filesystem.

Use a virtual environment. Keep `.venv`, `.talaria`, generated reports, caches, and secrets out of version control.

## 3. Configuration and state

Configuration is currently provided through application defaults and environment-aware helper functions. `.env.example` documents expected local settings; it is not a secrets store. Do not put real tokens or passwords in committed files.

The SQLite database is mutable state. Back it up before schema migrations or manual repair. Use a copy of the database for experiments. Database integrity checks and migration tests are required before release.

## 4. Network exposure

The API has JWT authentication, organization memberships, role checks, and
tenant scoping for core routes. The base Compose listeners remain on loopback.
For a VM deployment, the optional TLS overlay publishes Caddy on ports 80 and
443, routes API and webhook paths to FastAPI and other paths to Streamlit, and
configures Uvicorn to trust forwarded client addresses only from Caddy's
reserved edge-network address. DNS, firewall, certificate issuance/renewal,
and proxy behavior still require live acceptance. The Kubernetes manifest has
no ingress or TLS configuration. A firewall is not a substitute for
application authorization; no deployment topology is certified for public use.

## 5. Single-host deployment boundary

A hardened single-host deployment still requires:
- A dedicated service account with least-privilege filesystem access.
- Explicit repository allowlists and read-only mounts where practical.
- A managed secret store or OS credential facility.
- Authenticated API access and role-based authorization.
- Structured logs with sensitive-data redaction.
- Database backup, migration, restore, and integrity procedures.
- Process supervision, health checks, resource limits, and patch management.

## 6. Future distributed deployment

If scanning becomes asynchronous or multi-user, separate the API/control plane from bounded scan workers. Use a durable job queue, explicit job state transitions, tenant-aware authorization, encrypted storage, and isolated worker execution. Workers should receive only the repository snapshot and permissions required for a single job.

Do not introduce distributed infrastructure until measured workload or availability requirements justify it.

## 7. Deployment verification checklist

- [ ] Keep API/dashboard host ports loopback-bound and verify Caddy is the only
      public listener.
- [ ] Verify DNS, firewall, TLS certificate issuance/renewal, and trusted
      forwarded client addresses on the deployed VM.
- [ ] Confirm no secrets are present in source, logs, or artifacts.
- [ ] Confirm database backup and restore.
- [ ] Run unit, integration, and security tests.
- [ ] Run dependency and secret scans.
- [ ] Verify filesystem access is restricted to approved repositories.
- [ ] Verify scan limits and failure handling.
- [ ] Verify audit records for registration and scan lifecycle.
- [ ] Document rollback and recovery.

The repository's current container baseline and limitations are documented in
[Container deployment](../deployment/CONTAINER.md). The Compose and Kubernetes
files have syntax tests; neither has been deployed to a live host or cluster.
