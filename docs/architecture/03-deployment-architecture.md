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

This is a development/MVP topology, not a production deployment architecture.

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

The API has no authentication/RBAC in the current MVP. It must bind to loopback. A firewall is not a substitute for application authorization. Do not deploy this build to a public cloud, shared host, or team network.

## 5. Future single-host deployment

A hardened single-host deployment would require:
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

- [ ] Confirm API binds to loopback.
- [ ] Confirm no secrets are present in source, logs, or artifacts.
- [ ] Confirm database backup and restore.
- [ ] Run unit, integration, and security tests.
- [ ] Run dependency and secret scans.
- [ ] Verify filesystem access is restricted to approved repositories.
- [ ] Verify scan limits and failure handling.
- [ ] Verify audit records for registration and scan lifecycle.
- [ ] Document rollback and recovery.
