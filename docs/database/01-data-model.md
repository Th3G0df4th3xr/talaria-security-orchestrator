# Data model

TALARIA schema v17 is available in SQLite for local development and as a
checksummed PostgreSQL v11 baseline plus incremental v12 through v17 migrations for the
Docker Compose deployment. Both databases upgrade sequentially and validate
stored checksums. PostgreSQL rejects unmanaged schemas and checksum drift.
The supported legacy SQLite inputs are a pre-versioned v0 schema and compatible
v1 baseline; numbered SQLite migration functions v2 through v17 are held in one
ordered registry. Initialization rejects future schema versions before
preparing legacy tables. A local static test confirms matching v17 table and
column names; it does not validate PostgreSQL runtime types, indexes,
constraints, or transaction behavior. Live PostgreSQL parity and upgrade
acceptance still require a disposable server.

## Core records

| Table | Purpose |
|---|---|
| `organizations` | Tenant identity and active state |
| `users` | Normalized login identity, password hash, and platform-admin status |
| `organization_memberships` | Tenant membership and role |
| `repositories` | Local repository path and tenant owner |
| `scans` | Run status, timestamps, repository revision, and error summary |
| `findings` | Stable fingerprint, JSON payload, lifecycle status, and first/last seen timestamps |
| `finding_occurrences` | Finding observation in an individual scan |
| `refresh_sessions` | Hashed refresh-token sessions, rotation family, expiry, and revocation state |
| `approval_records` | Tenant-scoped second-person approvals bound to an exact action/resource and consumption time |
| `webhook_deliveries` | Deduplication key and hash of a verified delivery |
| `github_repositories` | Provider repository ID bound to one TALARIA tenant and local repository |
| `github_check_runs` | Bounded latest synchronization snapshot for each provider check run and commit |
| `github_events` | Sanitized, allowlisted event fields, tenant, and provider repository ID linked to a delivery |
| `request_rate_limits` | Hashed request scopes and shared GCRA quota state |
| `investigations` | Tenant-scoped AI run state, provider/model, evidence references, result, and failure type |
| `audit_events` | Structured event name, canonical JSON details, creation timestamp, and chained SHA-256 hashes |
| `schema_migrations` | Applied SQLite migration checksums or PostgreSQL v11 baseline and v12–v17 migration checksums |

Finding payloads are JSON text. Refresh bearer tokens are never stored; only
their hashes are persisted. Webhook request bodies are discarded after
signature verification and allowlisted metadata extraction. Audit details must
not include credentials, full source files, or unnecessary proprietary data.

## Integrity and operations

- SQLite enables foreign keys on every connection and checks database integrity
  and foreign-key consistency during readiness.
- PostgreSQL uses primary keys, foreign keys, uniqueness and check constraints;
  readiness validates the v11 baseline, v12–v17 migration checksums, and required tables.
- Schema v14 backfills and verifies an ID-ordered audit hash chain. SQLite
  blocks ordinary row updates/deletes and inserts without hashes; PostgreSQL
  appends are serialized and readiness verifies the chain. The chain has no
  independent immutable checkpoint, so a database owner who can rewrite the
  entire history can recompute it. External immutable anchoring remains a
  production requirement.
- Schema v15 records AI investigations as running, completed, or failed. Its
  composite foreign keys bind the finding and repository to the same tenant;
  the authenticated API applies role checks and scopes history to the selected
  organization.
- Schema v16 stores GitHub repository onboarding only after a platform
  administrator verifies provider identity and selects the TALARIA tenant and
  local repository. New webhook summaries are bound to the registered provider
  repository and installation IDs; historical summaries remain unassigned.
- Schema v17 persists tenant-bound GitHub check-run state for an onboarded
  repository and commit. The synchronization endpoint fetches at most 100 runs,
  validates the complete returned count, and replaces the commit snapshot in a
  transaction. Pagination and event-driven refresh are pending.
- API throttling uses an atomic database-backed GCRA bucket so worker processes
  share the same quota. The request-scope key is hashed before storage; stale
  buckets are pruned periodically. A database failure rejects throttled
  requests with 503. PostgreSQL concurrency still needs live acceptance.
- Scan persistence, session rotation, approval consumption, and migrations use
  transactions. PostgreSQL bootstrap and refresh rotation use advisory/row
  locks to serialize critical transitions.
- The SQLite-to-PostgreSQL import accepts only a ready schema-v17 SQLite source
  and an empty initialized PostgreSQL target. It reads the source read-only,
  copies all persistent tables in foreign-key order, including GitHub tenant
  mappings, check runs, scoped events, and AI investigation history, verifies
  counts, resets identity sequences, and records the import in the target audit
  log. Ephemeral rate-limit buckets and migration metadata are
  intentionally not copied.
- Repository paths, finding evidence, and backups are sensitive security data.
  Restrict access, define retention, encrypt backups before off-host storage,
  and test restore into an isolated destination.
