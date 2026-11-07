# Engineering decisions

These decisions preserve the existing modular-monolith architecture. The
existing architecture decision record remains in
[decisions/001-modular-monolith.md](decisions/001-modular-monolith.md).

## Database migration baseline

- The existing workspace database is a pre-versioned schema-v0 SQLite file.
  Compatible v1 legacy fixtures are also accepted by the first migration.
- SQLite migrations are registered once in `talaria.migrations.SQLITE_MIGRATIONS`
  and apply sequentially from v2 through v16. There is no historical v1
  migration function; adding one retroactively would alter the established
  checksum/version contract.
- PostgreSQL uses a frozen v11 schema baseline and incremental v12–v16 migrations.
  Changes to that baseline require an additive checksummed migration.
- The supplied recovered database contains a historical v2 checksum that
  differs from the current v2 source digest. One exact existing v2 digest is
  accepted to preserve readiness for those copies; new databases record the
  current digest, and all other drift remains rejected.
- Database startup rejects a SQLite schema version newer than the running code.
  It also rejects a partial unmanaged SQLite schema rather than filling missing
  legacy tables before a migration. Administrative schema changes remain
  explicit through `talaria upgrade-db`.
- SQLite DDL migrations use one transaction per version. PostgreSQL baseline
  creation and pending migrations execute inside the advisory-lock transaction.
  Recovery from a failed prior version uses a verified backup; there is no
  promise of reverse migrations.

## Shared request throttling

Sensitive and resource-intensive routes use an atomic database-backed GCRA
limiter. Request-scope keys are hashed before persistence, stale buckets are
pruned periodically, and limited routes fail closed when the store is
unavailable. SQLite multiple-handle behavior is tested; PostgreSQL concurrency
still requires the disposable integration service.

## Legacy orphan findings

The original database has two findings whose historical `scan_id` is 0 although
no scan 0 exists. Their true scan provenance cannot be inferred from existing
records, so the migration must not assign either finding to scan 1, 2, or 3.
The existing recovery path produces a separate database and records recovery
uncertainty. The source stays unchanged. The recovered copy passes current
SQLite integrity and foreign-key checks, but historical provenance remains
uncertain and must not be represented as reconstructed fact.

## Verification and external boundaries

External providers and destructive deployment acceptance stay disabled unless
explicitly authorized. Mocked tests prove adapter behavior only. PostgreSQL,
Docker, Kubernetes, TLS, and live provider checks are separate acceptance gates
and are not inferred from SQLite or YAML tests.
