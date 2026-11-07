# Database migrations

TALARIA does not run schema migrations from API request handling. The
administrative CLI owns schema changes. The Docker API container invokes
`talaria upgrade-db` before starting Uvicorn; that command initializes a fresh
PostgreSQL schema and applies registered migrations. For an existing PostgreSQL
schema that needs an upgrade, the command refuses to proceed unless a backup
path is supplied.

## Supported migration histories

### SQLite

The repository's original database is a pre-versioned schema-v0 database. A
compatible v1 legacy baseline is accepted. There is no separate v1 migration
function; numbered migration functions are registered in
`talaria.migrations.SQLITE_MIGRATIONS` from v2 through v17 and invoked in that
order. Fresh database initialization takes a SQLite write lock before deciding
whether to create the baseline, then creates all four legacy tables in one
explicit transaction. This serializes concurrent first starts and rolls back a
partially created baseline. Each numbered migration also takes a write lock,
verifies its expected prior version (except the first baseline upgrade),
commits its own transaction, and records a checksum once the migration-history
table exists.

One exact legacy v2 checksum is accepted because it is already stored in the
supplied v10/v11/v12 workspace database and the current v2 implementation has
changed. New databases store the current v2 checksum. All other migration
checksums remain strict; an unrecognized difference is rejected. This narrow
compatibility exception is covered by a test and must not be expanded without
reviewing migration behavior.

Unknown future versions, versions outside the accepted v0/v1 legacy baseline,
and partial unmanaged schemas fail without applying schema changes. A bad
legacy finding-to-scan reference aborts migration;
use the recovery command on a separate output path if the defect is the known
schema-v0 orphan case. Do not associate orphan findings with an arbitrary old
scan.

### PostgreSQL

PostgreSQL uses a frozen v11 schema baseline and additive, checksummed
migrations starting at v12. Version 13 adds the shared request rate-limit
bucket table used for cross-worker throttling. Initialization is serialized by a PostgreSQL
advisory transaction lock. Existing unmanaged schemas, gaps in applied
versions, and checksum drift are rejected. The available local environment did
not include a PostgreSQL server, so the PostgreSQL history still requires the
disposable integration run described in
[EXTERNAL_ACCEPTANCE_CHECKLIST.md](../EXTERNAL_ACCEPTANCE_CHECKLIST.md).

Schema v14 adds `previous_hash` and `entry_hash` to audit events and backfills
the chain in ID order. SQLite triggers reject unhashed inserts and ordinary
updates/deletes; PostgreSQL appends use a transaction advisory lock, and
readiness recomputes the chain. This detects row-level tampering while the
chain remains intact, but does not detect a database owner rewriting the full
chain. Store signed checkpoints in an independently controlled immutable
system before relying on it as a production audit guarantee.

Schema v15 adds tenant-scoped AI investigation history with constrained
`running`, `completed`, and `failed` states. Composite foreign keys require
the finding and repository to share a tenant. The authenticated API records
the initiating user after server-side tenant and role authorization. The API persists provider/model metadata, bounded
evidence references, validated result JSON, and a failure type without storing
prompts or provider error text.

Schema v16 adds GitHub repository mappings that bind a stable provider ID and
installation ID to a TALARIA organization and local repository. Onboarding
requires a platform administrator to select the tenant and verifies the remote
repository through the configured GitHub App installation. Verified webhook
events for enabled mappings are persisted with tenant ownership; older unscoped
event summaries remain unassigned. SQLite-to-PostgreSQL transfer copies the
new mappings and scoped events in foreign-key order.

Schema v17 stores validated GitHub check-run snapshots by onboarded repository
and commit. The authenticated synchronization endpoint is tenant-scoped, checks
the configured installation against the repository binding, caps a fetch at
100 runs, replaces the commit snapshot transactionally, and audits the count.
SQLite-to-PostgreSQL transfer copies the check runs after their repository
mapping. Pagination, webhook-driven refresh, and live provider acceptance are
not implemented yet.

Before importing, TALARIA creates a verified, owner-only temporary SQLite
snapshot and validates the schema, integrity, and audit chain on that snapshot.
The import reads only that snapshot, so changes made to the live SQLite source
after snapshot creation cannot make the transferred rows differ from the
validated state. Ensure the host has temporary free space at least as large as
the SQLite database; PostgreSQL transfer time does not hold a read transaction
against the live SQLite source.

## Operator commands

Check available options with `talaria --help` and `talaria upgrade-db --help`.
For the configured SQLite database, `talaria upgrade-db` makes a verified
timestamped backup before applying the chain. For an existing PostgreSQL
database, provide a new archive path:

```bash
talaria upgrade-db --backup-output /backups/pre-upgrade.dump
```

To migrate a SQLite database while preserving its source file, configure that
file as the input and use `--copy-to`. TALARIA builds the copy in a temporary
file, applies migrations, verifies current readiness, then publishes the new
path atomically without overwriting an existing destination:

```bash
TALARIA_DATABASE=.talaria/talaria-recovered-v10.db \
  talaria upgrade-db --copy-to .talaria/talaria-recovered-v16.db
```

This is the recommended path for the supplied recovered v12 database. Keep the
source and its separate verified backup until the upgraded copy is accepted.
If a schema-v0 source has orphaned findings, first use
`talaria recover-legacy-db` to repair a separate copy, then use `--copy-to` on
that recovered output. Failed copy upgrades do not publish a destination or
change the source.

For Compose, stop API/dashboard writers and use the mounted backup directory:

```bash
docker compose stop talaria-api talaria-dashboard
docker compose run --rm talaria-api talaria upgrade-db \
  --backup-output /backups/pre-upgrade.dump
docker compose up -d talaria-api talaria-dashboard
```

For a SQLite schema-v0 database with orphaned findings, recover to a new path;
the source must remain unchanged:

```bash
talaria recover-legacy-db \
  --source .talaria/talaria.db \
  --output .talaria/talaria-recovered.db
```

To inspect a database without upgrading it, use the application's read-only
`/health/ready` endpoint or the Python API `Database.readiness(path)`. That
check requires current schema version, recognized migration checksums (with
the one documented historical v2 exception), SQLite integrity, and no
foreign-key violations. It does not repair data.

## Failure and rollback

Each SQLite migration is transactional, so a failed migration leaves that
migration's prior schema/version intact. A chain may have earlier versions
committed if a later version fails; recover by restoring the verified
pre-upgrade backup to a new database and validating it before switching
configuration. PostgreSQL baseline creation and pending migrations run within
the initialization transaction; live failure behavior must still be tested
against the supported server.

TALARIA has no reverse migration implementation. Do not manually lower
`user_version`, remove `schema_migrations` rows, or edit checksums. Preserve the
failed database for diagnosis and use a separate restore target. Keep external
encrypted backups and a tested rollback procedure for production operations.

## Verification

The local migration tests cover every SQLite starting version v0 through v17,
repeated initialization, preserved finding/audit data, checksums, foreign-key
integrity, concurrent fresh initialization, baseline bootstrap rollback,
injected SQLite migration failure, partial schema refusal, and future-version
refusal. Run:

```bash
.venv/bin/pytest -q tests/test_migrations.py tests/test_database.py
.venv/bin/pytest -q tests/test_database_recovery.py
```

These tests do not prove PostgreSQL parity, Docker startup, backup encryption,
or a production restore drill.
