# Entity Relationship Model

## 1. Current relationships

```text
Organization (1) -- (*) GitHubRepository
GitHubRepository (1) -- (*) GitHubCheckRun
repositories (1) -------- (many) scans
repositories (1) -------- (many) findings
scans       (1) -------- (many) findings
audit_events (independent event log)
```

`scans.repository_id` references `repositories.id`. `findings.repository_id` references `repositories.id`, and `findings.scan_id` references `scans.id`.

## 2. Current cardinality caveat

The current unique constraint on `findings.fingerprint` makes the findings table behave like a global deduplicated issue store, while its `scan_id` column points to only one scan. It therefore cannot represent every repeated observation of the same issue. A later scan can detect the same fingerprint without recording a separate historical occurrence.

## 3. Target normalized relationship

```text
Repository 1 ---- * Scan
Repository 1 ---- * Finding
Finding    1 ---- * FindingOccurrence
Scan       1 ---- * FindingOccurrence
Repository 1 ---- * AuditEvent (recommended attribution)
```

A `FindingOccurrence` joins one canonical finding to one scan. The combination of finding ID and scan ID should be unique unless the product intentionally supports multiple locations/occurrences per scan, in which case include location identity in the uniqueness key.

## 4. Target entity responsibilities

- Repository: identity, canonical local/provider location, registration and authorization metadata.
- Scan: repository, commit/revision, profile version, start/end, status, counts, failure details.
- Finding: stable identity, rule metadata, severity, status, owner, first/last seen.
- FindingOccurrence: scan-specific location and evidence.
- AuditEvent: actor, event type, object reference, timestamp, correlation ID, safe structured details.
- Approval: human decision, reviewer identity, scope, decision, timestamp, and rationale (future).
- GitHubCheckRun: provider check-run identity, commit, validated status and
  bounded result metadata; one row is keyed by provider repository and check-run
  ID, and inherits its tenant boundary through the repository mapping.

## 5. Referential integrity

Use explicit foreign keys with deliberate delete behavior. Prefer soft deletion or archival for repositories and findings where audit history must remain. Avoid cascading deletion of audit evidence. SQLite connections enable foreign keys individually; PostgreSQL enforces its declared constraints directly.

## 6. Migration approach

1. Back up the database and verify the backup can be opened.
2. Create a migration with a version identifier.
3. Create the new occurrence table.
4. Backfill occurrences only where scan identity is supported by reliable evidence.
5. Record unresolved legacy rows for manual reconciliation; do not invent scan IDs.
6. Verify row counts, uniqueness, and foreign-key checks.
7. Run the full test suite against a disposable migrated copy.
8. Promote only after explicit backup and rollback readiness.
