# Data Model

## 1. Current persistence

The current SQLite schema contains four core tables: `repositories`, `scans`, `findings`, and `audit_events`. The current implementation stores finding details as JSON in `findings.payload`.

## 2. Current entities

### repositories

| Field | Meaning |
|---|---|
| id | Integer primary key |
| name | Repository display name |
| path | Resolved local path; unique |
| registered_at | Registration timestamp |

### scans

| Field | Meaning |
|---|---|
| id | Integer primary key |
| repository_id | Foreign key to repositories |
| started_at | Scan start timestamp |
| completed_at | Completion timestamp; null while incomplete |
| finding_count | Number of detections returned by that scan |

### findings

| Field | Meaning |
|---|---|
| id | Integer primary key |
| fingerprint | Unique deterministic finding fingerprint |
| repository_id | Foreign key to repositories |
| scan_id | Foreign key to scans |
| payload | JSON-serialized finding data |

### audit_events

| Field | Meaning |
|---|---|
| id | Integer primary key |
| event | Event type |
| details | JSON event details |
| created_at | Event timestamp |

## 3. Important current limitation

The present schema combines a canonical finding and its scan observation in one row. A unique fingerprint prevents duplicate rows, but it also means later scans may not create a new occurrence record for an existing fingerprint. This weakens history and can make the stored `scan_id` represent only the first observation.

The target model should separate:
- **Finding**: stable issue identity and lifecycle.
- **FindingOccurrence**: a finding observed in a specific scan, commit, path, and line.
- **Scan**: one execution against a repository revision and profile.
- **Repository**: registered source repository.
- **AuditEvent**: actor/action/time/context record.

## 4. Target finding fields

Recommended canonical fields include ID, repository ID, fingerprint, rule ID, title, severity, status, first-seen timestamp, last-seen timestamp, owner, and lifecycle metadata.

Recommended occurrence fields include ID, finding ID, scan ID, commit SHA, path, line, code evidence reference, and observed timestamp.

Avoid storing full source files or large snippets. Store the minimum evidence required for review and apply retention limits.

## 5. Integrity requirements

- Enable SQLite foreign-key enforcement on every connection.
- Use transactions for scan creation, finding/occurrence persistence, completion, and audit events.
- Enforce foreign keys and unique constraints.
- Use UTC timestamps with an explicit format.
- Validate JSON payloads before persistence.
- Add schema migrations; do not rely on ad hoc manual SQL in production.
- Run `PRAGMA foreign_key_check` and `PRAGMA integrity_check` during diagnostics.

## 6. Data classification and retention

Repository paths, snippets, findings, and audit details may reveal proprietary information or secrets. Treat them as sensitive security data. Restrict filesystem permissions, redact secrets, define retention, and securely dispose of database backups when no longer needed.
