# STRIDE Threat Analysis

| ID | Threat | Boundary / asset | Example | Mitigation | Residual |
|---|---|---|---|---|---|
| S-01 | Spoofing | Operator -> API | Unauthenticated caller invokes scan endpoint | Loopback-only now; authentication and identity before shared deployment | High until auth exists |
| T-01 | Tampering | Repository -> scanner | Crafted profile or source input alters scan behavior | Validate profile schema; no repository code execution; safe regex policy | Medium |
| T-02 | Tampering | App -> database | Broken transaction leaves inconsistent scan/finding records | Foreign keys per connection, transactions, migrations, integrity checks | Medium |
| R-01 | Repudiation | Operator actions | Scan or approval cannot be attributed to an actor | Structured audit events with actor, timestamp, correlation ID | Medium |
| I-01 | Information disclosure | Findings/reports | Secret appears in snippet or exported report | Redaction, access controls, retention, output minimization | Medium |
| I-02 | Information disclosure | API | Absolute paths or exception details leak host information | Stable sanitized errors; loopback-only | Medium |
| D-01 | Denial of service | Repository -> scanner | Huge tree or pathological regex consumes CPU/disk | File count/size/total-byte/time limits; bounded regex; cancellation | High until complete |
| E-01 | Elevation of privilege | API -> filesystem | Caller supplies path outside authorized roots | Explicit allowlist and authorization on every operation | High until implemented |
| E-02 | Elevation of privilege | AI -> GitHub (future) | Prompt injection persuades agent to create/merge code | No model-held write credentials; policy gate; human approval | High until designed and tested |

## STRIDE notes

- **Spoofing:** Localhost binding reduces network exposure but does not authenticate local processes.
- **Tampering:** SQLite foreign keys are enabled on each connection; PostgreSQL uses database constraints. Both backends use atomic transactions, and PostgreSQL refuses mismatched baseline schemas.
- **Repudiation:** Basic event records are not equivalent to tamper-proof audit logging.
- **Information disclosure:** Source snippets and file paths can contain proprietary or sensitive material.
- **Denial of service:** Per-file size checks alone do not bound total repository cost or pathological regular expressions.
- **Elevation of privilege:** A path accepted by the API is not automatically an authorized path.

## Prioritization

Address high residual risks before any shared or internet-facing deployment: authentication/authorization, repository-root allowlisting, complete scan resource limits, database integrity, and secret redaction. AI and GitHub risks must be mitigated before those integrations are enabled.

## Verification

Every mitigation should have a test or operational check. Examples include path traversal and symlink tests, malformed profile tests, resource-limit tests, database foreign-key checks, API unauthenticated-access tests, and prompt-injection evaluation for future AI features.
