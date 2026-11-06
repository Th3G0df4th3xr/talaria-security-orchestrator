# Security Controls

## 1. Security objectives

Protect repository confidentiality, database integrity, operator control, and the integrity of findings and audit records. TALARIA processes potentially proprietary source code and must be treated as a security-sensitive tool.

## 2. Current controls and gaps

| Control | Current state | Required next step |
|---|---|---|
| Local repository validation | Implemented in repository service | Add explicit allowlisted roots and symlink tests |
| YAML hunter profiles | Implemented | Schema validation and safe-regex controls |
| Finding fingerprinting | Implemented | Separate canonical findings from occurrences |
| SQLite persistence | Implemented | Enable foreign keys per connection; transactional scan writes; migrations |
| Audit events | Basic event writes implemented | Actor identity, event coverage, tamper resistance, retention |
| API request validation | Pydantic models | Add authorization before network exposure |
| Authentication/RBAC | Not implemented | Required before shared deployment |
| Secret management | Local example configuration only | Use OS credential store/secret manager |
| Scan resource limits | Basic per-file size setting | Add file count, total bytes, timeout, symlink and cancellation controls |
| AI safety | No active AI investigation | Threat model and evaluation before enablement |
| GitHub write controls | Not implemented | Least privilege and human approval |

## 3. Repository access

Only scan repositories the operator is authorized to assess. Resolve paths, verify repository roots, and restrict targets to configured approved roots when running as a service. Avoid following symlinks outside the approved root. Do not modify repository files during scanning.

## 4. Input and parser safety

Treat source files and YAML profiles as untrusted input. Bound file size, file count, total scan duration, regex complexity, and output size. Reject malformed profiles. Avoid evaluating code from repositories. Never execute build scripts, tests, hooks, or package installation steps from a scanned repository as part of a scan.

## 5. Secrets and sensitive data

Never log credentials or full environment contents. Redact likely secrets from snippets and reports. Store tokens outside the repository. Keep `.env`, SQLite databases, backups, caches, and reports out of Git unless a sanitized fixture is intentionally committed.

## 6. API controls

Until authentication and authorization are implemented, bind the API to loopback only. Validate all inputs, avoid leaking absolute paths or stack traces, and disable permissive cross-origin access. Add rate limits and job concurrency limits before shared use.

## 7. Database and audit

Enable foreign keys on every SQLite connection. Use transactions for state transitions. Add migrations and backup/restore tests. Audit registration, scan start/completion/failure, finding status changes, approvals, and integration actions. Do not include secrets or unnecessary source content in audit details.

## 8. Release gate

A release must pass formatting, linting, type checks where configured, unit/integration tests, dependency audit, secret scan, database integrity checks, and a manual review of permissions and network exposure. Document known limitations rather than claiming controls that do not exist.
