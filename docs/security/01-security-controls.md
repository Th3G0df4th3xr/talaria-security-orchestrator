# Security Controls

## 1. Security objectives

Protect repository confidentiality, database integrity, operator control, and the integrity of findings and audit records. TALARIA processes potentially proprietary source code and must be treated as a security-sensitive tool.

## 2. Current controls and gaps

| Control | Current state | Required next step |
|---|---|---|
| Local repository validation | Git roots validated; API roots default to cwd or configured allowlist; symlinks excluded | Expand filesystem race and production-root tests |
| YAML hunter profiles | Implemented | Schema validation and safe-regex controls |
| Finding fingerprinting | Implemented | Separate canonical findings from occurrences |
| Persistence | SQLite v16 checksummed migrations, serialized upgrades, verified copy/restore, legacy recovery, tenant-bound GitHub repository mappings, and append-only chained audit rows; PostgreSQL v11 baseline plus v12–v16 migrations, shared throttling buckets, audit-chain verification, readiness checks, and guarded SQLite import | Live PostgreSQL acceptance, encrypted off-host backups, restore drills, immutable external audit checkpoints, and operational rollback |
| Audit and request events | Database audit events plus redacted JSON HTTP request logs and request IDs | Retention policy, tamper-resistant export, centralized collection, and alerts |
| API request validation | Strict Pydantic inputs, bearer dependencies, organization scoping, and representative role/action matrix | Independent exhaustive authorization and abuse review |
| Authentication/RBAC | JWT, Argon2id, rotating/revocable sessions, organizations, memberships, route role checks, and shared database-backed throttling | MFA/SSO decision, live PostgreSQL throttling acceptance, and production acceptance |
| Secret management | Environment, Docker secret, and Kubernetes Secret hooks; examples contain placeholders | Select and validate a production secret manager; rotate credentials operationally |
| Outbound credential transport | GitHub App and LLM HTTP clients reject redirects, preventing `urllib` from forwarding bearer credentials to a redirect target | Validate provider behavior in staging and retain strict TLS/egress policy |
| Dashboard credential transport | Dashboard API client rejects non-TLS remote origins and URL userinfo, query, fragment, path-prefix, and ambiguous authority forms; HTTP is limited to loopback and the exact Compose API service | Validate the UI-to-API network boundary and TLS termination in the target deployment |
| PostgreSQL transport | TLS is required unless the exact database hostname appears in `TALARIA_DATABASE_TRUSTED_HOSTS`; the plaintext exception rejects hostaddr/service routing overrides; Compose trusts only its internal `postgres` service name | Prefer `sslmode=verify-full` with managed CA roots; `sslmode=require` encrypts without authenticating the server; validate certificate rotation and trusted network at deployment |
| CI supply chain | GitHub Actions are pinned to full commit SHAs; Dependabot checks action, container, and Python dependencies weekly | Review and merge update proposals; verify CI and security scan runs |
| Scan resource limits | File, byte, depth, and profile limits; API repository-root allowlist | Load tests, cancellation, and resource measurements for production workloads |
| AI safety | Opt-in analysis-only LLM adapter with no tools; bounded source context, heuristic source/response credential redaction, and evidence-reference validation | Redaction cannot guarantee all secrets; adversarial evaluations, execution isolation, and reviewer workflow remain |
| GitHub write controls | Branch/PR adapter methods require persisted second-person approval | Repository onboarding, full orchestration, live acceptance, and state synchronization |

## 3. Repository access

Only scan repositories the operator is authorized to assess. Resolve paths, verify repository roots, and restrict targets to configured approved roots when running as a service. Avoid following symlinks outside the approved root. Do not modify repository files during scanning.

## 4. Input and parser safety

Treat source files and YAML profiles as untrusted input. Bound file size, file count, total scan duration, regex complexity, and output size. Reject malformed profiles. Avoid evaluating code from repositories. Never execute build scripts, tests, hooks, or package installation steps from a scanned repository as part of a scan.

## 5. Secrets and sensitive data

Never log credentials or full environment contents. Redact likely secrets from snippets and reports. Store tokens outside the repository. Keep `.env`, SQLite databases, backups, caches, and reports out of Git unless a sanitized fixture is intentionally committed.

## 6. API controls

The API requires bearer authentication for protected application routes and scopes core records to an organization. Readiness checks are read-only and require the current migration checksum history. Keep it bound to loopback until the selected TLS boundary, shared rate limits, deployment controls, and independent authorization review are complete. Validate all inputs, avoid leaking absolute paths or stack traces, and keep cross-origin access disabled unless explicitly configured.

## 7. Database and audit

Enable foreign keys on every SQLite connection. PostgreSQL enforces database constraints and uses transactional row locks for concurrent bootstrap and refresh rotation. Use immediate SQLite transactions for state transitions and migrations. Back up before schema upgrades, verify recovery copies, and audit registration, scan start/completion/failure, finding status changes, approvals, and integration actions. Do not include secrets or unnecessary source content in audit details.

## 8. Release gate

A release must pass formatting, linting, type checks where configured, unit/integration tests, dependency audit, secret scan, database integrity checks, and a manual review of permissions and network exposure. Document known limitations rather than claiming controls that do not exist.
