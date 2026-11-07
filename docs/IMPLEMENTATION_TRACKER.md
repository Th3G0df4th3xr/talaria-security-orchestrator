# TALARIA implementation tracker

This file is the project-wide source of truth for the workstreams in the
implementation brief. A task is complete only when code and relevant tests
demonstrate its acceptance requirement. Documentation alone does not count as
implementation. Statuses reflect the repository as it stands; `⏳` means the
work is not complete and must not be treated as available.

The requirement-by-requirement execution register, architecture map, blockers,
and release gates are in [PRODUCTION_READINESS_MASTER_PLAN.md](PRODUCTION_READINESS_MASTER_PLAN.md).

## Track A — Multi-user authentication and RBAC

| ID | Requirement / acceptance evidence | Status |
|---|---|---|
| A01 | Hash and verify passwords with Argon2id; malformed inputs fail safely. | ✅ Implemented; successful login upgrades outdated Argon2 parameters transactionally, with API regression coverage |
| A02 | Sign and validate short-lived JWT access tokens with fixed issuer, audience, algorithm, and required claims. | ✅ Implemented; unit tests present |
| A03 | Generate high-entropy refresh tokens and store/compare only their hashes. | ✅ Primitives implemented; unit tests present |
| A04 | Persist refresh sessions, enforce expiry, and support lookup and revocation. | ✅ Implemented in schema v3; tests pass |
| A05 | Rotate refresh tokens atomically and invalidate the previous token. | ✅ Implemented; transaction tests pass |
| A06 | Detect refresh-token reuse and revoke the compromised token family. | ✅ Implemented; reuse tests pass |
| A07 | Revoke one session and all sessions for a user through authenticated logout/session controls. | ✅ Implemented; logout and logout-all tests pass |
| A08 | Persist users with unique normalized identities, password hashes, status, and timestamps. | ✅ Implemented in schema v5; auth tests pass |
| A09 | Persist organizations and lifecycle metadata. | ✅ Implemented in schema v5 with platform-admin creation flow |
| A10 | Persist organization memberships and enforce one supported role per membership. | ✅ Implemented in schema v5; membership tests pass |
| A11 | Provide a registration flow that cannot grant elevated roles to the registrant. | ✅ Implemented as org-admin-managed registration; role escalation tested |
| A12 | Authenticate credentials, issue access and refresh credentials, and resist account enumeration. | ✅ Generic credential failures and dummy-hash verification prevent account-existence disclosure; password login input now also enforces the 1,024-byte UTF-8 limit before user lookup/Argon2 and audit-logs the rejection; API tests pass |
| A13 | Validate and rotate refresh credentials through an endpoint. | ✅ Implemented; API tests pass |
| A14 | Provide authenticated logout and session revocation. | ✅ Implemented; API tests pass |
| A15 | Return the authenticated principal and authorized organization memberships. | ✅ Implemented at `/auth/me`; API tests pass |
| A16 | Bootstrap the first platform administrator through a one-time, non-public operator flow. | ✅ Secret-gated, one-time bootstrap endpoint; tests pass |
| A17 | Enforce `platform_admin`, `org_admin`, `security_lead`, `security_analyst`, `developer`, and `auditor` permissions. | 🟡 Role/action matrix behavior-tests all organization roles for every bearer-protected OpenAPI operation; OpenAPI contract requires bearer auth or an explicit documented control for every published API route; platform-admin explicit tenant scoping is tested; independent authorization review remains |
| A18 | Isolate organization-owned records and queries by tenant. | ✅ Core repository/scan/finding/dashboard and approval data are scoped; legacy data is assigned on first bootstrap |
| A19 | Enforce permissions on every protected API operation. | ✅ Core application and approval routes enforce authentication and roles |
| A20 | Record authentication and authorization outcomes without recording credentials or tokens. | ✅ Auth, authorization denials, findings, approvals, and webhook delivery metadata are audited |
| A21 | Test unauthenticated access, cross-tenant reads/writes, privilege escalation, and session attacks. | 🟡 Core IDOR, tenant, privilege, account/organization deactivation, refresh, and role/action cases tested; independent authorization review and broader abuse testing remain |

## Track B — GitHub PR automation

| ID | Requirement / acceptance evidence | Status |
|---|---|---|
| B01 | Configure a least-privilege GitHub App adapter. | 🟡 GitHub App client implemented with strict owner/repository path-segment and branch control-character validation; App permission setup and live verification pending |
| B02 | Authenticate to GitHub using short-lived App credentials. | 🟡 RS256 App JWT and installation-token exchange implemented; custom API base URLs require HTTPS and reject userinfo, query/fragment, traversal, percent-encoded, and backslash authority forms; credential-bearing requests reject redirects; live credential test pending |
| B03 | Install and onboard repositories with an explicit organization binding. | 🟡 Platform-admin-only onboarding verifies the remote repository through the configured App installation and binds its provider ID to a local tenant repository; live GitHub acceptance and managed multi-installation support remain |
| B04 | Receive bounded, authenticated GitHub webhook requests. | ✅ Webhook intake bounds payloads and validates signatures |
| B05 | Verify webhook signatures and reject invalid/replayed requests. | ✅ HMAC verification, 30-day delivery deduplication, and expiry cleanup tested |
| B06 | Record repository branch and commit identity for each analysis. | ✅ Branch and commit SHA persisted on scans; scanner/API tests pass |
| B07 | Map a finding to validated source locations and an immutable base commit. | ✅ Finding paths/lines and scan branch/commit provenance are persisted |
| B08 | Generate a proposed remediation patch with provenance. | 🟡 Opt-in LLM patch generator emits a base-SHA-bound proposal; review workflow pending |
| B09 | Validate patch paths, size, syntax, and policy before use. | 🟡 Temporary-copy apply/syntax validation implemented; full test/policy validation pending |
| B10 | Create a scoped branch without changing protected branches. | 🟡 Adapter now requires validator output bound to the exact patch digest/base, uploads the validated files as Git blobs, creates a tree and child commit, and reconciles a failed ref write only at that exact patch commit; mocked content/base/approval/reconciliation checks pass; live acceptance pending |
| B11 | Create an idempotent pull request only after authorization. | 🟡 Approval-checked adapter checks for exact existing PR content and reconciles a failed write with one exact-match provider lookup; mocked retry tests pass; persisted workflow orchestration and live acceptance remain |
| B12 | Include finding evidence, tests, limitations, and provenance in PR descriptions. | 🟡 Factual PR content builder records validation limits and approval; workflow integration pending |
| B13 | Read and persist CI/check status. | 🟡 Tenant-scoped authenticated synchronization fetches at most 100 GitHub check runs for an onboarded commit, validates and replaces that commit snapshot transactionally, audits the sync, and persists it in schema v17; paging beyond 100, event-driven refresh, and live acceptance remain |
| B14 | Synchronize PR state and handle provider retries idempotently. | 🟡 Signed events for onboarded repositories are checked against provider repository and installation IDs, persisted with tenant ownership, and deduplicated; a tenant-scoped API now derives latest PR state from the persisted event stream; persisted remediation workflow orchestration and live acceptance remain |
| B15 | Record human approval before consequential PR actions. | ✅ Two-person, tenant-scoped approval records and adapter enforcement implemented; tested |
| B16 | Track merge/close state from GitHub events or polling. | 🟡 Tenant-scoped pull-request summaries expose latest open/closed/merged state from signed events; synchronization into a persisted remediation workflow and live provider-state reconciliation remain |
| B17 | Audit GitHub actions with actor, repository, commit, and provider identifiers. | 🟡 Branch/PR writes record attempted, failed, completed, and reconciled-after-write-error outcomes with actor, approval, commit/digest, and PR number where available; persisted workflow references and provider IDs remain |
| B18 | Test with mocked provider responses and disposable repositories; no live writes in unit tests. | 🟡 Mocked adapter and webhook tests pass; disposable-repository acceptance pending |

## Track C — AI investigation and remediation

| ID | Requirement / acceptance evidence | Status |
|---|---|---|
| C01 | Define a provider-neutral LLM interface with typed input/output contracts. | ✅ Provider protocol and typed response schema implemented |
| C02 | Configure model/provider selection, timeouts, output bounds, and secret sources. | ✅ OpenAI-compatible settings, timeout, HTTPS check, response limits, and redirect rejection implemented |
| C03 | Implement an opt-in investigation path; deterministic analysis stays available. | 🟡 Authenticated endpoint persists tenant-scoped running/completed/failed records and exposes role-protected history; provider acceptance and retention policy remain |
| C04 | Ingest only authorized, bounded repository context. | 🟡 Tenant-scoped findings and configured repository roots gate bounded context; source is read with no-follow bounded file access, sensitive paths are excluded, and common credential patterns are redacted; provider data handling and broader context review remain |
| C05 | Analyze imports/dependencies with explicit limits and evidence. | 🟡 Static Python import extraction added; package-resolution/dependency graph pending |
| C06 | Investigate findings through a constrained workflow. | 🟡 Authenticated, rate-limited API persists running/completed/failed state, redacts recognizable credentials from returned rationale/remediation, records unexpected provider exceptions without exposing their text, and recovers runs older than five minutes at startup and every 60 seconds in audited batches of 100 (history reads also recover the selected tenant); multi-stage workflow and deployed restart/load acceptance remain |
| C07 | Attach source-linked evidence for each material conclusion. | 🟡 Context evidence IDs include the full source-content digest, citations are validated, and references are persisted; broader evidence review remains |
| C08 | Separate observed evidence from root-cause hypotheses. | 🟡 Prompts require uncertainty/evidence; root-cause workflow pending |
| C09 | Assess false positives with uncertainty and human review. | 🟡 Output supports a likely-false-positive assessment; reviewer workflow pending |
| C10 | Produce remediation recommendations without granting execution authority. | 🟡 Recommendation output exists; evidence evaluation and reviewer workflow pending |
| C11 | Generate patches only in an isolated, reviewable workspace. | 🟡 Opt-in LLM patch proposal generator added; no repository writes |
| C12 | Validate generated patches with deterministic checks before approval. | 🟡 Base-SHA/clean-tree checks, git apply, and Python AST validation run on a temp copy; source and finding context are redacted before provider submission, and generated credential-like output is rejected; broader repository/security tests and approval workflow remain |
| C13 | Add multi-agent orchestration only with explicit stage boundaries. | ⏳ |
| C14 | Enforce execution time, memory, file, and network controls. | 🟡 Investigation and patch-proposal outputs are byte-bounded across provider implementations; repository reads and provider calls have limits/timeouts. OS-level CPU/memory/network isolation and deployed load acceptance remain |
| C15 | Apply server-side per-tool permissions; model output cannot authorize actions. | 🟡 Investigation requests advertise no tools and the provider client rejects tool/function-call responses even when text is also returned; no tools are implemented, so a server-side allowlist is still required before any tool is added |
| C16 | Test prompt-injection resistance using hostile repository content. | 🟡 A maintained local corpus includes hostile retrieved instructions and verifies the system boundary and output policy; fake-provider tests do not establish model resistance, so external provider evaluation remains |
| C17 | Test retrieval integrity against poisoned/untrusted source material. | 🟡 Scan-time file digests are stored with findings; bounded no-follow reads compute current digests and source sharing fails closed on a missing or mismatched digest; the local evaluation corpus checks citation grounding and hostile retrieval; provider-level poisoning evaluation remains |
| C18 | Audit agent steps, tool inputs/outputs, and decisions with sensitive-data controls. | 🟡 Investigation success/failure audits record actor, finding, decision summary, and source-sharing state without provider prompts or source text; multi-stage traces remain |
| C19 | Require human approval before patch publication or other consequential actions. | 🟡 GitHub branch and PR writes consume tenant-scoped, two-person approvals bound to the exact base/content/patch digest; an offline generated-patch-to-branch test proves denial before approval and authorization after a second-person decision. A persisted AI remediation workflow and actual patch-to-PR publication remain |
| C20 | Maintain evaluations for grounding, security, quality, repeatability, cost, and latency. | 🟡 A deterministic local corpus checks grounding, hostile retrieved text, citation rejection, and output redaction; real provider quality/repeatability, token/cost reporting, and latency measurements remain |

## Track D — Production deployment hardening

| ID | Requirement / acceptance evidence | Status |
|---|---|---|
| D01 | Support PostgreSQL with equivalent constraints and transaction behavior. | 🟡 PostgreSQL v11 baseline plus checksummed v12–v17 migrations, GitHub repository and check-run tenant mapping, qmark adapter, tenant constraints, readiness checks, shared rate-limit state, serialized bootstrap/refresh operations, and ephemeral PostgreSQL 17 CI service added; live PostgreSQL acceptance remains |
| D02 | Version migrations, backup/restore behavior, and a documented rollback strategy. | 🟡 SQLite empty-schema bootstrap now takes a write lock and creates all baseline tables in one rollback-capable transaction; eight-way fresh initialization and injected partial-bootstrap rollback tests pass. Legacy v0/v1 baselines upgrade sequentially through v2–v17 with boundary, preservation, injected rollback, and future-version tests. Backup/recovery/upgrade copies are verified and fsynced before atomic no-overwrite publication; failed destination-directory sync attempts to remove the unpublished target. PostgreSQL v11 baseline/v12–v17 migrations and backup/restore tools exist; live PostgreSQL restore and encrypted off-host drills remain |
| D03 | Validate typed environment configuration and fail safely on invalid settings. | 🟡 Application startup validates JWT signing configuration, repository roots, scan limits, configured secret files, AI booleans/timeouts/provider completeness, partial GitHub App credentials, and PostgreSQL TLS policy without network access; PostgreSQL requires TLS except for plaintext connections to exact operator-listed trusted hosts; use `verify-full` with a managed CA for identity validation; remaining typed configuration and live certificate/deployment acceptance remain |
| D04 | Load secrets from deployment secret facilities and prevent accidental logging. | 🟡 Docker secret files cover PostgreSQL, JWT, bootstrap, GitHub, and LLM credentials; non-empty files are rejected unless owner-only, and live deployment/ownership validation remains |
| D05 | Build a minimal, non-root production container. | 🟡 Dockerfile added; image build unavailable in current environment |
| D06 | Provide a local deployment composition with health checks and persistent data. | 🟡 Loopback-only Compose includes PostgreSQL, API, and dashboard services, isolated DB networking, mounted secrets, and health checks; Docker runtime verification remains unavailable |
| D07 | Provide Kubernetes manifests with resource/security constraints. | 🟡 Restricted StatefulSet/ClusterIP manifest added; cluster validation pending |
| D08 | Document and enforce TLS at the supported ingress boundary. | 🟡 Optional Caddy Compose overlay provides automatic HTTPS and routes API/webhook paths separately from the dashboard; DNS, firewall, trusted-proxy address, and live certificate acceptance remain |
| D09 | Rate-limit authentication and resource-intensive operations. | 🟡 Shared database-backed GCRA throttles cover auth, approval, scan, AI, GitHub onboarding, check-run synchronization, and webhook paths; dynamic finding, approval, repository, and commit identifiers map to stable quota keys so they cannot split per-client limits. Bounded local guard and ASGI 1,000,000-byte body limit remain. SQLite sharing and ID-variation bypass regressions pass; live PostgreSQL concurrency acceptance remains; PostgreSQL uses server time |
| D10 | Add safe security headers and explicit CORS policy. | 🟡 Security headers added; CORS remains disabled by default |
| D11 | Emit structured, redacted application logs. | 🟡 JSON HTTP request events include opaque request IDs and omit query strings, bodies, tokens, and client IP; broader application/audit log policy and centralized collection remain |
| D12 | Expose bounded service and scan metrics. | 🟡 Token-protected Prometheus text endpoint reports bounded HTTP request/latency and scan outcome metrics; the GitHub check-run route maps repository IDs and commit SHAs to a fixed metric label. Metrics are process-local and alerting/operational acceptance remain |
| D13 | Separate liveness and dependency-aware readiness probes. | 🟡 Read-only readiness checks SQLite integrity/checksums or PostgreSQL v11 baseline, v12–v17 migration checksums, and required tables; live PostgreSQL acceptance remains |
| D14 | Document and test encrypted backup and restore procedures. | 🟡 PostgreSQL restore preflight rejects public relations/routines/user-defined types and non-system custom schemas before invoking `pg_restore`; SQLite and mocked PostgreSQL backup/restore checks pass; encryption remains external and live PostgreSQL encrypted restore drills remain |
| D15 | Automate build, verification, and controlled deployment stages. | 🟡 CI now runs lint, tests, package/container builds; controlled deployment remains |
| D16 | Scan dependencies and container artifacts in CI. | 🟡 Dependency and secret-history scans plus critical/high Trivy scans for TALARIA, Compose PostgreSQL, and TLS Caddy images are configured; CI PostgreSQL matches the Compose image; GitHub Actions are full-SHA pinned and Dependabot proposes weekly action/container/Python updates; workflow-run validation pending |
| D17 | Keep threat models current with shipped controls and residual risks. | 🟡 Threat-model documents exist; update after each track |
| D18 | Add security tests for auth, tenant boundaries, integrations, and patch handling. | 🟡 Core auth, tenant, webhook replay, GitHub URL/path-injection rejection, AI authorization/context, GitHub audit, patch, dashboard TLS-origin/redirect/refresh enforcement, secret-file loading, readiness, backup/recovery, every SQLite migration boundary, failed-migration rollback, and future-schema refusal tests pass; CI uses ephemeral PostgreSQL 17 while local live tests skip without a disposable server; independent security review remains |
| D19 | Measure concurrency/resource limits and graceful overload behavior. | 🟡 Docker Compose now bounds CPU, memory, and process counts for PostgreSQL, API, and dashboard containers; resource sizing, load/concurrency measurements, and graceful-overload acceptance remain |
| D20 | Document supported production topology, operations, backup, upgrades, and incident response. | 🟡 Single-VM Compose runbook covers startup, verified backup-before-PostgreSQL-migration, restore, secret rotation, and incident recovery; live operational acceptance, alerting, and organization-specific incident procedures remain |

## Execution order

1. Keep the schema-v0 original untouched. The supplied recovered copy remains at schema v12; use `TALARIA_DATABASE=<recovered-copy> talaria upgrade-db --copy-to <new-v17-path>` and verify the published copy before serving API traffic or importing to PostgreSQL.
2. Complete the Track A role/action matrix and comprehensive tenant isolation checks.
3. Integrate Track B from repository onboarding through PR/check/event synchronization; live GitHub credentials and a disposable repository are needed for provider acceptance.
4. Close Track C injection, execution-isolation, evidence-grounding, audit, and evaluation gaps before enabling AI workflows.
5. Complete live PostgreSQL and Docker VM acceptance for the selected target; implement TLS, monitoring, encrypted off-host backups, live restore drills, and deployment acceptance.
6. Run end-to-end success and failure acceptance across scanning, investigation, approval, PR, CI, synchronization, and audit flows.

## Database hardening batch

- SQLite migration functions are registered once in `SQLITE_MIGRATIONS` and
  applied in ascending version order. The supported legacy inputs are the
  pre-versioned schema-v0 and compatible schema-v1 baseline; numbered
  migrations begin at v2. Initialization rejects a future `user_version`
  before running legacy table setup. Tests upgrade every baseline v0 through
  v17, verify preserved findings/audit/occurrences and checksums, inject a
  failed v3 migration to prove rollback, and reject future/unsupported schema
  versions. One exact v2 checksum found in the supplied recovered copy remains
  accepted; new databases use the current v2 checksum and all other drift fails.
- Read-only inspection on 2026-11-07 found the original `.talaria/talaria.db`
  remains v0 with one repository, three scans, two findings, four audit events,
  and two foreign-key violations from the known missing scan ID 0 references.
  The recovered `.talaria/talaria-recovered-v10.db` is v12 with one repository,
  four scans, two findings, two occurrences, five audit events, successful
  SQLite quick check, and zero foreign-key violations. No source records were
  changed during this inspection.
- API readiness is read-only and requires schema version 17, recognized stored
  migration checksums (including one documented historical v2 digest), SQLite
  integrity, and zero foreign-key violations. API database handles do not
  initialize or create missing databases.
- `talaria upgrade-db` applies migrations explicitly and creates a verified,
  timestamped backup first. Migration steps acquire SQLite's write lock before
  checking the current schema version. Fresh SQLite baseline creation also
  takes a write lock before inspecting the schema and creates all four legacy
  tables in one explicit transaction, preventing concurrent first-start races
  and partial bootstrap schemas.
- `talaria backup-db` and `talaria restore-db` create verified copies at new
  paths without overwriting existing files. `talaria recover-legacy-db` repairs
  schema-v0 orphaned findings in a new copy and migrates it through the current schema.
- The workspace database `.talaria/talaria.db` remains unchanged at schema 0
  (file permissions were restricted to owner read/write). The recovered copy
  `.talaria/talaria-recovered-v10.db` is at schema 12; verified pre-migration
  backups at schemas 10 and 11 were created before their respective upgrades.
  The copy preserves both findings and links them to a marked failed recovery
  scan. Docker Compose targets PostgreSQL 17; live PostgreSQL and VM acceptance
  remain production milestones.

The current repository has not completed these tracks merely because a design
or placeholder exists. Review this tracker alongside [the roadmap](ROADMAP.md)
after each implementation batch.
