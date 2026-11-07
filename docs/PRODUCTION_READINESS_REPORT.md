# TALARIA readiness report

**Assessment date:** 2026-11-07
**Decision:** **NOT PRODUCTION READY**
**Scope:** Local repository, source, tests, docs and read-only workspace database
inspection. No live provider, Docker, PostgreSQL, Kubernetes, or deployment
acceptance was performed.

## Requirement status

- Original tracker: **79** requirements — **26 complete**, **52 partial**,
  **1 not started**. “Complete” reflects repository tests/evidence recorded by
  the tracker, not independent security certification.
- Master directive: **85** additional requirements — **18 implemented but not
  fully verified**, **36 partial**, **18 not implemented**, **11 blocked by
  external infrastructure/credentials**, **2 requiring external human
  approval**. The full cross-reference is in
  [the master plan](PRODUCTION_READINESS_MASTER_PLAN.md).
- Advanced scenarios: **12 required** — **0 complete scenario executions**,
  **9 partial**, **2 blocked**, **1 not implemented**. See the
  [scenario report](PRODUCTION_ACCEPTANCE_TEST_REPORT.md).
- Independent external security reviews completed: **0**.

## Implemented in the current migration batch

- Added shared database-backed GCRA request throttling and fail-closed handling
  for protected high-cost routes. SQLite and PostgreSQL schema v16 include
  hashed request-scope buckets; PostgreSQL multi-connection concurrency remains
  unverified until the disposable service is available.

- Consolidated SQLite migration registration in `SQLITE_MIGRATIONS` and used
  that registry as the single sequential invocation list.
- Added `talaria upgrade-db --copy-to <path>` for atomic source-preserving
  SQLite upgrades. The destination is published only after current-schema
  readiness succeeds; broken legacy input leaves the source unchanged and no
  destination behind.
- Added a preflight rejection for SQLite databases with `user_version` newer
  than the supported v17; added a post-migration version assertion.
- Added tests from legacy v0/v1 and every intermediate v2–v17 state through the
  current schema, including preserved records, checksum/readiness validation,
  foreign keys, injected v3, v13, v14, v15, and v16 rollback, registry continuity, and future-version
  refusal without schema mutation. Initialization also refuses partial legacy
  SQLite schemas without creating tables before the migration validates them.
- Expanded recovery acceptance fixtures to preserve scans 1–3 and audit history,
  retain finding IDs/payloads, leave valid scan associations unchanged, and
  associate orphaned findings only with a clearly marked synthetic recovery
  scan that lists the missing historical scan ID.
- Added v16 tenant-bound GitHub repository mappings, platform-admin-only
  onboarding, installation-checked webhook intake, and SQLite-to-PostgreSQL
  transfer coverage for the mappings and tenant-scoped event summaries.
- Added schema v17 GitHub check-run persistence and an authenticated tenant-
  scoped synchronization endpoint. A fetched commit snapshot is validated,
  bounded to 100 runs, replaced transactionally, and audited; unsupported
  pagination and live provider verification remain open.
- Added a local AI evaluation corpus for grounded findings, hostile retrieved
  content, citation rejection, and response redaction. It validates TALARIA's
  provider boundary using fake providers; model quality, repeatability, usage-
  based cost, and latency still need a controlled provider evaluation.
- Added a shared no-redirect HTTP helper for GitHub App and LLM requests. Python's
  default redirect behavior can forward authorization headers; redirects now
  fail closed, with tests for the helper and both credential-bearing clients.
- Hardened the separate AI patch-proposal path: the base-commit source check
  uses original context, while a distinct redacted copy of finding/source data
  is sent to the provider; recognizable credential patterns in generated patch
  output are rejected. Added prompt and output regression tests.
- Closed a GitHub publication defect where approved branch creation previously
  pointed only at the base commit. The adapter now requires the validator's
  bounded output bound to the approved base and patch digest, uploads the
  validated file contents, creates a child commit, and points the branch at
  that commit. Lost ref-write responses reconcile only when the remote ref
  points at the expected patch commit. Mock tests cover contents, parent, exact
  ref target, and approval gating; persisted workflow orchestration and live
  GitHub acceptance remain outstanding.
- Successful authentication now upgrades outdated Argon2 password hashes
  using a conditional transactional update and records the upgrade in the audit
  chain. Role-matrix coverage now includes the GitHub binding list endpoint.
- PostgreSQL restore now rejects targets containing relations, routines, or
  user-defined types in `public`, and rejects non-system custom schemas before
  running `pg_restore`; mock tests cover both refusal cases. Live PostgreSQL
  restore acceptance remains outstanding.
- CI now runs its disposable PostgreSQL service using the Compose image and
  scans the TALARIA, PostgreSQL, and TLS Caddy images with Trivy for critical
  and high vulnerabilities. Workflow execution is still pending.
- Docker Compose now sets configurable CPU and memory ceilings and PID limits
  for PostgreSQL, API, and dashboard services. Static manifest tests pass;
  Docker runtime validation and workload sizing have not been performed.
- The dashboard API client disables HTTP redirects and rejects redirect
  responses for both authenticated requests and refresh rotation; a rejected
  refresh clears local credentials. Mock-client regressions cover these paths.
- The dashboard API client requires HTTPS for remote origins and rejects
  credentials, query strings, fragments, path prefixes, and ambiguous authority
  forms. Plain HTTP is limited to loopback and the exact Compose API service.
  Target network-boundary acceptance remains open.
- Application startup now validates the JWT signing secret, repository root
  directories, scan limits, configured secret files, AI settings/provider
  completeness, and partial GitHub App configuration. It does not contact
  providers; malformed settings fail before the service accepts requests. An
  empty mounted LLM key is accepted only while AI is disabled, matching the
  Compose placeholder-secret configuration.
- Pinned third-party GitHub Actions in CI to full commit SHAs and added weekly
  Dependabot proposals for GitHub Actions, Docker images, and Python packages.
- Added an AI adapter-level output byte limit so oversized responses from any
  provider implementation are rejected before JSON parsing; focused tests,
  full pytest, Ruff, and diff checks pass.
- Backup, recovery, and upgrade publishers now fsync completed database files
  and their containing directory around atomic no-overwrite publication. If
  directory synchronization fails after linking the destination, publication
  attempts to roll back the visible destination and reports failure. This
  covers local crash durability; filesystem-specific behavior and live
  PostgreSQL restore durability still require deployment acceptance.
- Added an OpenAPI route-authentication contract test: every published API
  operation must declare bearer authentication or appear on an explicit list
  of routes with a separate control. The hidden metrics route is separately
  checked and its token gate has request-level tests. Full role/action review
  remains incomplete.
- Fixed a rate-limit bypass on AI investigation and approval-decision routes:
  caller-controlled finding/approval IDs now share stable per-client quota
  keys. API regression confirms changing finding IDs does not evade the
  five-request investigation limit.
- Added a provider-independent byte limit to generated patch proposal output;
  oversized results fail before Pydantic JSON parsing or patch validation.
- Added scan-time source SHA-256 values and bounded no-follow file reads. When
  source sharing is enabled, TALARIA rejects changed or legacy findings without
  a scan-time digest before contacting the model; evidence IDs carry the source
  digest. Real-provider retrieval-poisoning evaluation remains outstanding.
- Added a scanner race regression that swaps a checked source file to an external
  symlink immediately before open; the no-follow file-descriptor read rejects it.
- Repository roots are now required to be canonical, and secure reads open each
  root path component without following symlinks. A symlinked root regression
  passes, closing the root-swap redirection gap before source collection.
- Corrected the PostgreSQL operations runbook so operators build the reviewed
  image, run the one-off upgrade with its required verified backup path, then
  start services. A static documentation test locks in that ordering.
- GitHub repository owner/name segments now accept only a strict ASCII set,
  branch names reject control characters, and the API client rejects control
  characters in paths before constructing credentialed requests. Injection
  regressions confirm rejection before the provider client is called.
- Custom GitHub API bases now require HTTPS and reject embedded credentials,
  query/fragment delimiters, traversal, and ambiguous authority encodings while
  retaining clean HTTPS Enterprise API prefixes.
- The role matrix now checks every bearer-protected OpenAPI operation for
  coverage and exercises each listed operation against every organization
  role. It exposed and closed omissions for finding detail/status/investigation
  and approval-decision routes.
- Approval service methods now recheck active requester/reviewer status and
  organization roles inside the transaction; decision time is measured after
  acquiring the transaction lock. Offline tests also connect an AI-generated
  patch digest to second-person branch authorization. The persisted
  patch-to-PR workflow remains incomplete.
- Added a static v17 SQLite/PostgreSQL declaration comparison for table and
  column names. This catches declaration drift but does not substitute for a
  PostgreSQL server test of types, constraints, transactions, or cascades.
- Read-only inspected the original and recovered local SQLite files. The
  original remains unchanged; the recovered copy passes SQLite integrity and
  foreign-key checks. Neither result substitutes for a PostgreSQL restore
  drill or establishes historical provenance for the orphan findings.
- Added traceability for all 85 directive IDs and all 12 advanced scenarios,
  with conservative statuses and explicit external blockers. Added engineering
  decisions, security assessment, operations, release, external acceptance,
  and scenario report documents.

## Verification

- `ruff check .`: passed.
- `git diff --check`: passed.
- `.venv/bin/pytest -ra`: **393 passed, 6 skipped, 0 failed**, one Starlette/httpx
  deprecation warning. All skips are PostgreSQL integration tests because
  `TALARIA_TEST_POSTGRES_URL` is unset.
- Authentication API checks: **21 passed**, including an oversized multibyte
  login password rejected before password verification.
- SQLite backup, CLI, and recovery checks: **18 passed**, including failure
  handling for an unusable destination directory without changing the source.
- PostgreSQL backup helpers reject malformed connection URLs with a sanitized
  error for both backup and restore; this mocked validation does not replace a
  live PostgreSQL archive/restore drill.
- PostgreSQL transport/configuration and deployment contract checks:
  **55 passed**, covering remote plaintext rejection, required TLS modes, and
  the exact trusted-host exception used by Compose/CI. The exception rejects
  hostaddr/service overrides and PostgreSQL routing environment overrides.
  Certificate validation with `verify-full` remains a deployment acceptance
  item.
- GitHub integration tests expose latest signed-event PR state through a
  tenant-filtered read API and reject boolean PR numbers or non-boolean merge
  values; the check-run sync endpoint now validates and persists bounded,
  tenant-scoped snapshots. Provider lifecycle reconciliation remains unverified.
- Focused recovery/migration/database tests: **62 passed**.
- Static PostgreSQL declaration tests: **7 passed**; six live PostgreSQL
  integration tests remain skipped without `TALARIA_TEST_POSTGRES_URL`.
- `python -m build --wheel --no-isolation`: passed.
- `pip check`: no broken requirements.
- Ruff Bandit-derived source security rules: **passed** locally and are part
  of CI lint; dedicated SAST/DAST scans remain unavailable.
- Gitleaks history and source/config scans: **ran**, no findings in scanned
  source/config/history; two generic-key findings are confined to ignored
  `.venv` third-party source map in the full-workspace scan. Docker,
  Kubernetes, PostgreSQL runtime, SAST, DAST, dependency vulnerability scan,
  container scan, and SBOM: **not run here**.

## Database evidence and risk

Read-only SQLite checks found `.talaria/talaria.db` at schema v0 with one
repository, three scans, two findings, four audit events, and two foreign-key
violations because both findings reference missing scan ID 0. The file was not
modified. `.talaria/talaria-recovered-v10.db` is v12 with one repository, four
scans, two findings, two occurrences, and five audit events; SQLite quick check
passes and foreign-key check returns no violations. Historical finding-to-scan
provenance in the source cannot be reconstructed from the available records.
The recovered copy predates schema v16 and current readiness reports it as
behind (`Database.readiness` returns `(False, 12)`); the schema-v0 original
returns `(False, 0)`. Upgrade a verified copy before API use or PostgreSQL
import. Neither workspace database was modified.
An isolated temporary copy of the recovered v12 database upgraded to schema v16
and passed `Database.readiness`; SQLite quick check and foreign-key check passed,
and repository, scan, finding, and audit-event counts matched before and after
the upgrade. The temporary copy was removed. The workspace recovered database
remains v12 and was not modified.
The actual schema-v0 source was also recovered to a disposable temporary
destination with `recover_legacy_database`: both orphan findings were
preserved, assigned to one synthetic failed scan documenting missing scan ID
0, and represented by finding-occurrence rows. The recovered result reached
v16, passed readiness and SQLite integrity/foreign-key checks, and the source
records remained unchanged. The disposable result was removed; this verifies
the recovery path without switching the active database.

## Release blockers

1. Run PostgreSQL 17 migration/parity, backup, restore, and concurrency tests
   against disposable infrastructure.
2. Build and run the production image and validate Compose networking, secrets,
   persistence and recovery; validate Kubernetes only if retained as a target.
3. Implement and test the complete GitHub onboarding-to-PR/check/state-sync
   workflow with a disposable repository when authorized.
4. Complete AI investigation persistence, context security, per-tool controls,
   evaluations, and patch-to-approval workflow.
5. Validate Caddy TLS ingress in the target environment; add metrics alerts,
   tamper-evident audit integrity, capacity limits, and incident/recovery
   procedures.
6. Run supply-chain/security scans, a clean install, and all 12 advanced
   scenarios. Obtain independent security review and owner acceptance of legal
   and publication items.

No commit, push, tag, publication, deployment, or database-record mutation was
performed in this work batch.
