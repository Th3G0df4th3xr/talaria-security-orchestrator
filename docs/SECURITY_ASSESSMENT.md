# TALARIA security assessment snapshot

**Assessment type:** implementation review and local regression evidence.
**Independent assessment:** not performed. This document is not a penetration
test, certification, or claim that TALARIA cannot be compromised.
**Evidence date:** 2026-11-07.

## Controls observed

- Argon2id password hashing, signed short-lived JWTs, hashed refresh tokens,
  token rotation/reuse detection, session revocation, and role checks have
  unit/API coverage. Successful logins upgrade outdated Argon2 parameters with
  a conditional transactional write and an audit event.
- Organization-scoped repository, scan, finding, approval, and dashboard paths
  have regression coverage, but exhaustive authorization review remains open.
- GitHub webhook HMAC validation, bounded intake, delivery deduplication, and
  conflict detection have mocked tests.
- AI investigation is opt-in and role-gated; source sharing is opt-in. Bounded
  context excludes sensitive path classes, opens files through no-follow
  directory descriptors, and redacts common credential patterns before
  provider submission. Redaction is heuristic and cannot guarantee all secrets
  are removed. Patch proposals now redact source/finding context separately from
  the base-commit comparison and reject recognizable credential material in
  generated patch output. Investigation requests provide no tool definitions,
  and the provider adapter rejects tool/function-call responses. Persistent
  history, model-level retrieval-poisoning evaluation, and future per-tool
  security policy remain incomplete.
- Secret-file reads reject symlinks, non-regular files, and overly broad modes.
  HTTP responses include security headers and bounded request bodies. Sensitive
  routes use hashed, database-backed GCRA quotas shared across workers; the local
  in-memory limiter is an additional guard. Requests fail closed with 503 if the
  shared rate-limit store is unavailable. The dashboard API client rejects 3xx
  responses and disables redirects for requests and refresh-token rotation.
- Application lifespan validates the JWT secret and configured optional
  integrations before serving requests; GitHub and AI configuration checks do
  not make network calls. Empty LLM key files are allowed only while AI is
  disabled. PostgreSQL connections now require TLS by default; plaintext is
  permitted only for exact operator-listed trusted hostnames with explicit
  conninfo host settings and no hostaddr, service-file, or PGHOST routing
  overrides. Prefer `sslmode=verify-full` with a managed CA because
  `sslmode=require` encrypts transport without verifying the server identity.
  The Compose Postgres exception is limited to its internal-only bridge
  network; live TLS/CA acceptance and broader typed settings validation remain
  open.
- SQLite readiness and the current recovered copy pass integrity and foreign
  key checks. The original schema-v0 database intentionally retains its two
  known invalid finding-to-scan references and was not modified.

## Outstanding security risks

- The GitHub integration is not a complete persisted onboarding-to-PR workflow;
  provider write authorization needs end-to-end acceptance.
- Schema v14 adds an ID-ordered SHA-256 audit chain, readiness verification,
  SQLite append-only triggers, and centralized runtime writes. It detects
  row-level changes while the chain remains intact, but cannot detect an
  administrator rewriting and recomputing the complete chain. Independent
  immutable checkpoints and live PostgreSQL validation remain outstanding.
- Full multi-tenant review, abuse testing, and independent security review are
  still required.
- An optional Caddy Compose overlay provides automatic HTTPS for the VM topology
  and configures Uvicorn to trust forwarded client addresses only from Caddy's
  reserved edge-network IP. DNS, firewall, live certificate renewal, and
  Kubernetes ingress remain unverified.
- A bearer-token-protected metrics endpoint exposes bounded process-local HTTP
  request/latency and scan outcome metrics. Alerting, centralized logging,
  formal capacity testing, and a disaster-recovery drill remain outstanding.
- Shared throttles cover login, refresh/logout, bootstrap, member and organization
  creation, approval operations, logout-all, scans, AI investigations, and GitHub
  webhooks. PostgreSQL runtime concurrency and clock-skew behavior still need
  acceptance; rate limiting does not replace edge-level abuse controls.
- Gitleaks scanned the current Git history (one commit) and found no leaks. It
  also scanned TALARIA source, tests, docs, deployment files, secret examples,
  and root configuration with no findings. A full workspace scan found two
  generic-key matches in an ignored `.venv` third-party source map; the file is
  not tracked and is excluded by `.gitignore`.
- Ruff's Bandit-derived security rules are enabled for application source and
  run in CI; `.venv/bin/ruff check --select S talaria` passes locally. This is
  a basic static security lint, not a dedicated SAST review. Dependency and
  container scans are configured in CI but were not run locally; DAST and SBOM
  evidence and an independent security assessment are unavailable.
- PostgreSQL tests are skipped locally without a disposable server. Docker and
  Kubernetes runtime acceptance are unavailable.

## Required before release

1. Re-run the secret-history scan after the owner reviews/commits release files;
   execute the configured dependency/container scans, add dedicated SAST and
   DAST review, and triage findings.
2. Complete role/action and tenant authorization review, including negative
   tests for every protected route and persisted resource.
3. Add independently controlled immutable checkpoints for the audit chain and validate PostgreSQL append behavior.
4. Run the PostgreSQL, container, TLS ingress, backup/restore, concurrency, and
   failure-recovery acceptance in disposable infrastructure.
5. Obtain an independent security review and resolve or formally accept every
   critical/high finding.
