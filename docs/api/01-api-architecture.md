# API Architecture

## 1. Purpose and boundary

The FastAPI application exposes a small local API for health checks, repository registration, scans, and finding retrieval. It is an operator interface to the modular-monolith services, not a public multi-user service.

Protected API routes require a bearer JWT, load the active principal from the configured database, resolve the active organization membership, and enforce role checks. `/health`, login, refresh, and the secret-gated one-time bootstrap are public. Run on loopback until deployment hardening is complete.

## 2. Current endpoints

| Method | Path | Purpose | Current behavior |
|---|---|---|---|
| GET | `/health` | Liveness check | Returns service name, status, and version |
| GET | `/repositories` | List repositories | Returns registered repository records |
| POST | `/repositories` | Register repository | Accepts `{"path": "<local path>"}` |
| POST | `/scans` | Run scan | Accepts `{"repository_path": "<local path>"}` and runs the default profile |
| GET | `/findings` | List findings | Returns decoded tenant-scoped payloads; default page is 100 and maximum is 500 |
| GET | `/findings/{finding_id}` | Read finding | Returns one tenant-owned payload and a bounded occurrence page, or HTTP 404 |
| POST | `/findings/{finding_id}/investigate` | Request opt-in AI triage | Analyst roles only; source context is sent only when explicitly enabled |
| POST | `/integrations/github/repositories` | Onboard a GitHub repository | Platform administrator selects a tenant; validates the local repository and verifies provider identity using the configured App installation |
| GET | `/integrations/github/repositories` | List onboarded GitHub repositories | Returns only mappings for the selected tenant |
| POST | `/integrations/github/webhook` | Receive GitHub events | Persists signed events only for registered repository and installation mappings |

The CLI supports profile selection; the current API scan request model does not expose a profile field. Do not assume API and CLI capabilities are identical.

## 3. Request validation

Pydantic request models reject extra fields and require non-empty path strings. This is input-shape validation, not authorization. A syntactically valid path can still be outside an approved scan scope.

Repository service validation establishes that the path exists and belongs to a Git working tree. API registration, scans, findings, and AI investigation require authentication, organization scoping, and role checks. Repository roots are allowlisted; before network exposure, complete the independent authorization review and deployment controls.

## 4. Service composition

The API creates non-initializing Database handles through a service factory. Services share the configured database URL or SQLite path. Schema initialization is an explicit operator action; readiness opens the existing database without creating it or applying migrations. SQLite readiness checks integrity, foreign keys, audit-chain validity, and migration checksums. PostgreSQL readiness checks the v11 baseline, v12–v16 migration checksums, required tables, and audit-chain validity. AI investigation records and results are persisted in the selected tenant and history reads are role-gated and organization-scoped. Application lifespan startup and a periodic task recover stale investigations. Sensitive and resource-intensive routes use an atomic shared GCRA quota in the configured database; limiter storage failures return 503. The API layer translates known repository and scan validation errors into HTTP 400 responses and missing finding IDs into HTTP 404.

Database handles are created per request and closed after each operation. Application lifespan manages the periodic stale-investigation recovery task and cancels it during clean shutdown.

## 5. Error contract

Expected client errors should return stable, non-sensitive messages. Do not return stack traces, SQL statements, absolute internal paths, environment variables, or credential material. Unexpected exceptions should be logged with a correlation identifier and mapped to a generic server error.

## 6. Operational controls

- Bind to `127.0.0.1`, not `0.0.0.0`.
- Do not enable permissive CORS.
- Do not expose interactive API documentation on an untrusted network.
- The ASGI edge rejects HTTP bodies larger than 1,000,000 bytes before JSON parsing, including chunked requests; webhook-specific limits can be smaller. Scan budgets exist; execution-time/concurrency controls, distributed job execution, and coordinated rate limits remain open.
- Preserve authentication, authorization, and audit attribution on every new multi-user endpoint; add CSRF protection if browser credentials move to cookies.
- Treat scan requests as resource-intensive operations; eventually execute them through a bounded job queue.

## 7. Planned API evolution

Future endpoints may include richer investigation history and integration status. Add them only with explicit schemas, authorization checks, audit events, pagination, stable error contracts, and tests. GitHub write or merge actions must never be exposed without policy enforcement and human approval.
