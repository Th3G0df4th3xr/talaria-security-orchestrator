# API Architecture

## 1. Purpose and boundary

The FastAPI application exposes a small local API for health checks, repository registration, scans, and finding retrieval. It is an operator interface to the modular-monolith services, not a public multi-user service.

The current API has no authentication or authorization middleware. Run it on loopback only and do not expose it through a public interface, reverse proxy, or shared network.

## 2. Current endpoints

| Method | Path | Purpose | Current behavior |
|---|---|---|---|
| GET | `/health` | Liveness check | Returns service name, status, and version |
| GET | `/repositories` | List repositories | Returns registered repository records |
| POST | `/repositories` | Register repository | Accepts `{"path": "<local path>"}` |
| POST | `/scans` | Run scan | Accepts `{"repository_path": "<local path>"}` and runs the default profile |
| GET | `/findings` | List findings | Returns decoded finding payloads |
| GET | `/findings/{finding_id}` | Read finding | Returns one payload or HTTP 404 |

The CLI supports profile selection; the current API scan request model does not expose a profile field. Do not assume API and CLI capabilities are identical.

## 3. Request validation

Pydantic request models reject extra fields and require non-empty path strings. This is input-shape validation, not authorization. A syntactically valid path can still be outside an approved scan scope.

Repository service validation should establish that the path exists and belongs to a Git working tree. Before any network exposure, add an explicit authorization layer and an allowlisted repository-root policy.

## 4. Service composition

The API creates a Database, RepositoryService, and ScanService through a service factory. The services share the same SQLite database path. The API layer translates known repository and scan validation errors into HTTP 400 responses and missing finding IDs into HTTP 404.

A production design should use FastAPI dependency injection and application lifespan management so database/service resources are initialized once, closed cleanly, and overridden in tests.

## 5. Error contract

Expected client errors should return stable, non-sensitive messages. Do not return stack traces, SQL statements, absolute internal paths, environment variables, or credential material. Unexpected exceptions should be logged with a correlation identifier and mapped to a generic server error.

## 6. Operational controls

- Bind to `127.0.0.1`, not `0.0.0.0`.
- Do not enable permissive CORS.
- Do not expose interactive API documentation on an untrusted network.
- Apply request-size, execution-time, and concurrency limits before shared deployment.
- Add authentication, authorization, CSRF protections where applicable, and audit attribution before multi-user use.
- Treat scan requests as resource-intensive operations; eventually execute them through a bounded job queue.

## 7. Planned API evolution

Future endpoints may include scan status/history, finding lifecycle transitions, approval records, and integration status. Add them only with explicit schemas, authorization checks, audit events, pagination, stable error contracts, and tests. GitHub write or merge actions must never be exposed without policy enforcement and human approval.
