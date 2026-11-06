# ADR-001: Adopt a Modular Monolith

- **Status:** Accepted for the current MVP
- **Date:** 2026-11-06
- **Decision owners:** TALARIA project maintainers

## Context

TALARIA needs clear separation between API, repository management, scanning, finding normalization, investigation, remediation guidance, persistence, and future integrations. The current project is a single-developer/local-first MVP. Operating microservices would add deployment, networking, observability, and data-consistency costs before there is a demonstrated need.

## Decision

Use a Python modular monolith. Keep domain responsibilities in separate packages with explicit service boundaries, but deploy and execute them within one process for the MVP.

## Package boundaries

- `talaria.api`: HTTP transport and request/response mapping.
- `talaria.cli`: command-line interface.
- `talaria.repositories`: local repository validation and registration.
- `talaria.hunters`: profile loading and rule configuration.
- `talaria.scanning`: scan orchestration and file traversal.
- `talaria.findings`: finding normalization and lifecycle concepts.
- `talaria.investigation`: deterministic triage and future AI adapter boundary.
- `talaria.remediation`: remediation advice and future controlled patch workflow.
- `talaria.database`: persistence boundary.
- `talaria.audit`: audit event services and query operations (where implemented).
- `talaria.integrations`: external provider adapters (future).
- `talaria.notifications`: notification interfaces (future).
- `talaria.dashboard`: operator UI (future).

A package name or interface alone is not evidence that its feature is implemented.

## Consequences

Positive:
- Simple local development and debugging.
- Lower operational overhead.
- Shared transaction boundary for core MVP workflows.
- Easier end-to-end testing.

Trade-offs:
- Components share process resources and failure domain.
- Interfaces must be kept clean to avoid package coupling.
- Long-running scans can block request handling unless moved to bounded background workers.
- Scaling individual components independently is not available.

## Revisit when

Reconsider a worker/service split when measured scan volume, concurrency, isolation, availability, or team ownership requirements justify it. Do not split services solely for architectural fashion.

## Guardrails

Keep business rules out of HTTP route handlers. Avoid circular imports. Use typed service contracts. Centralize database access. Make external integrations optional and fail closed. Preserve human approval for consequential actions.
