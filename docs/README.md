# TALARIA Documentation

TALARIA is a local-first application-security scanning and finding-orchestration MVP. This documentation describes the current implementation, its security boundaries, operational workflows, and the planned evolution toward controlled AI-assisted remediation.

## Documentation map

| Area | Documents |
|---|---|
| Architecture | [System overview](architecture/01-system-overview.md), [Component architecture](architecture/02-component-architecture.md), [Deployment](architecture/03-deployment-architecture.md), [AI agent architecture](architecture/04-ai-agent-architecture.md), [GitHub integration](architecture/05-github-integration.md) |
| API | [API architecture](api/01-api-architecture.md) |
| Data | [Data model](database/01-data-model.md), [Entity relationship model](database/02-entity-relationship-model.md) |
| Decisions | [ADR-001: Modular monolith](decisions/001-modular-monolith.md) |
| Security | [Security controls](security/01-security-controls.md) |
| Threat modeling | [Overview](threat-model/01-threat-model-overview.md), [STRIDE analysis](threat-model/02-stride-analysis.md), [AI security threats](threat-model/03-ai-security-threats.md), [Risk register](threat-model/04-risk-register.md) |
| Workflows | [Scanning](workflows/01-scanning-workflow.md), [Investigation](workflows/02-investigation-workflow.md), [Remediation](workflows/03-remediation-workflow.md), [Pull requests](workflows/04-pull-request-workflow.md) |

## Status language

- **Implemented** means present in the current local MVP and supported by code/tests.
- **Partial** means a basic implementation exists but important controls or operational behavior remain incomplete.
- **Planned** means design intent only; do not represent it as a working feature.
- **Out of scope** means deliberately excluded from the current MVP.

## Current capability boundary

The current scanner uses YAML-defined regular-expression checks. Findings are triage signals, not proof of exploitability. The current application does not provide production authentication/RBAC, multi-tenant isolation, AI-powered investigation, patch generation, GitHub write operations, approval orchestration, or automatic merging.

Keep the API bound to localhost. Scan only repositories for which the operator has authorization. Never commit secrets, real customer source code, database files, or scan output containing sensitive data.

## Engineering rule

Documentation must describe verified behavior. When implementation changes, update the relevant status, API contract, data model, threat model, and tests together. A planned component must not be described as implemented merely because a package or interface exists.
