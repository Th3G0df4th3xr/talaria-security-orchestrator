# TALARIA Documentation

TALARIA is a local-first application-security scanning and finding-orchestration MVP. This documentation describes the current implementation, its security boundaries, operational workflows, and the planned evolution toward controlled AI-assisted remediation.

## Documentation map

| Area | Documents |
|---|---|
| Architecture | [System overview](architecture/01-system-overview.md), [Component architecture](architecture/02-component-architecture.md), [Deployment](architecture/03-deployment-architecture.md), [AI agent architecture](architecture/04-ai-agent-architecture.md), [GitHub integration](architecture/05-github-integration.md) |
| API | [API architecture](api/01-api-architecture.md) |
| Data | [Data model](database/01-data-model.md), [Entity relationship model](database/02-entity-relationship-model.md), [Migrations](database/MIGRATIONS.md) |
| Decisions | [ADR-001: Modular monolith](decisions/001-modular-monolith.md) |
| Security | [Security controls](security/01-security-controls.md) |
| Threat modeling | [Overview](threat-model/01-threat-model-overview.md), [STRIDE analysis](threat-model/02-stride-analysis.md), [AI security threats](threat-model/03-ai-security-threats.md), [Risk register](threat-model/04-risk-register.md) |
| Workflows | [Scanning](workflows/01-scanning-workflow.md), [Investigation](workflows/02-investigation-workflow.md), [Remediation](workflows/03-remediation-workflow.md), [Pull requests](workflows/04-pull-request-workflow.md) |
| Readiness and operations | [Implementation tracker](IMPLEMENTATION_TRACKER.md), [85-requirement master plan](PRODUCTION_READINESS_MASTER_PLAN.md), [Readiness report](PRODUCTION_READINESS_REPORT.md), [Advanced test report](PRODUCTION_ACCEPTANCE_TEST_REPORT.md), [Security assessment](SECURITY_ASSESSMENT.md), [Engineering decisions](ENGINEERING_DECISIONS.md), [Release checklist](RELEASE_CHECKLIST.md), [External acceptance](EXTERNAL_ACCEPTANCE_CHECKLIST.md), [Testing](TESTING.md), [Roadmap](ROADMAP.md), [Operations runbook](deployment/OPERATIONS.md) |

## Status language

- **Implemented** means present in the current local MVP and supported by code/tests.
- **Partial** means a basic implementation exists but important controls or operational behavior remain incomplete.
- **Planned** means design intent only; do not represent it as a working feature.
- **Out of scope** means deliberately excluded from the current MVP.

## Current capability boundary

The scanner uses YAML-defined checks. Findings are triage signals, not proof of exploitability. The application includes password/JWT authentication, organization roles, tenant scoping, an opt-in analysis-only LLM adapter, GitHub webhook intake, and approval-gated provider operations. The full GitHub onboarding-to-PR lifecycle, persistent AI investigation history, deployed infrastructure acceptance, production observability, and independent security review remain incomplete. TALARIA is not production-ready; see the readiness tracker and master plan.

Keep the API bound to localhost. Scan only repositories for which the operator has authorization. Never commit secrets, real customer source code, database files, or scan output containing sensitive data.

## Engineering rule

Documentation must describe verified behavior. When implementation changes, update the relevant status, API contract, data model, threat model, and tests together. A planned component must not be described as implemented merely because a package or interface exists.
