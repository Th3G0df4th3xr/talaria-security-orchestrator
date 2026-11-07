# Architecture

TALARIA v0.1 is a local-first modular monolith:

1. **Repository layer** validates that a supplied path resolves to a Git worktree and records it.
2. **Hunter profiles** describe enabled checks in YAML.
3. **Scanner** enumerates bounded source files, applies non-executing text patterns, and emits candidate findings.
4. **Finding normalizer** assigns a deterministic fingerprint and severity metadata.
5. **Investigation** adds deterministic triage context; it does not call an LLM.
6. **Remediation advisor** returns human-readable suggestions without editing source files.
7. **Database layer** persists repositories, scans, findings, tenants, approvals, sessions, and audit records. Local development uses SQLite; the Docker Compose target uses PostgreSQL.
8. **CLI/API** expose the workflow.

Optional LLM analysis is connected to a tenant-scoped finding endpoint and dashboard action; source is shared only when explicitly enabled. GitHub App API methods and signed webhook intake are present but are not connected into a complete scan-to-verified-PR workflow. GitHub branch and pull-request writes require a persisted, tenant-scoped second-person approval; generated patches are validated in a temporary copy and never applied to the user's repository.
