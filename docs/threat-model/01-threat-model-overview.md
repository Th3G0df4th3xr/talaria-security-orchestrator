# Threat Model Overview

## 1. Scope

This threat model covers the local-first TALARIA MVP and its planned evolution into an AI-assisted application-security orchestration platform. It focuses on repository ingestion, scanning, finding storage, API/CLI access, AI analysis, and future GitHub actions.

## 2. Security objectives

1. Scan only authorized repositories.
2. Preserve source-code confidentiality.
3. Maintain integrity and traceability of scans and findings.
4. Prevent untrusted repository content from controlling TALARIA.
5. Keep AI recommendations separate from authorization decisions.
6. Require human approval for source-code changes and external write actions.
7. Avoid unauthorized merge or deployment.

## 3. Assets

- Source code and repository metadata.
- Finding details, snippets, and remediation notes.
- SQLite database and backups; PostgreSQL database, password secret, and dumps in the selected Compose topology.
- Hunter profiles and scan configuration.
- API/CLI access and local filesystem permissions.
- Future AI prompts, model responses, and provider credentials.
- Future GitHub App credentials, PR metadata, and approval records.
- Audit records and reports.

## 4. Trust boundaries

| Boundary | From -> To | Main risk |
|---|---|---|
| TB-1 | Operator -> CLI/API | Unauthorized or malformed requests |
| TB-2 | TALARIA -> filesystem/repository | Path traversal, symlink escape, excessive resource use |
| TB-3 | Repository content -> scanner | Malicious or malformed input, regex/resource exhaustion |
| TB-4 | TALARIA -> SQLite/PostgreSQL | Corruption, injection, broken references, unsafe schema initialization |
| TB-5 | Repository evidence -> AI model (future) | Direct/indirect prompt injection and data leakage |
| TB-6 | TALARIA -> GitHub (future) | Credential misuse and unauthorized writes |
| TB-7 | TALARIA -> notification provider (future) | Sensitive-data disclosure |

## 5. Assumptions

- The operator has legitimate authorization for each repository.
- The workstation and operating system are not already compromised.
- Source files and repository metadata are untrusted.
- Pattern matches may be false positives.
- AI output, when introduced, is untrusted.
- External provider APIs may fail or return unexpected data.

## 6. Out of scope

The current MVP does not attempt to prove exploitability, execute payloads, exploit vulnerabilities, perform dynamic testing, or autonomously change or merge source code. Production multi-tenant operation is also out of scope until identity, authorization, isolation, and operational controls exist.

## 7. Method

Use STRIDE to identify threat classes, map threats to assets and boundaries, estimate likelihood/impact, define mitigations, and track residual risk. Revisit the model whenever a new integration, permission, data flow, or autonomous capability is introduced.
