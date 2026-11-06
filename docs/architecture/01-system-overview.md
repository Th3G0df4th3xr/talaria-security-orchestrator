# TALARIA — System Architecture Overview

## 1. Purpose

TALARIA is a local-first application security orchestration platform designed to coordinate the application security lifecycle, from repository onboarding and security scanning to investigation and verified remediation.

## 2. Architectural Principles

- Security by design.
- Least-privilege access.
- Modular monolith architecture.
- Deterministic security controls.
- Human approval for consequential actions.
- Complete auditability.
- Reproducible security scans.
- Source-code confidentiality.
- Separation of detection and validation.
- Fail-secure integration behavior.

## 3. Current Implementation

| Capability | Technology | Status |
|---|---|---|
| Repository onboarding | GitPython | Implemented |
| Hunter profiles | YAML | Implemented |
| Security scanning | Regex | Implemented |
| Finding normalization | Fingerprinting | Implemented |
| Investigation | Deterministic engine | Implemented |
| Remediation advice | Rule-based suggestions | Implemented |
| Persistence | SQLite | Implemented |
| REST API | FastAPI | Implemented |
| CLI | Python | Implemented |
| Audit events | SQLite | Implemented |
| Authentication and RBAC | Planned | Not implemented |
| Application ownership | Planned | Not implemented |
| AI investigation | LLM integration | Planned |
| Patch generation | Controlled workflow | Planned |
| GitHub integration | GitHub App | Planned |
| Pull request orchestration | Approval workflow | Planned |
| Remediation verification | Re-scanning | Planned |

## 4. High-Level Architecture

    SECURITY ENGINEERING TEAM
              |
              v
         CLI / REST API
              |
              v
           API LAYER
              |
              v
      REPOSITORY MANAGEMENT
              |
              v
         SCANNING SERVICE
              |
              v
          HUNTER ENGINE
              |
              v
      FINDING NORMALIZATION
              |
              v
      INVESTIGATION ENGINE
              |
              v
       REMEDIATION ADVISOR
              |
              v
        PERSISTENCE LAYER
              |
              v
         SQLITE DATABASE
              |
              v
          AUDIT EVENTS

## 5. Future Architecture Extensions

    TALARIA
       |
       +---- AI Investigation Adapter
       |
       +---- GitHub App Integration
       |
       +---- Policy Engine
       |
       +---- PR Orchestrator
       |
       +---- Human Approval
       |
       +---- Patch Validation
       |
       +---- Verification Engine
       |
       +---- Notification Engine

These are planned components, not currently implemented services.

## 6. Trust Boundaries

| ID | Boundary | Security Concern |
|---|---|---|
| TB-01 | User to API | Authentication and authorization |
| TB-02 | TALARIA to repository | Filesystem access |
| TB-03 | Scanner to source files | Untrusted source content |
| TB-04 | TALARIA to AI provider | Prompt injection and data exposure |
| TB-05 | TALARIA to GitHub | Credentials and write permissions |
| TB-06 | Application to database | Data integrity and confidentiality |
| TB-07 | TALARIA to notification provider | Information disclosure |

## 7. Security Assumptions

- Only authorized repositories may be onboarded.
- Repository source code is untrusted input.
- Detection results are not automatically confirmed vulnerabilities.
- AI-generated content is untrusted.
- AI agents cannot override application authorization.
- Source-code modifications require explicit authorization.
- Pull request merging remains under application-team control.
- Credentials must never be committed to source control.

## 8. Current Limitations

TALARIA is currently a local-first MVP.

It does not yet provide production authentication, role-based access control, multi-tenant isolation, distributed scanning, full semantic SAST, AI-powered investigation, automated patch generation, GitHub integration, or enterprise notification workflows.

The regex-based scanner identifies patterns requiring investigation. It does not establish exploitability or prove a vulnerability.

The API must remain restricted to localhost until authentication and access controls are implemented.
