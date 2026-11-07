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
| Persistence | SQLite locally; PostgreSQL v11 baseline plus checksummed v12–v16 migrations for Docker Compose | SQLite verified; PostgreSQL live acceptance and incremental migration work remain |
| REST API | FastAPI | Implemented |
| CLI | Python | Implemented |
| Audit events | Configured database | Implemented for SQLite; PostgreSQL path awaits live acceptance |
| Authentication and RBAC | Partial | JWT, Argon2id, organization memberships, role checks, and tenant-scoped core endpoints implemented; production hardening remains |
| Application ownership | Organizations and memberships | Core tenant ownership and role checks implemented; full role/action review remains |
| AI investigation | Opt-in provider adapter | Analysis adapter and bounded context collection implemented; authorization wiring and evaluation remain |
| Patch generation | Temporary-copy validator | Base-commit-bound proposal generation and syntax validation implemented; test/policy workflow remains |
| GitHub integration | GitHub App and webhook adapters | App auth, read/write methods, signature checks, and delivery deduplication implemented; live setup and workflow sync remain |
| Pull request orchestration | Approval-gated adapter methods | Branch/PR methods require persisted approval; end-to-end orchestration remains |
| Remediation verification | Re-scanning | Not implemented |

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

This is the target end-to-end architecture. Some adapters and approval controls exist, but orchestration, provider synchronization, and verification services remain to be implemented.

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

It does not yet provide production-grade identity/RBAC, distributed scanning, full semantic SAST, persisted AI investigation history, automated patch publication, completed GitHub PR workflows, or enterprise notification workflows.

The regex-based scanner identifies patterns requiring investigation. It does not establish exploitability or prove a vulnerability.

The API must remain restricted to localhost until deployment hardening and the remaining authorization review are complete.
