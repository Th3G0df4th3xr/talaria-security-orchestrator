TALARIA — Component Architecture

1. Purpose
This document describes the internal components of TALARIA, their responsibilities, interfaces, dependencies, and interactions.


The current implementation follows a modular monolith architecture. Components are logically separated into Python packages but execute within the same application process.

2. Component Inventory

Component	Package / Module	Responsibility	Status
REST API	talaria/api.py	Exposes HTTP endpoints	Implemented
CLI	talaria/cli.py	Command-line interaction	Implemented
Configuration	talaria/config.py	Runtime configuration and database path	Implemented
Repository Service	talaria/repositories/	Validates and registers Git repositories	Implemented
Hunter Profile Manager	talaria/hunters/	Loads YAML scanning profiles	Implemented
Scanning Service	talaria/scanning/	Traverses source files and executes checks	Implemented
Finding Normalizer	talaria/findings/	Generates finding fingerprints	Implemented
Investigation Engine	talaria/investigation/	Performs deterministic initial triage	Implemented
Remediation Advisor	talaria/remediation/	Provides rule-based remediation guidance	Implemented
Database Layer	talaria/database.py	SQLite persistence and audit events	Implemented
Data Models	talaria/models.py	API request models	Implemented
AI Investigation Adapter	Planned	LLM-assisted investigation	Planned
Policy Engine	Planned	Enforces action authorization	Planned
GitHub Integration	Planned	Repository and pull request integration	Planned
Approval Service	Planned	Records human approval decisions	Planned
Verification Engine	Planned	Validates remediation through rescanning	Planned

3. Component Responsibilities

3.1 API Layer

Responsibilities:

* Accept repository registration requests.
* Initiate security scans.
* Return repository and finding information.
* Validate request payloads.
* Translate service errors into HTTP responses.

Current endpoints:

* GET /health
* GET /repositories
* POST /repositories
* POST /scans
* GET /findings
* GET /findings/{finding_id}

The API currently has no authentication or authorization layer. It must remain restricted to localhost until appropriate access controls are implemented.

3.2 Repository Service

Responsibilities:

* Resolve supplied filesystem paths.
* Validate directory existence.
* Verify Git repository membership.
* Identify the Git working-tree root.
* Register repositories.
* Prevent duplicate registration of the same resolved path.

Security requirements:

* Accept only repositories the operator is authorized to scan.
* Never trust an arbitrary user-supplied path.
* Restrict filesystem access to explicitly authorized locations.
* Consider symlink and path traversal behavior.
* Avoid exposing sensitive filesystem details through API errors.

3.3 Hunter Profile Manager

Responsibilities:

* Load YAML-based scanning profiles.
* Define security checks.
* Specify applicable file extensions.
* Define rule identifiers, descriptions, severity, and patterns.
* Support enabling or disabling individual checks.

Future requirements:

* Validate profile schemas.
* Reject unsafe or invalid regular expressions.
* Version profiles.
* Record the profile version used for each scan.
* Restrict profile modification to authorized operators.

3.4 Scanning Service

Responsibilities:

1. Register or resolve the target repository.
2. Create a scan record.
3. Load the selected Hunter Profile.
4. Traverse eligible repository files.
5. Apply configured detection rules.
6. Normalize matches into finding records.
7. Invoke investigation and remediation components.
8. Persist scan results.
9. Record audit events.
10. Return a scan summary.

Current detection is regex-based and should be considered an initial pattern-matching capability, not a complete SAST engine.

Future enhancements:

* File-size and repository-size limits.
* Execution timeouts.
* Symlink protections.
* Language-specific parsers.
* AST analysis.
* Data-flow analysis.
* Secret scanning integrations.
* Scan cancellation and failure recovery.

3.5 Finding Normalizer

Responsibilities:

* Convert raw detection matches into a consistent finding representation.
* Generate deterministic fingerprints.
* Support duplicate detection.
* Preserve relevant source location and rule metadata.

Important design distinction:

A Finding represents the canonical security issue.

A FindingOccurrence represents that issue being observed during a particular scan.

These must become separate persistence concepts so repeated scans preserve historical observations without creating duplicate canonical findings.

The current MVP has fingerprint-based deduplication but does not yet implement a complete occurrence-history model.

3.6 Investigation Engine

Current responsibilities:

* Evaluate a normalized finding.
* Assign an initial triage classification.
* Record confidence.
* Explain that pattern matching alone does not prove exploitability.

Current output includes:

* Triage status.
* Investigation rationale.
* Confidence.

Future AI-assisted investigation must not replace deterministic authorization controls.

3.7 Remediation Advisor

Current responsibilities:

* Map detection rule identifiers to remediation recommendations.
* Provide actionable developer guidance.
* Avoid automatically changing repository source files.

Future capabilities:

* Context-aware remediation plans.
* Patch proposals.
* Secure coding references.
* Patch validation.
* Regression test generation.

3.8 Persistence Layer

Current technology: SQLite.

Current entities:

* Repositories
* Scans
* Findings
* Audit Events

Responsibilities:

* Store repository metadata.
* Persist scan records.
* Persist canonical findings.
* Record audit events.
* Provide structured database access.

Future data-model extensions include:

* Applications
* Teams
* Repository ownership
* Finding occurrences
* Investigations
* Remediations
* Approvals
* Patches
* Pull requests
* Verification records
* Policies

Database writes should be transactional where multiple related records must remain consistent.

3.9 Audit Service

The current database layer provides an audit-event insertion method.

Future audit requirements:

* Actor identity.
* Event type.
* Timestamp.
* Target resource.
* Previous and resulting state where appropriate.
* Correlation identifier.
* Approval references.
* Integration activity.
* Tamper-resistant retention.

Audit records should not contain secrets, access tokens, or unnecessary source-code content.

4. Component Interaction Flow

             SECURITY ENGINEER
                    |
                    v
               CLI / REST API
                    |
                    v
             REPOSITORY SERVICE
                    |
                    v
             HUNTER PROFILE MANAGER
                    |
                    v
              SCANNING SERVICE
                    |
                    v
             FINDING NORMALIZER
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

This represents the logical processing flow. It does not imply that every component is an independently deployed service.

5. Dependency Rules

The following dependency rules should be maintained:

1. API handlers invoke application services rather than implementing scanning logic.
2. Repository services own repository validation and registration.
3. Scanning services coordinate scanning but do not own HTTP behavior.
4. Hunter profiles define detection configuration rather than persistence behavior.
5. Finding normalization must remain deterministic.
6. Investigation components must not bypass authorization.
7. Remediation advice must not modify source code.
8. Database access must be centralized through the persistence layer.
9. Integration adapters must not expose unrestricted credentials to AI components.
10. Audit events must be recorded for security-relevant state transitions.

6. Trust Boundaries

Boundary	Source	Destination	Primary Risk
TB-01	User	API	Unauthorized requests
TB-02	API	Repository Service	Arbitrary filesystem access
TB-03	Repository	Scanner	Malicious source content
TB-04	Scanner	Hunter Rules	Unsafe patterns and resource exhaustion
TB-05	Finding	Investigation Engine	Manipulated finding context
TB-06	TALARIA	AI Provider	Prompt injection and source disclosure
TB-07	TALARIA	GitHub	Credential misuse and unauthorized writes
TB-08	Application	Database	Integrity and confidentiality failures

7. Future Component Extension Strategy

The following components may be introduced as independent modules when their complexity justifies it:

* Background job orchestration.
* AI investigation adapter.
* Policy decision engine.
* GitHub App integration.
* Approval workflow.
* Pull request orchestrator.
* Patch validation engine.
* Notification service.
* Remediation verification engine.

The modular monolith remains the preferred architecture until scaling, isolation, or operational requirements justify service separation.

8. Architectural Constraints

* No unrestricted autonomous source-code modification.
* No automatic pull request merging.
* No unrestricted AI access to GitHub credentials.
* No implicit trust in repository content.
* No assumption that a regex match proves a vulnerability.
* No production multi-tenancy without tenant isolation and authorization.
* No external integration without explicit credential and permission controls.
