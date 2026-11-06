# Architecture

TALARIA v0.1 is a local-first modular monolith:

1. **Repository layer** validates that a supplied path resolves to a Git worktree and records it.
2. **Hunter profiles** describe enabled checks in YAML.
3. **Scanner** enumerates bounded source files, applies non-executing text patterns, and emits candidate findings.
4. **Finding normalizer** assigns a deterministic fingerprint and severity metadata.
5. **Investigation** adds deterministic triage context; it does not call an LLM.
6. **Remediation advisor** returns human-readable suggestions without editing source files.
7. **SQLite store** persists repositories, scans, findings, and audit records.
8. **CLI/API** expose the workflow.

The future AI investigator and GitHub integration should be explicit adapters with human approval gates. No network integration or autonomous write path is present in this release.
