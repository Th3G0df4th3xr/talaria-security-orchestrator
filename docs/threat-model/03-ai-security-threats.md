# AI Security Threats

## 1. Applicability

This document describes risks for the opt-in finding investigation endpoint and any future agentic workflow. The endpoint is advisory only, uses an authenticated tenant-scoped finding, and has no repository tools. Do not treat remaining evaluation and data-governance work as implemented.

## 2. Threat scenarios

### Indirect prompt injection
An attacker places instructions in source comments, README files, issue text, dependency metadata, or test fixtures. The model reads the content as evidence and treats it as instructions.

**Controls:** When source sharing is explicitly enabled, collect a bounded source excerpt from configured roots, label repository content as untrusted, use fixed system instructions, prohibit instruction following from evidence, validate output and evidence references, and test adversarial repositories.

### Retrieval poisoning
A retrieved document contains misleading or malicious guidance that influences analysis.

**Controls:** Preserve source provenance, rank trusted internal policy separately from repository evidence, show citations/locations, and require human verification.

### Sensitive-data disclosure
The model receives credentials, proprietary code, personal data, or unrelated files.

**Controls:** Minimize evidence, heuristically redact recognizable credentials from source context and model rationale/remediation, apply data-classification rules, use approved providers and retention settings, and prohibit broad repository uploads by default. Redaction is not guaranteed and must not replace source-sharing review.

### Tool misuse
An agent is induced to run shell commands, access files, or perform GitHub writes.

**Controls:** Start with no tools. If tools are later added, expose narrow server-side functions, enforce authorization outside the model, use short-lived credentials, and audit each call.

### Hallucinated remediation
The model invents APIs, misidentifies root cause, or recommends an unsafe change.

**Controls:** Require evidence-linked output, compile/test proposed patches in isolation, compare against policy, and require human review.

### Excessive agency
A model chains investigation, patching, PR creation, and merge without meaningful checkpoints.

**Controls:** Separate permissions by stage, require explicit approval for each consequential transition, and do not provide merge authority to the model.

### Model/provider compromise
A provider outage, model change, or compromised endpoint changes behavior or exposes data.

**Controls:** Pin/configure approved models, version prompts, validate outputs, monitor drift, and provide a deterministic manual fallback.

## 3. Agent permission model

| Capability | Initial AI permission |
|---|---|
| Read minimized finding evidence | Allowed when policy permits |
| Explain likely root cause | Allowed as recommendation |
| Suggest remediation | Allowed as recommendation |
| Change finding severity/status | Not autonomously |
| Read arbitrary repository files | Denied by default |
| Execute shell or tests | Denied |
| Write source files | Denied |
| Create GitHub PR | Denied until separately approved integration |
| Merge PR | Denied |

## 4. Evaluation gate

Before enabling AI in a deployment, test direct and indirect prompt injection, data exfiltration attempts, malformed output, evidence fabrication, severity manipulation, unsafe patches, tool-call manipulation, and denial-of-service cases. Record model, prompt, and evaluation versions. AI output must remain advisory.
