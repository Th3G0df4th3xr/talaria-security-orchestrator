# AI Security Threats

## 1. Applicability

This document describes risks for a future AI investigation or agentic workflow. The current MVP's deterministic investigation engine is not an LLM agent. Do not treat planned AI controls as implemented.

## 2. Threat scenarios

### Indirect prompt injection
An attacker places instructions in source comments, README files, issue text, dependency metadata, or test fixtures. The model reads the content as evidence and treats it as instructions.

**Controls:** Label repository content as untrusted, delimit evidence, use fixed system instructions, prohibit instruction following from evidence, and test adversarial repositories.

### Retrieval poisoning
A retrieved document contains misleading or malicious guidance that influences analysis.

**Controls:** Preserve source provenance, rank trusted internal policy separately from repository evidence, show citations/locations, and require human verification.

### Sensitive-data disclosure
The model receives credentials, proprietary code, personal data, or unrelated files.

**Controls:** Minimize evidence, redact secrets, apply data-classification rules, use approved providers and retention settings, and prohibit broad repository uploads by default.

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

Before enabling AI, test direct and indirect prompt injection, data exfiltration attempts, malformed output, evidence fabrication, severity manipulation, unsafe patches, tool-call manipulation, and denial-of-service cases. Record model, prompt, and evaluation versions. AI output must remain advisory.
