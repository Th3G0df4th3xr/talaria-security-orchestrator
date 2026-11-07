# AI Agent Architecture

## 1. Status

An authenticated, analyst-authorized endpoint and dashboard action can request opt-in analysis for a tenant-owned finding. Repository context is collected only when source sharing is enabled, from configured roots, with traversal/symlink and size limits; model output is schema-checked and evidence references are validated. The service has no tools and cannot authorize actions. Results are returned to the caller and audited without prompts or source text; a persisted investigation history, live provider evaluation, and adversarial testing remain incomplete. Deterministic triage remains the default.

## 2. Design objective

An opt-in provider-neutral AI adapter summarizes findings through an explicit authenticated request; scans do not call it automatically. It has no tools and cannot decide whether an action is permitted.

```text
Finding + bounded evidence
        |
        v
Evidence minimization and redaction
        |
        v
Authenticated endpoint + opt-in AI investigation adapter
        |
        v
Schema validation + policy checks
        |
        v
Untrusted recommendation
        |
        v
Human review
```

## 3. Trust boundaries

Repository content, comments, documentation, commit messages, dependency metadata, and scanner snippets are untrusted. Any of them may contain direct or indirect prompt injection. Model output is also untrusted, including tool names, URLs, code, severity changes, and claims of validation.

## 4. Least-privilege design

The investigation model should receive only the minimum evidence necessary. It should not receive GitHub write credentials, shell access, unrestricted filesystem access, production secrets, or permission to merge code. Prefer a no-tools analysis mode for initial investigation.

If tools are introduced later, expose narrow typed functions with server-side authorization, argument validation, timeouts, output limits, and audit events. The model must not select or expand its own privileges.

## 5. Prompt and evidence construction

- Separate trusted system instructions from untrusted repository evidence.
- Delimit and label all source-derived content as untrusted data.
- Do not interpret instructions embedded in source files as operator instructions.
- Redact credentials, personal data, and unrelated proprietary content.
- Include rule ID, file path, line, limited snippet, and scanner rationale only when necessary.
- Record model/provider, model version, prompt-template version, and evidence references where policy permits.

## 6. Output contract

Require the current strict structured response: `triage`, `rationale`, `confidence`, `evidence_refs`, and `remediation`. The adapter rejects malformed output and evidence references that were not supplied.

Validate types, enumerations, maximum lengths, and references to evidence. Reject malformed output. The model may recommend a severity change, but a deterministic policy or authorized human must approve it.

## 7. Failure behavior

Timeouts, rate limits, provider errors, malformed JSON, unsupported claims, and prompt-injection indicators must fail closed. Preserve the original finding and mark AI analysis unavailable or requiring manual review. Never silently convert an AI failure into a clean result.

## 8. Evaluation

Before enabling an AI adapter, create a benchmark with true positives, false positives, ambiguous cases, prompt-injection examples, secret-bearing fixtures, and adversarial repository instructions. Measure factual grounding, unsupported claims, severity drift, data leakage, repeatability, and cost/latency. Human review remains mandatory for consequential decisions.
