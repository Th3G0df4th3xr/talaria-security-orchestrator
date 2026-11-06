# AI Agent Architecture

## 1. Status

AI-assisted investigation is a future extension. The current MVP performs deterministic, rule-based triage. The presence of an adapter interface or placeholder package does not mean an LLM integration is operational.

## 2. Design objective

An AI component may help explain a finding, identify missing context, compare remediation approaches, and draft a recommendation. It must not become the authority that decides whether an action is permitted.

```text
Finding + bounded evidence
        |
        v
Evidence minimization and redaction
        |
        v
AI investigation adapter (future)
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

Require a strict structured response, for example:
- `summary`
- `likely_root_cause`
- `supporting_evidence`
- `counter_evidence`
- `confidence`
- `recommended_next_steps`
- `suggested_remediation`
- `limitations`

Validate types, enumerations, maximum lengths, and references to evidence. Reject malformed output. The model may recommend a severity change, but a deterministic policy or authorized human must approve it.

## 7. Failure behavior

Timeouts, rate limits, provider errors, malformed JSON, unsupported claims, and prompt-injection indicators must fail closed. Preserve the original finding and mark AI analysis unavailable or requiring manual review. Never silently convert an AI failure into a clean result.

## 8. Evaluation

Before enabling an AI adapter, create a benchmark with true positives, false positives, ambiguous cases, prompt-injection examples, secret-bearing fixtures, and adversarial repository instructions. Measure factual grounding, unsupported claims, severity drift, data leakage, repeatability, and cost/latency. Human review remains mandatory for consequential decisions.
