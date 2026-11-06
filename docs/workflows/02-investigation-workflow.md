# Investigation Workflow

## 1. Purpose

Convert a scanner match into a reviewable, evidence-based triage record without overstating certainty.

## 2. Current deterministic process

1. Receive normalized finding metadata.
2. Identify the rule and source location.
3. Retain only a bounded source snippet.
4. Apply deterministic triage logic.
5. Record classification, confidence, rationale, and limitations.
6. Preserve the finding for manual review.

The current investigation engine does not call an LLM, execute code, perform dynamic testing, or establish exploitability.

## 3. Analyst review

The reviewer should:
- Open the relevant source context in the authorized repository.
- Verify whether the matched API/function is actually reachable.
- Identify input control and trust boundaries.
- Check validation, encoding, authentication, authorization, and data flow as relevant.
- Determine whether the pattern is a true positive, false positive, or needs more evidence.
- Record the evidence supporting the decision.

## 4. Recommended triage states

Suggested lifecycle vocabulary:
- `new`
- `triaging`
- `confirmed`
- `false_positive`
- `accepted_risk`
- `remediation_planned`
- `in_progress`
- `resolved`
- `reopened`

These are target lifecycle states unless persistence and transition enforcement are verified in the current build.

## 5. Evidence quality

Separate observed facts from analyst inference. Record rule ID, repository revision, file path, line, scan ID, and evidence summary. Avoid copying secrets or large code blocks into findings. Confidence must describe evidence strength, not model fluency.

## 6. Future AI-assisted investigation

If AI is enabled, provide minimized, redacted evidence and require structured, evidence-linked output. Treat the output as a recommendation. A human must approve status/severity changes and any consequential next step. On provider failure or malformed output, retain the original finding and require manual review.
