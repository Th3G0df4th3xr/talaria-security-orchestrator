# Remediation Workflow

## 1. Purpose

Guide an authorized engineer from a confirmed finding to a tested, reviewable fix. TALARIA currently provides rule-based remediation advice only; it does not generate or apply source-code patches.

## 2. Current workflow

```text
Finding detected
  -> analyst validates finding
  -> analyst confirms severity and scope
  -> remediation advisor returns guidance
  -> engineer designs fix outside TALARIA
  -> engineer implements and tests change
  -> reviewer verifies fix
  -> subsequent TALARIA scan checks whether signal remains
```

## 3. Remediation record

A future remediation record should capture finding ID, proposed change, rationale, affected files, author, base commit, test plan, validation results, approval state, and references to resulting commits/PRs.

## 4. Safety requirements for future patch generation

- Generate changes in an isolated worktree or disposable copy.
- Never modify the operator's working tree without explicit approval.
- Bind the patch to a known base commit.
- Restrict changed paths to the intended repository.
- Reject path traversal, symlink escape, binary surprises, and unexpected file changes.
- Run bounded tests and static checks in a sandbox without production credentials.
- Show a complete diff to the human reviewer.
- Require explicit approval before publishing any change.

## 5. Validation

A remediation is not complete merely because a patch applies or a test passes. Validate the original security condition, regression behavior, relevant tests, and unintended side effects. Re-scan the relevant revision and preserve the verification result.

## 6. Closure

Close a finding only when the evidence supports resolution or an authorized risk-acceptance decision is recorded. If the issue reappears, reopen it and link the new occurrence to the canonical finding.
