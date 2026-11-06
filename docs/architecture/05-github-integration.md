# GitHub Integration Architecture

## 1. Status

GitHub integration is planned. The current MVP does not create branches, commits, pull requests, reviews, or merges. A placeholder adapter is not a functioning integration.

## 2. Intended workflow

```text
Finding selected by operator
  -> policy eligibility check
  -> remediation proposal
  -> patch generated in isolated workspace (future)
  -> static checks and tests
  -> human approval
  -> GitHub branch and pull request (future)
  -> CI checks
  -> application-owner review
  -> merge by authorized repository process
  -> TALARIA observes merge and verifies remediation
```

## 3. Authentication and permissions

Prefer a GitHub App over a long-lived personal access token. Request only the minimum repository permissions required for each enabled capability. Separate read-only discovery from write operations. Store credentials in a secret manager or OS credential store, never in source control, logs, command history, or scan payloads.

## 4. Repository and PR identity

Persist stable provider identifiers in addition to human-readable owner/repository names. Record installation identity, repository ID, branch, commit SHA, PR number, and provider URL. Do not use a mutable branch name as the sole identity of scanned content.

## 5. Idempotency and retries

Create operations must use idempotency keys or a deterministic correlation key based on finding, repository, base commit, and remediation revision. Handle rate limits and transient failures with bounded exponential backoff. Reconcile provider state before retrying an operation whose outcome is unknown.

## 6. Safety controls

- Never merge automatically in the initial integration.
- Never push a patch without an explicit policy decision and approval.
- Never let model output directly invoke GitHub write APIs.
- Verify repository and branch scope server-side.
- Protect against fork confusion, branch substitution, stale base commits, and permission drift.
- Require CI checks and designated human review.
- Record every attempted and completed write action in an append-only audit trail.

## 7. PR lifecycle

Track at least: proposed, awaiting approval, approved, creation pending, open, checks pending, changes requested, approved by reviewers, merged, closed without merge, failed, and verification pending. State transitions must be validated; provider webhooks must be authenticated and replay-protected.

## 8. Rollback and incident response

A PR can be closed or reverted through the repository's approved process. TALARIA must not rewrite protected branches or attempt destructive rollback automatically. On credential compromise, revoke the installation/token, disable write capabilities, preserve audit evidence, and investigate affected repositories.
