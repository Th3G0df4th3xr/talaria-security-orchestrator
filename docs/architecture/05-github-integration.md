# GitHub Integration Architecture

## 1. Status

The repository contains a GitHub App client, short-lived installation-token exchange, platform-admin repository onboarding bound to a selected tenant and local repository, signed webhooks scoped to registered provider repository and installation IDs, tenant-scoped approval records, and branch/PR adapter methods. The adapter requires a validator backed by an approved record before a write. There is not yet an end-to-end workflow that maps a TALARIA remediation patch to a branch and PR, persists provider action state, or synchronizes checks/reviews/merges. Live GitHub acceptance requires a configured GitHub App and disposable repository.

## 2. Intended workflow

```text
Finding selected by operator
  -> policy eligibility check
  -> remediation proposal
  -> patch proposed and validated in a temporary copy (adapter exists; workflow integration pending)
  -> static checks and tests
  -> human approval
  -> GitHub branch and pull request (approval-gated adapter methods exist; workflow integration pending)
  -> CI checks
  -> application-owner review
  -> merge by authorized repository process
  -> TALARIA observes merge and verifies remediation
```

## 3. Authentication and permissions

Prefer a GitHub App over a long-lived personal access token. Request only the minimum repository permissions required for each enabled capability. Separate read-only discovery from write operations. Configure `GITHUB_APP_ID`, `GITHUB_INSTALLATION_ID`, and `GITHUB_APP_PRIVATE_KEY_PATH`; configure `GITHUB_WEBHOOK_SECRET` for webhook delivery. Store credentials in a secret manager or OS credential store, never in source control, logs, command history, or scan payloads.

## 4. Repository and PR identity

Persist stable provider identifiers in addition to human-readable owner/repository names. Record installation identity, repository ID, branch, commit SHA, PR number, and provider URL. Do not use a mutable branch name as the sole identity of scanned content.

The authenticated `POST /integrations/github/repositories` endpoint accepts a
local `repository_id`, GitHub `owner`, and GitHub `repository`. A platform
administrator must supply the selected `X-Organization-ID`; TALARIA confirms
the local repository belongs to that tenant and queries GitHub through the
configured `GITHUB_INSTALLATION_ID` before persisting the provider ID and
default branch. Provider repository IDs are globally unique in TALARIA, so the
same remote repository cannot be claimed by a second tenant. The current
configuration supports one GitHub App installation ID per deployment; managed
multi-installation configuration is still required for broader SaaS use.

Webhook payloads are discarded after signature verification and allowlisted
summary extraction. TALARIA persists an event only when the provider repository
ID is enabled and the signed event's installation ID matches its onboarding
record; unknown or mismatched events are acknowledged and ignored.

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
