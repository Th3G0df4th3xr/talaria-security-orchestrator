# Pull Request Workflow

## 1. Status

The GitHub adapter has approval-gated branch and idempotent pull-request methods, but TALARIA does not yet orchestrate the full scan-to-verified-PR workflow. This document defines that target workflow; live provider acceptance and state synchronization remain outstanding.

## 2. Target sequence

1. A human selects a confirmed finding for remediation.
2. Policy checks repository, branch, finding status, and permissions.
3. A remediation proposal is generated or supplied by an engineer.
4. The change is applied in an isolated worktree.
5. Diff and tests are validated.
6. A human explicitly approves publication.
7. A least-privilege GitHub App creates a branch and PR.
8. CI and repository protection rules run.
9. Application owners review and approve.
10. An authorized repository actor merges through normal controls.
11. TALARIA observes the merged commit and schedules verification.

## 3. Approval model

Approval must be explicit, attributable, scoped, and time-bound. Approval of a remediation proposal is not automatically approval to merge. A change to the base commit, patch contents, target repository, or requested permissions invalidates the prior approval and requires review again.

## 4. PR metadata

Record repository provider ID, installation ID, base and head commit SHAs, branch, PR number, URL, finding IDs, patch digest, test results, approval identity, and timestamps. Do not store credentials in PR descriptions or audit payloads.

## 5. Webhooks and synchronization

Verify webhook signatures, reject replayed deliveries, process events idempotently, and reconcile with provider state after missed events. Treat PR titles, descriptions, comments, branch names, and CI output as untrusted content.

## 6. Failure handling

Handle rate limits, network timeouts, ambiguous create outcomes, revoked permissions, closed PRs, and stale base branches. Do not blindly retry non-idempotent writes. Never merge automatically in the initial integration.

## 7. Verification and closure

After merge, identify the exact merged commit and run a new scan against that revision. Close the finding only when verification evidence supports resolution. Preserve links between finding, remediation, PR, merge commit, and verification scan.
