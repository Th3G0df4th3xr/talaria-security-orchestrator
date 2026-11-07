# Release checklist

This checklist is a gate, not an assertion that a release is ready. Do not
publish, tag, deploy, or change remote settings without explicit owner
authorization.

## Code and evidence

- [ ] Review all tracked modifications and every untracked file.
- [ ] Reconcile all 79 A–D tracker rows and all 85 master-directive IDs.
- [ ] Run full pytest, Ruff, `git diff --check`, package build, and dependency
      checks from a clean environment.
- [ ] Run the 12 advanced acceptance scenarios; distinguish component tests
      from completed scenarios and retain exact results.
- [ ] Run disposable PostgreSQL migration, parity, concurrency, backup, and
      restore acceptance.
- [ ] Build and run the Docker image; validate Kubernetes only if it is a
      supported target.
- [ ] Run secret-history, dependency, SAST, DAST, container, and SBOM checks.
- [ ] Obtain independent security review and document disposition of critical
      and high findings.

## Data and deployment

- [ ] Confirm no workspace or production database records changed unexpectedly.
- [ ] Verify encrypted off-host backups and a restore to a new target.
- [ ] Validate TLS, secret ownership/rotation, monitoring, alert delivery,
      resource limits, and incident procedures in the selected topology.
- [ ] Verify a clean install from only files intended for distribution.

## Owner publication handoff

- [ ] Review `git status --short --untracked-files=all` and every diff.
- [ ] Confirm license ownership and third-party notices.
- [ ] Confirm the repository history contains no secrets or private data.
- [ ] Select and approve a version only after all release gates pass.
- [ ] Owner performs any commit, tag, push, repository visibility change, or
      publication after review.
