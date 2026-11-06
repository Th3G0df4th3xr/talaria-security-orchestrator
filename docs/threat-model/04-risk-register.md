# TALARIA Risk Register

Likelihood and impact are qualitative: Low, Medium, High. Ratings describe the current MVP unless explicitly marked future.

| ID | Risk | Likelihood | Impact | Priority | Treatment / acceptance criteria |
|---|---|---:|---:|---:|---|
| R-01 | API has no authentication/RBAC | Medium | High | Critical | Keep loopback-only; implement authz before shared exposure |
| R-02 | Repository path can exceed intended scan scope | Medium | High | High | Allowlisted roots, canonical paths, symlink escape tests |
| R-03 | Scanner resource exhaustion | Medium | High | High | Bound file count, bytes, time, regex cost, concurrency |
| R-04 | Finding-to-scan foreign-key inconsistency | Medium | High | High | Foreign keys per connection, atomic writes, migration and integrity tests |
| R-05 | Duplicate finding model loses occurrence history | High | Medium | High | Introduce FindingOccurrence and backfill only evidence-supported data |
| R-06 | Sensitive snippets/secrets persisted or exported | Medium | High | High | Redaction, minimized evidence, permissions, retention |
| R-07 | Basic audit log can be altered with local DB access | Medium | Medium | Medium | Add actor/correlation metadata and protected export/centralization for production |
| R-08 | Malicious regex/profile causes excessive CPU | Medium | High | High | Schema validation, regex policy/timeouts, trusted profile distribution |
| R-09 | AI prompt injection (future) | High | High | Critical | No-tools default, untrusted-data boundaries, evaluation, human approval |
| R-10 | AI leaks source or secrets (future) | Medium | High | High | Data minimization, redaction, approved provider, retention controls |
| R-11 | GitHub credential misuse (future) | Medium | High | High | GitHub App least privilege, short-lived credentials, secret manager |
| R-12 | Autonomous merge/unsafe patch (future) | Medium | Critical | Critical | No autonomous merge; policy gate and human approval |
| R-13 | Incomplete failure recovery leaves scan pending | Medium | Medium | Medium | Explicit failed status, exception-safe transaction and audit |
| R-14 | Dependency compromise | Low/Medium | High | High | Pin/review dependencies, vulnerability and secret scanning |

## Risk ownership

The project maintainer owns risk acceptance. A risk may be marked mitigated only when the control is implemented and verified by test or operational evidence. A design document or TODO is not mitigation evidence.

## Review triggers

Review this register when authentication, network exposure, new scanner rules, AI providers, GitHub write permissions, notifications, multi-user access, or deployment topology changes. Reassess likelihood and impact after each major release.
