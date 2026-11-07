# Roadmap

See [IMPLEMENTATION_TRACKER.md](IMPLEMENTATION_TRACKER.md) for the detailed
requirements and current evidence. TALARIA is not production-ready until the
open acceptance items in that tracker are closed.

## Next milestones

1. Validate PostgreSQL migrations, import, backup and restore against an
   ephemeral PostgreSQL service in CI and on the selected Docker VM; perform a
   restore drill and add encrypted off-host retention.
2. Complete organization-bound GitHub onboarding and connect scans,
   investigations, approvals, branch/PR publication, checks, and webhook
   updates into one persisted workflow. Keep provider writes disabled until
   mocked acceptance passes and a disposable repository is explicitly selected.
3. Add persisted AI investigation history, retention, grounding/security
   evaluations, and failure testing. Keep source sharing disabled unless the
   operator enables it after provider data review.
4. Close operational gaps for TLS ingress, shared rate limiting, metrics,
   centralized redacted logs, dependency/container scan execution, and
   incident/backup runbooks.
5. Run end-to-end failure and recovery acceptance on the selected Docker VM
   topology and obtain an independent security review.
