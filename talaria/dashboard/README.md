# Dashboard

The dashboard is not implemented in the current MVP. Future views should be
built on read-only service/API contracts for repository inventory, scan
history, finding trends, severity distribution, and remediation status.

Do not query SQLite directly from browser-facing code. Do not expose secrets,
raw credentials, or unrestricted filesystem paths.
