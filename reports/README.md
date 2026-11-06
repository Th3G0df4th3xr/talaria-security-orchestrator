# Reports Directory

This directory is reserved for generated TALARIA reports and exports.

Do not commit reports containing proprietary source snippets, credentials, personal data, internal repository paths, or customer information. Prefer sanitized synthetic examples for version control.

Generated artifacts should include:
- report generation timestamp (UTC)
- TALARIA version
- repository identifier or sanitized alias
- scanned commit/revision where available
- Hunter Profile name/version
- scan identifier
- finding totals by severity and status
- explicit limitations stating that regex matches are not proof of exploitability

Apply a retention policy and remove temporary exports when no longer required. This directory is intentionally documentation-only until a report generator is implemented.
