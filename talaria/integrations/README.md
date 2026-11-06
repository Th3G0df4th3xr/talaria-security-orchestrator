# Integrations Package

This package is reserved for external-system adapters. The presence of this directory does not imply that an integration is active.

## Planned adapters

- AI investigation provider: advisory analysis only, with minimized evidence and strict output validation.
- GitHub App: repository metadata and, after separate approval gates, controlled pull-request operations.
- Notification providers: sanitized status notifications without source snippets or secrets.

## Adapter requirements

Every integration must:
- be disabled by default until configured and explicitly enabled;
- use least-privilege credentials stored outside source control;
- validate all inbound and outbound data;
- use bounded timeouts, retries, and response sizes;
- handle rate limits and provider outages safely;
- emit audit events for security-relevant actions;
- expose a clear health/status result;
- fail closed when authorization or policy checks fail.

Do not place provider tokens, private keys, or real customer data in this package or its tests. Use mocks and synthetic fixtures.
