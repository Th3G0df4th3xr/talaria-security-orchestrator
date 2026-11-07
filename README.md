# TALARIA

**Early-stage application security orchestration MVP.** TALARIA registers local Git repositories, runs conservative source-pattern checks, normalizes findings, and exposes the workflow through a CLI and FastAPI. Local development defaults to SQLite; the Docker Compose single-host target uses PostgreSQL.

> This is an educational, early-stage MVP—not the original enterprise Project Talaria, not a certified security product, and not a replacement for SAST or a security review. Scanning is limited to local repositories that you are authorized to assess.

## What works in v0.1

- Register a local Git repository and persist its metadata.
- Load YAML Hunter Profiles containing enabled checks.
- Scan common source files for a small set of illustrative patterns.
- Normalize and deduplicate findings with stable SHA-256 fingerprints.
- Persist repositories, scans, findings, and audit events in SQLite locally or PostgreSQL in the Compose deployment.
- Produce JSON scan output and browse results through FastAPI.
- Offer remediation guidance only; no files are changed automatically.

## Explicitly not implemented

An opt-in, no-tools LLM investigation endpoint and GitHub App/webhook/approval foundations are present. PostgreSQL incremental migrations and verified backup/restore commands are implemented, but live PostgreSQL migration/restore drills and deployment acceptance remain. The end-to-end remediation-to-PR workflow, autonomous patching, and auto-merge are not complete. Authentication, organization membership, tenant-scoped APIs, and basic role checks are present, but the platform is not production-hardened. The scanner is intentionally a small demonstration ruleset and will have false positives and false negatives.

## Quick start (macOS/Linux)

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
pytest
ruff check .
```

Register and scan a repository you own or are authorized to test:

```bash
talaria register /absolute/path/to/git/repository
talaria scan /absolute/path/to/git/repository --json-out reports/scan.json
```

Start the API:

```bash
export TALARIA_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
talaria upgrade-db
uvicorn talaria.api:app --reload
```

Create the first administrator from a local terminal (one time):

```bash
talaria bootstrap-admin --email admin@example.com --organization "Example"
```

The API bootstrap endpoint is also available only when `TALARIA_BOOTSTRAP_TOKEN`
is configured and no account exists. It should be disabled after initial setup.
API requests and health checks do not apply schema migrations. The
`talaria upgrade-db` command creates a verified timestamped backup before
upgrading an existing SQLite database, and creates the PostgreSQL v11 baseline and applies v12
only in an empty PostgreSQL schema. To recover a schema-v0 database with
orphaned findings, create a migrated copy with
`talaria recover-legacy-db --source OLD.db --output NEW.db`, then import it
into an empty PostgreSQL database with
`talaria import-sqlite-db --source NEW.db`. Never use the live database as both
source and output. See the [container operations guide](docs/deployment/CONTAINER.md)
for the PostgreSQL deployment and backup limitations.

Open `http://127.0.0.1:8000/docs` for the interactive API documentation.

## API

- `GET /health` and `/health/live` (public liveness), `/health/ready` (read-only dependency/schema readiness)
- `POST /auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/me`
- `POST /auth/register` (organization-admin managed membership)
- `GET /repositories`, `POST /repositories`
- `POST /scans`, `GET /scans`
- `GET /findings` (bounded `limit`/`offset` pagination), `GET /findings/{finding_id}`
- `POST /findings/{finding_id}/investigate` (opt-in AI, analyst roles)
- `PATCH /findings/{finding_id}/status`

Protected API routes require a bearer access token. Tenant-scoped routes use the account's sole organization membership or accept `X-Organization-ID` when the user belongs to several organizations. The API still binds to localhost by default. Do not expose it to an untrusted network until the remaining production hardening work is complete.

API-initiated repository registration and scans are restricted to the current working directory by default. Set `TALARIA_ALLOWED_REPOSITORY_ROOTS` to a path-separator-delimited allowlist when repositories live elsewhere.

## Hunter Profiles

Profiles live in `talaria/hunters/profiles/`. `baseline.yaml` enables the built-in `python-eval` and `possible-hardcoded-secret` checks. Patterns are indicators for manual review, not proof of exploitability or credential validity.

## Data and privacy

The default database is `.talaria/talaria.db` under the current working directory. TALARIA does not transmit source code by default. If an operator enables AI source sharing, bounded source excerpts for requested findings are sent to the configured provider. Scan results may also contain source excerpts; treat the database and exported reports as sensitive. Keep secrets out of test repositories and reports.

## Development

```bash
python -m compileall -q talaria tests
pytest
ruff check .
python -m build
```

See [architecture](docs/ARCHITECTURE.md), [roadmap](docs/ROADMAP.md), [use cases](docs/USE_CASES.md), [security policy](SECURITY.md), and [contributing](CONTRIBUTING.md).
