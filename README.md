# TALARIA

**Local-first application security orchestration MVP.** TALARIA registers local Git repositories, runs conservative source-pattern checks, normalizes findings, records scans and audit events in SQLite, and exposes the workflow through a CLI and FastAPI.

> This is an educational, early-stage MVP—not the original enterprise Project Talaria, not a certified security product, and not a replacement for SAST or a security review. Scanning is limited to local repositories that you are authorized to assess.

## What works in v0.1

- Register a local Git repository and persist its metadata.
- Load YAML Hunter Profiles containing enabled checks.
- Scan common source files for a small set of illustrative patterns.
- Normalize and deduplicate findings with stable SHA-256 fingerprints.
- Persist repositories, scans, findings, and audit events in SQLite.
- Produce JSON scan output and browse results through FastAPI.
- Offer remediation guidance only; no files are changed automatically.

## Explicitly not implemented

No Devin/LLM agent, hosted model, GitHub API/PR creation, autonomous remediation, auto-merge, CI enforcement, or enterprise RBAC. Those are future integration points, not functioning features in this release. The scanner is intentionally a small demonstration ruleset and will have false positives and false negatives.

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
uvicorn talaria.api:app --reload
```

Open `http://127.0.0.1:8000/docs` for the interactive API documentation.

## API

- `GET /health`
- `GET /repositories`
- `POST /repositories` with `{"path":"/absolute/path/to/repo"}`
- `POST /scans` with `{"repository_path":"/absolute/path/to/repo"}`
- `GET /findings`
- `GET /findings/{finding_id}`

The API binds to localhost when run with the command above. Do not expose it to an untrusted network without adding authentication, authorization, TLS, and deployment hardening.

## Hunter Profiles

Profiles live in `talaria/hunters/profiles/`. `baseline.yaml` enables the built-in `python-eval` and `possible-hardcoded-secret` checks. Patterns are indicators for manual review, not proof of exploitability or credential validity.

## Data and privacy

The default database is `.talaria/talaria.db` under the current working directory. TALARIA does not upload source code. Scan results may include source excerpts; treat the database and exported reports as sensitive. Keep secrets out of test repositories and reports.

## Development

```bash
python -m compileall -q talaria tests
pytest
ruff check .
python -m build
```

See [architecture](docs/ARCHITECTURE.md), [roadmap](docs/ROADMAP.md), [use cases](docs/USE_CASES.md), [security policy](SECURITY.md), and [contributing](CONTRIBUTING.md).
