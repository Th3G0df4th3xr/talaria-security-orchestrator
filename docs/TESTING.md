# Testing and verification

Run commands from the repository root with the project virtual environment.
The checked-in CI workflow additionally provisions PostgreSQL 17; this local
workspace has no PostgreSQL server, Docker, or Kubernetes runtime.

## Local deterministic checks

```bash
.venv/bin/ruff check .
.venv/bin/pytest -ra
git diff --check
.venv/bin/python -m build --wheel --no-isolation
.venv/bin/pip check
```

The migration and legacy-recovery batch can be rerun with:

```bash
.venv/bin/pytest -q tests/test_migrations.py tests/test_database_recovery.py
```

The PostgreSQL tests are intentionally skipped unless a disposable database URL
is provided. The database name must begin with `talaria_test_`; the fixture
truncates all TALARIA tables in that database:

```bash
TALARIA_TEST_POSTGRES_URL='postgresql://USER:PASSWORD@HOST:5432/talaria_test_local' \
  .venv/bin/pytest -q tests/test_postgres_integration.py
```

Never point this variable at a production, shared, or valuable database.

## Existing focused test groups

```bash
.venv/bin/pytest -q tests/auth tests/test_api.py
.venv/bin/pytest -q tests/integrations
.venv/bin/pytest -q tests/test_patch_validation.py tests/test_investigation_context.py
.venv/bin/pytest -q tests/test_config.py tests/test_secret_files.py tests/test_security_middleware.py
.venv/bin/pytest -q tests/test_deployment_files.py
```

These groups are component regressions, not substitutes for complete
end-to-end or external acceptance. See
[PRODUCTION_ACCEPTANCE_TEST_REPORT.md](PRODUCTION_ACCEPTANCE_TEST_REPORT.md)
for the 12 advanced scenarios and their current status.

## Test markers

Pytest markers are registered in `pyproject.toml` for unit, integration,
security, adversarial, concurrency, PostgreSQL, Docker, Kubernetes, external,
acceptance, and database work. Markers are only applied to tests that actually
exercise the category; a registered marker does not make an unmarked test part
of that category. Use `pytest --markers` to inspect active marker declarations.
