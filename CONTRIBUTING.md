# Contributing

1. Open an issue describing the change and its security impact.
2. Keep scanning local and authorized; do not add exploit execution or automatic source modification.
3. Add tests for new rules, API behavior, and persistence changes.
4. Run `ruff check .`, `python -m compileall -q talaria tests`, and `pytest`.
5. Document false-positive considerations and any new data collected.

Please do not submit real credentials, customer data, or proprietary source code.
