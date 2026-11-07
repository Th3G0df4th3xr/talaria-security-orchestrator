# Local secrets

Place local development credentials in this directory. The files are ignored
by Git. Never commit real private keys, webhook secrets, or JWT signing keys.
For Docker Compose, set `GITHUB_APP_PRIVATE_KEY_FILE` to a local PEM file,
`GITHUB_WEBHOOK_SECRET_FILE` to the GitHub webhook signing secret,
`TALARIA_POSTGRES_PASSWORD_FILE` to a PostgreSQL password file, and
`TALARIA_LLM_API_KEY_FILE` to a provider key file when AI is explicitly enabled.
Set the PostgreSQL, JWT, GitHub, and LLM secret files' owner to the API
container UID and restrict non-empty files to mode `0400` (or stricter). TALARIA
rejects non-empty secret files that are group/world-readable. Empty example
files are placeholders and do not enable optional integrations.
