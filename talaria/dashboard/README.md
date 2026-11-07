# Dashboard

`app.py` provides a Streamlit dashboard for sign-in, organization selection,
repository inventory, scans, finding lifecycle, severity distribution, and
trends. It calls the FastAPI service through `client.py`; it does not access
SQLite or PostgreSQL directly. The dashboard is a presentation client, not an
independent authorization boundary.

Run the API and install the dashboard extra before starting Streamlit. Set
`TALARIA_API_URL` to the API origin when it is not available at loopback. The
client requires HTTPS for remote origins; plain HTTP is accepted only for
loopback development and the exact `talaria-api:8000` Docker Compose service.
Run behind the same trusted TLS boundary as the API before remote use. Do not
expose Streamlit directly to an untrusted network.

The client keeps access and refresh tokens in Streamlit server-side session
state and sends them only to the configured TALARIA API. API error messages
omit response bodies to avoid rendering internal paths or diagnostics. Session
refresh, idle expiration, and production browser-session review remain open
hardening work.
