# External acceptance checklist

External acceptance is intentionally separate from local and mocked tests. The
current workspace has no Docker, PostgreSQL server utilities, Kubernetes
cluster, GitHub App credentials/disposable repository, or AI provider
credentials. None of the procedures below has been executed here.

| Acceptance | Required environment | Evidence to retain | Current status |
|---|---|---|---|
| PostgreSQL migrations and parity | Disposable PostgreSQL 17 service; set `TALARIA_TEST_POSTGRES_URL` to a database named `talaria_test_*`. | Test output, schema/index comparison, migration checksums, FK and constraint checks. | Blocked locally; CI workflow is configured but no run is claimed. |
| PostgreSQL backup and restore | Disposable source and empty target databases; PostgreSQL client tools. | Backup verification, restore output, readiness, row counts, FK check. | Not run. |
| Docker/Compose | Docker Engine and Compose plugin; synthetic data and owner-only secret files. | Image build, container identity, health, network exposure, restart and failure behavior. | Blocked; Docker is unavailable locally. |
| Kubernetes | Disposable cluster and validated secrets/storage/ingress. | Server-side manifest validation, rollout, health, network policy, persistence and recovery. | Blocked; no cluster/client. |
| TLS ingress | Supported reverse proxy or ingress, test hostname/certificate, remote reachability controlled by operator. | TLS protocol/certificate checks, proxy trust behavior, headers, webhook reachability. | Not implemented/validated in this workspace. |
| GitHub App lifecycle | Least-privilege test App and disposable repository/organization. | Installation/token lifecycle, repository binding, webhook, branch/PR/check/state sync. | Not run; current instruction limits work to local/mocked checks. |
| AI provider | Disposable provider project/key, synthetic repository content, approved data handling. | Timeout/error/output-bound tests, prompt-injection suite, data-sharing and cost behavior. | Not run; current instruction limits work to local/mocked checks. |
| Security scans/review | CI or isolated scan environment plus independent reviewer. | Dependency, secret-history, SAST/DAST, container and SBOM outputs; signed review report. | Local Gitleaks history/source scans ran; CI scan, dependency/SAST/DAST/container scans and independent review remain unverified. |

Do not paste credentials into chat or commit them. Configure secrets locally and
use synthetic data only. A skipped test remains blocked and must not be counted
as passed.
