from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]


def test_container_validates_runtime_configuration_before_database_migration():
    dockerfile = (ROOT / "Dockerfile").read_text()
    command_line = next(
        line for line in dockerfile.splitlines() if line.startswith("CMD ")
    )

    validate_at = command_line.index("validate_runtime_configuration")
    migrate_at = command_line.index("talaria upgrade-db")
    serve_at = command_line.index("uvicorn talaria.api:app")

    assert validate_at < migrate_at < serve_at


def test_compose_is_loopback_only_and_requires_signing_secret():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    service = compose["services"]["talaria-api"]

    assert service["ports"] == ["127.0.0.1:8000:8000"]
    assert service["read_only"] is True
    assert service["environment"]["TALARIA_JWT_SECRET_FILE"] == "/run/secrets/jwt_secret"
    assert "jwt_secret" in service["secrets"]
    assert "no-new-privileges:true" in service["security_opt"]
    assert "${TALARIA_HOST_REPOSITORY_ROOT:-.}:/repositories:ro" in service["volumes"]
    assert service["environment"]["TALARIA_ALLOWED_REPOSITORY_ROOTS"] == "/repositories"


def test_compose_uses_private_persistent_postgres_and_secret_password():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    database = compose["services"]["postgres"]
    api = compose["services"]["talaria-api"]
    dashboard = compose["services"]["talaria-dashboard"]

    assert "ports" not in database
    assert "postgres-data:/var/lib/postgresql/data" in database["volumes"]
    assert database["environment"]["POSTGRES_PASSWORD_FILE"] == (
        "/run/secrets/postgres_password"
    )
    assert api["environment"]["TALARIA_DATABASE_URL"].startswith("postgresql://")
    assert "sslmode=disable" in api["environment"]["TALARIA_DATABASE_URL"]
    assert api["environment"]["TALARIA_DATABASE_TRUSTED_HOSTS"] == "postgres"
    assert api["environment"]["TALARIA_JWT_SECRET_FILE"] == "/run/secrets/jwt_secret"
    assert "TALARIA_JWT_SECRET" not in api["environment"]
    assert "jwt_secret" in api["secrets"]
    assert "GITHUB_WEBHOOK_SECRET" not in api["environment"]
    assert "github_webhook_secret" in api["secrets"]
    assert api["depends_on"]["postgres"]["condition"] == "service_healthy"
    assert compose["networks"]["database"]["internal"] is True
    assert dashboard["ports"] == ["127.0.0.1:8501:8501"]
    assert dashboard["environment"]["TALARIA_API_URL"] == "http://talaria-api:8000"
    assert "postgres_password" not in dashboard.get("secrets", [])


def test_compose_bounds_resources_for_every_production_service():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())

    for name in ("postgres", "talaria-api", "talaria-dashboard"):
        service = compose["services"][name]
        assert service["mem_limit"]
        assert service["cpus"]
        assert service["pids_limit"] > 0

    assert compose["services"]["postgres"]["mem_limit"].startswith(
        "${TALARIA_POSTGRES_MEMORY_LIMIT:-"
    )
    assert compose["services"]["talaria-api"]["mem_limit"].startswith(
        "${TALARIA_API_MEMORY_LIMIT:-"
    )
    assert compose["services"]["talaria-dashboard"]["mem_limit"].startswith(
        "${TALARIA_DASHBOARD_MEMORY_LIMIT:-"
    )


def test_tls_overlay_publishes_caddy_and_trusts_only_its_reserved_proxy_ip():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    overlay = yaml.safe_load((ROOT / "docker-compose.tls.yml").read_text())
    api = compose["services"]["talaria-api"]
    tls_api = overlay["services"]["talaria-api"]
    caddy = overlay["services"]["caddy"]
    caddyfile = (ROOT / "deploy/caddy/Caddyfile").read_text()

    assert compose["networks"]["edge"]["internal"] is True
    assert api["environment"]["FORWARDED_ALLOW_IPS"] == (
        "${TALARIA_FORWARDED_ALLOW_IPS:-127.0.0.1,::1}"
    )
    assert caddy["image"] == "caddy:2.11.9-alpine"
    assert caddy["environment"]["TALARIA_DOMAIN"].startswith("${TALARIA_DOMAIN:?")
    assert caddy["ports"] == ["80:80/tcp", "443:443/tcp", "443:443/udp"]
    assert caddy["networks"]["edge"]["ipv4_address"] == (
        "${TALARIA_CADDY_IP:-172.30.20.2}"
    )
    assert tls_api["environment"]["FORWARDED_ALLOW_IPS"] == (
        "${TALARIA_CADDY_IP:-172.30.20.2}"
    )
    assert "NET_BIND_SERVICE" in caddy["cap_add"]
    assert caddy["cap_drop"] == ["ALL"]
    assert "/auth/*" in caddyfile and "/integrations/*" in caddyfile
    assert "reverse_proxy talaria-api:8000" in caddyfile
    assert "reverse_proxy talaria-dashboard:8501" in caddyfile
    assert "/metrics" not in caddyfile


def test_caddy_routes_every_published_api_path_to_the_api_service():
    import re

    from talaria.api import app

    caddyfile = (ROOT / "deploy/caddy/Caddyfile").read_text()
    api_matcher = re.search(r"@api\s*\{\s*path\s+([^}]+)\}", caddyfile, re.DOTALL)
    assert api_matcher is not None
    api_patterns = api_matcher.group(1).split()

    def is_routed_to_api(path):
        return any(
            path == pattern
            or (pattern.endswith("/*") and path.startswith(pattern[:-1]))
            for pattern in api_patterns
        )

    published_paths = set(app.openapi()["paths"])
    assert published_paths
    assert all(is_routed_to_api(path) for path in published_paths)
    assert not is_routed_to_api("/metrics")
    assert "reverse_proxy talaria-api:8000" in caddyfile


def test_kubernetes_manifest_is_internal_and_runs_restricted():
    with (ROOT / "deploy/kubernetes/api.yaml").open() as manifest_file:
        documents = list(yaml.safe_load_all(manifest_file))
    stateful_set = next(item for item in documents if item["kind"] == "StatefulSet")
    service = next(item for item in documents if item["kind"] == "Service")
    container = stateful_set["spec"]["template"]["spec"]["containers"][0]

    assert service["spec"]["type"] == "ClusterIP"
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["readinessProbe"]["httpGet"]["path"] == "/health/ready"


def test_kubernetes_github_key_is_optional_and_does_not_require_a_secret_file():
    with (ROOT / "deploy/kubernetes/api.yaml").open() as manifest_file:
        documents = list(yaml.safe_load_all(manifest_file))
    stateful_set = next(item for item in documents if item["kind"] == "StatefulSet")
    container = stateful_set["spec"]["template"]["spec"]["containers"][0]
    key_env = next(
        item for item in container["env"] if item["name"] == "GITHUB_APP_PRIVATE_KEY"
    )
    secret_key = key_env["valueFrom"]["secretKeyRef"]

    assert secret_key == {
        "name": "talaria-secrets",
        "key": "github-app-private-key",
        "optional": True,
    }
    assert not any(
        item["name"] == "GITHUB_APP_PRIVATE_KEY_PATH" for item in container["env"]
    )
    volumes = stateful_set["spec"]["template"]["spec"]["volumes"]
    assert not any(item["name"] == "github-key" for item in volumes)


def test_operations_runbook_runs_verified_postgres_backup_upgrade_before_start():
    runbook = (ROOT / "docs/deployment/OPERATIONS.md").read_text()
    build = runbook.index("docker compose build talaria-api")
    upgrade = runbook.index("talaria upgrade-db", build)
    backup_argument = runbook.index("--backup-output", upgrade)
    start = runbook.index("docker compose up -d", backup_argument)

    assert build < upgrade < backup_argument < start
    assert "/backups/pre-upgrade-$(date -u" in runbook


def test_ci_runs_postgres_integration_against_disposable_database():
    with (ROOT / ".github/workflows/ci.yml").open() as workflow_file:
        workflow = yaml.safe_load(workflow_file)
    test_job = workflow["jobs"]["test"]
    assert "sslmode=disable" in test_job["env"]["TALARIA_TEST_POSTGRES_URL"]
    assert test_job["env"]["TALARIA_DATABASE_TRUSTED_HOSTS"] == "localhost"

    assert test_job["services"]["postgres"]["image"] == "postgres:17-alpine"
    assert test_job["services"]["postgres"]["env"]["POSTGRES_DB"].startswith(
        "talaria_test_"
    )
    assert "/talaria_test_ci?sslmode=disable" in test_job["env"][
        "TALARIA_TEST_POSTGRES_URL"
    ]


def test_ci_scans_each_deployed_container_image():
    with (ROOT / "docker-compose.yml").open() as compose_file:
        compose = yaml.safe_load(compose_file)
    with (ROOT / "docker-compose.tls.yml").open() as overlay_file:
        overlay = yaml.safe_load(overlay_file)
    with (ROOT / ".github/workflows/ci.yml").open() as workflow_file:
        workflow = yaml.safe_load(workflow_file)

    production_images = {
        "talaria:ci",
        compose["services"]["postgres"]["image"],
        overlay["services"]["caddy"]["image"],
    }
    job = workflow["jobs"]["container"]
    scanned_images = {
        step["with"]["image-ref"]
        for step in job["steps"]
        if step.get("uses", "").startswith("aquasecurity/trivy-action@")
    }

    assert scanned_images == production_images
    pulls = "\n".join(
        step.get("run", "") for step in job["steps"] if "run" in step
    )
    assert compose["services"]["postgres"]["image"] in pulls
    assert overlay["services"]["caddy"]["image"] in pulls


def test_ci_external_actions_are_full_sha_pinned_and_dependabot_tracks_updates():
    import re

    with (ROOT / ".github/workflows/ci.yml").open() as workflow_file:
        workflow = yaml.safe_load(workflow_file)
    action_refs = [
        step["uses"]
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
        if "uses" in step
    ]
    assert action_refs
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", ref) for ref in action_refs)

    with (ROOT / ".github/dependabot.yml").open() as dependabot_file:
        dependabot = yaml.safe_load(dependabot_file)
    ecosystems = {update["package-ecosystem"] for update in dependabot["updates"]}
    assert ecosystems == {"github-actions", "docker", "pip"}


def test_master_readiness_plan_covers_each_tracker_requirement():
    import re

    tracker = (ROOT / "docs/IMPLEMENTATION_TRACKER.md").read_text()
    plan = (ROOT / "docs/PRODUCTION_READINESS_MASTER_PLAN.md").read_text()
    tracker_ids = set(re.findall(r"^\| ([A-D]\d{2}) \|", tracker, re.MULTILINE))
    plan_ids = set(re.findall(r"^\| ([A-D]\d{2}) \|", plan, re.MULTILINE))

    assert len(tracker_ids) == 79
    assert plan_ids == tracker_ids
    assert "| Functional completeness |" in plan
    assert "| Independent verification |" in plan


def test_master_plan_and_acceptance_report_cover_directive_ids():
    import re

    plan = (ROOT / "docs/PRODUCTION_READINESS_MASTER_PLAN.md").read_text()
    report = (ROOT / "docs/PRODUCTION_ACCEPTANCE_TEST_REPORT.md").read_text()
    roadmap_ids = set(
        re.findall(
            r"^\| ((?:DB|AUTH|GH|AI|API|UI|INFRA|OBS|SEC|ACCEPT|RELEASE)-\d{2}) \|",
            plan,
            re.MULTILINE,
        )
    )
    acceptance_ids = set(re.findall(r"TALARIA-ADV-\d{3}", report))

    assert len(roadmap_ids) == 85
    assert acceptance_ids == {f"TALARIA-ADV-{index:03d}" for index in range(1, 13)}
