"""Small-process request throttling and safe response headers."""

import hashlib
import json
import logging
import re
from collections import OrderedDict, defaultdict, deque
from threading import Lock
from time import monotonic, perf_counter
from uuid import uuid4

from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from talaria.config import database_path
from talaria.database import Database

MAX_REQUEST_BODY_BYTES = 1_000_000
METRIC_METHODS = frozenset({"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"})
METRIC_ROUTES = frozenset(
    {
        "/health", "/health/live", "/health/ready", "/metrics",
        "/repositories", "/scans", "/dashboard/summary", "/dashboard/severity",
        "/dashboard/trends", "/findings", "/investigations",
        "/auth/login", "/auth/refresh", "/auth/logout", "/auth/logout-all",
        "/auth/bootstrap", "/auth/register", "/auth/organizations", "/auth/me",
        "/auth/approvals", "/integrations/github/repositories",
        "/integrations/github/webhook",
    }
)
DURATION_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)

logger = logging.getLogger("talaria.http")


def _metric_route(path: str) -> str:
    """Map requests to a fixed route set so labels cannot expose IDs or grow unbounded."""
    if path in METRIC_ROUTES:
        return path
    parts = path.strip("/").split("/")
    if (
        len(parts) == 7
        and parts[:3] == ["integrations", "github", "repositories"]
        and parts[3].isdigit()
        and parts[4] == "commits"
        and re.fullmatch(r"[0-9a-fA-F]{40}", parts[5])
        and parts[6] == "check-runs"
    ):
        return "/integrations/github/repositories/{repository_id}/commits/{sha}/check-runs"
    if len(parts) == 2 and parts[0] == "findings" and parts[1].isdigit():
        return "/findings/{finding_id}"
    if (
        len(parts) == 3
        and parts[0] == "findings"
        and parts[1].isdigit()
        and parts[2] in {"investigate", "status"}
    ):
        return f"/findings/{{finding_id}}/{parts[2]}"
    if (
        len(parts) == 4
        and parts[:2] == ["auth", "approvals"]
        and parts[3] == "decision"
    ):
        return "/auth/approvals/{approval_id}/decision"
    return "other"


def _rate_limit_route(path: str) -> str:
    """Use stable route templates so caller-controlled IDs cannot split quotas."""
    parts = path.strip("/").split("/")
    if (
        len(parts) == 7
        and parts[:3] == ["integrations", "github", "repositories"]
        and parts[3].isdigit()
        and parts[4] == "commits"
        and re.fullmatch(r"[0-9a-fA-F]{40}", parts[5])
        and parts[6] == "check-runs"
    ):
        return "/integrations/github/repositories/{repository_id}/commits/{sha}/check-runs"
    if (
        len(parts) == 3
        and parts[0] == "findings"
        and parts[1].isdigit()
        and parts[2] == "investigate"
    ):
        return "/findings/{finding_id}/investigate"
    if (
        len(parts) == 4
        and parts[:2] == ["auth", "approvals"]
        and parts[2]
        and parts[3] == "decision"
    ):
        return "/auth/approvals/{approval_id}/decision"
    return path


class RequestMetrics:
    """Bounded, process-local HTTP and scan metrics with no tenant or client labels."""

    def __init__(self):
        self._lock = Lock()
        self._requests: defaultdict[tuple[str, str, str], int] = defaultdict(int)
        self._durations: defaultdict[tuple[str, str], list[float | int]] = defaultdict(
            lambda: [0.0, 0, *([0] * len(DURATION_BUCKETS))]
        )
        self._scans: defaultdict[str, int] = defaultdict(int)

    def observe_request(self, method: str, path: str, status: int, duration_seconds: float):
        method_label = method.upper() if method.upper() in METRIC_METHODS else "OTHER"
        route_label = _metric_route(path)
        status_label = f"{status // 100}xx" if 100 <= status <= 599 else "other"
        duration = max(0.0, duration_seconds)
        with self._lock:
            self._requests[(method_label, route_label, status_label)] += 1
            aggregate = self._durations[(method_label, route_label)]
            aggregate[0] += duration
            aggregate[1] += 1
            for index, boundary in enumerate(DURATION_BUCKETS):
                if duration <= boundary:
                    aggregate[index + 2] += 1

    def record_scan(self, status: str):
        if status not in {"completed", "failed", "rejected"}:
            status = "other"
        with self._lock:
            self._scans[status] += 1

    def render(self) -> str:
        with self._lock:
            requests = dict(self._requests)
            durations = {key: list(value) for key, value in self._durations.items()}
            scans = dict(self._scans)
        lines = [
            "# HELP talaria_http_requests_total HTTP requests by bounded method, route, "
            "and status class.",
            "# TYPE talaria_http_requests_total counter",
        ]
        for (method, route, status), count in sorted(requests.items()):
            lines.append(
                "talaria_http_requests_total{"
                f'method="{method}",route="{route}",status_class="{status}"'
                f"}} {count}"
            )
        lines.extend(
            [
                "# HELP talaria_http_request_duration_seconds HTTP request duration histogram.",
                "# TYPE talaria_http_request_duration_seconds histogram",
            ]
        )
        for (method, route), aggregate in sorted(durations.items()):
            cumulative = 0
            for index, boundary in enumerate(DURATION_BUCKETS):
                cumulative += int(aggregate[index + 2])
                lines.append(
                    "talaria_http_request_duration_seconds_bucket{"
                    f'method="{method}",route="{route}",le="{boundary:g}"'
                    f"}} {cumulative}"
                )
            lines.append(
                "talaria_http_request_duration_seconds_bucket{"
                f'method="{method}",route="{route}",le="+Inf"'
                f"}} {aggregate[1]}"
            )
            lines.append(
                "talaria_http_request_duration_seconds_sum{"
                f'method="{method}",route="{route}"'
                f"}} {aggregate[0]:.6f}"
            )
            lines.append(
                "talaria_http_request_duration_seconds_count{"
                f'method="{method}",route="{route}"'
                f"}} {aggregate[1]}"
            )
        lines.extend(
            [
                "# HELP talaria_scans_total Scan runs by bounded outcome.",
                "# TYPE talaria_scans_total counter",
            ]
        )
        for status, count in sorted(scans.items()):
            lines.append(f'talaria_scans_total{{status="{status}"}} {count}')
        return "\n".join(lines) + "\n"


request_metrics = RequestMetrics()


class RequestRateLimiter:
    """Per-process sliding-window limiter for expensive or credential routes."""

    def __init__(self, max_keys: int = 10_000):
        if max_keys <= 0:
            raise ValueError("Rate limiter key bound must be positive")
        self.max_keys = max_keys
        self._hits: OrderedDict[tuple[str, str], deque[float]] = OrderedDict()
        self._lock = Lock()
        self._shared_calls = 0

    def should_prune_shared(self) -> bool:
        """Prune expired shared buckets periodically without per-request scans."""
        with self._lock:
            self._shared_calls += 1
            return self._shared_calls % 256 == 0

    def allow(self, key: tuple[str, str], limit: int, window_seconds: float) -> bool:
        now = monotonic()
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                if len(self._hits) >= self.max_keys:
                    self._hits.popitem(last=False)
                hits = deque()
                self._hits[key] = hits
            else:
                self._hits.move_to_end(key)
            while hits and hits[0] <= now - window_seconds:
                hits.popleft()
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True


class RequestBodyLimitMiddleware:
    """Bound request bodies before framework JSON parsing or route handling."""

    def __init__(self, app, max_body_bytes: int = MAX_REQUEST_BODY_BYTES):
        if max_body_bytes <= 0:
            raise ValueError("Request body limit must be positive")
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_lengths = [
            value
            for key, value in scope.get("headers", [])
            if key.lower() == b"content-length"
        ]
        if len(content_lengths) > 1:
            await self._respond(scope, receive, send, 400, "Invalid Content-Length")
            return
        if content_lengths:
            try:
                declared_length = int(content_lengths[0])
            except ValueError:
                await self._respond(scope, receive, send, 400, "Invalid Content-Length")
                return
            if declared_length < 0:
                await self._respond(scope, receive, send, 400, "Invalid Content-Length")
                return
            if declared_length > self.max_body_bytes:
                await self._respond(scope, receive, send, 413, "Request body is too large")
                return

        chunks = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            chunks.extend(message.get("body", b""))
            if len(chunks) > self.max_body_bytes:
                await self._respond(scope, receive, send, 413, "Request body is too large")
                return
            if not message.get("more_body", False):
                break

        body = bytes(chunks)
        sent = False

        async def replay_receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)

    async def _respond(self, scope, receive, send, status_code: int, detail: str):
        response = JSONResponse({"detail": detail}, status_code=status_code)
        await response(scope, receive, send)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.limiter = RequestRateLimiter()

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        request_id = uuid4().hex
        request.state.request_id = request_id
        started = perf_counter()
        method = request.method.upper()
        rate_limit_path = _rate_limit_route(path)
        limit = _limit_for(rate_limit_path, method)
        if limit is not None:
            host = request.client.host if request.client else "unknown"
            configured_database = database_path()
            database_scope = hashlib.sha256(
                str(configured_database).encode("utf-8")
            ).hexdigest()[:16]
            key = f"{database_scope}:{host}:{method}:{rate_limit_path}"
            if not self.limiter.allow(
                (database_scope, f"{host}:{method}:{rate_limit_path}"), limit, 60.0
            ):
                response = JSONResponse(
                    {"detail": "Too many requests"},
                    status_code=429,
                    headers={"Retry-After": "60"},
                )
                _log_request(request.method, path, 429, request_id, started)
                return _secure_headers(response, path, request_id)
            try:
                allowed = await run_in_threadpool(
                    Database(configured_database, initialize=False).allow_shared_rate_limit,
                    key,
                    limit,
                    60.0,
                    prune_stale=self.limiter.should_prune_shared(),
                )
            except Exception as exc:
                logger.error(
                    json.dumps(
                        {
                            "event": "http.rate_limit_unavailable",
                            "request_id": request_id,
                            "error_type": type(exc).__name__,
                        },
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                )
                response = JSONResponse(
                    {"detail": "Request protection is temporarily unavailable"},
                    status_code=503,
                    headers={"Retry-After": "60"},
                )
                _log_request(request.method, path, 503, request_id, started)
                return _secure_headers(response, path, request_id)
            if not allowed:
                response = JSONResponse(
                    {"detail": "Too many requests"},
                    status_code=429,
                    headers={"Retry-After": "60"},
                )
                _log_request(request.method, path, 429, request_id, started)
                return _secure_headers(response, path, request_id)
        try:
            response = await call_next(request)
        except Exception as exc:
            _log_request(
                request.method,
                path,
                500,
                request_id,
                started,
                error_type=type(exc).__name__,
            )
            raise
        _log_request(request.method, path, response.status_code, request_id, started)
        return _secure_headers(response, path, request_id)


def _limit_for(path: str, method: str) -> int | None:
    method = method.upper()
    if path == "/auth/login" and method == "POST":
        return 10
    if path in {"/auth/refresh", "/auth/logout"} and method == "POST":
        return 20 if path.endswith("refresh") else 30
    if path == "/auth/bootstrap" and method == "POST":
        return 3
    if path == "/auth/register" and method == "POST":
        return 10
    if path == "/auth/organizations" and method == "POST":
        return 5
    if path == "/auth/approvals" and method in {"GET", "POST"}:
        return 60 if method == "GET" else 30
    if (
        path.startswith("/auth/approvals/")
        and path.endswith("/decision")
        and method == "POST"
    ):
        return 30
    if path == "/auth/logout-all" and method == "POST":
        return 30
    if path == "/integrations/github/repositories" and method == "POST":
        return 10
    if (
        path == "/integrations/github/repositories/{repository_id}/commits/{sha}/check-runs"
        and method == "GET"
    ):
        return 10
    if path == "/scans" and method == "POST":
        return 5
    if (
        path.startswith("/findings/")
        and path.endswith("/investigate")
        and method == "POST"
    ):
        return 5
    if path == "/integrations/github/webhook" and method == "POST":
        return 120
    return None


def _secure_headers(response, path: str, request_id: str):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if path in {"/docs", "/redoc"}:
        csp = (
            "default-src 'none'; script-src 'self' 'unsafe-inline' "
            "https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' "
            "https://cdn.jsdelivr.net; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
    else:
        csp = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    response.headers.setdefault("Content-Security-Policy", csp)
    if path.startswith("/auth/"):
        response.headers.setdefault("Cache-Control", "no-store")
    response.headers["X-Request-ID"] = request_id
    return response


def _log_request(
    method: str,
    path: str,
    status: int,
    request_id: str,
    started: float,
    error_type: str | None = None,
) -> None:
    request_metrics.observe_request(
        method,
        path,
        status,
        max(0.0, perf_counter() - started),
    )
    record = {
        "event": "http.request",
        "request_id": request_id,
        "method": method,
        "path": path,
        "status": status,
        "duration_ms": round((perf_counter() - started) * 1000, 2),
    }
    if error_type:
        record["error_type"] = error_type
    logger.info(json.dumps(record, separators=(",", ":"), sort_keys=True))
