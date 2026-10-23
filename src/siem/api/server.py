"""HTTP API and dashboard backend."""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import threading
import time
from urllib.parse import parse_qs, urlparse

from siem.domain.events import SecurityEvent
from siem.storage.sqlite import SqliteEventStore
from siem.api.dashboard import DASHBOARD_HTML, DASHBOARD_JS


SESSION_COOKIE = "siem_session"
SESSION_TTL = timedelta(hours=8)
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated caller: its role and the name recorded in the audit log."""

    role: str
    name: str
    via_session: bool = False


def parse_api_keys(value: str | None) -> dict[str, str]:
    """Parse `[name:]key=role,...` credentials from environment configuration.

    The optional name identifies the key holder in the incident audit log.
    """
    return {key: role for key, (role, _) in parse_named_api_keys(value).items()}


def parse_named_api_keys(value: str | None) -> dict[str, tuple[str, str]]:
    if not value:
        return {}
    result: dict[str, tuple[str, str]] = {}
    for item in value.split(","):
        credential, separator, role = item.strip().rpartition("=")
        name, colon, key = credential.partition(":")
        if not colon:
            name, key = "", credential
        if separator and key and role in {"viewer", "analyst", "admin"}:
            result[key] = (role, name or f"key-{hashlib.sha256(key.encode()).hexdigest()[:8]}")
    return result


def principal_for_request(headers, api_key: str | None, api_keys: dict[str, tuple[str, str]] | None = None,
                          *, allow_anonymous: bool = False) -> Principal | None:
    """Resolve an API key. Anonymous admin access exists only in explicit local dev mode."""
    supplied = headers.get("X-API-Key", "")
    authorization = headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    configured = api_keys or ({api_key: ("admin", "api-key")} if api_key else {})
    for candidate, (role, name) in configured.items():
        if supplied and hmac.compare_digest(supplied, candidate):
            return Principal(role, name)
    return Principal("admin", "local-dev") if allow_anonymous and not supplied else None


def role_for_request(headers, api_key: str | None, api_keys: dict[str, str] | None = None) -> str | None:
    named = {key: (role, "") for key, role in (api_keys or {}).items()}
    principal = principal_for_request(headers, api_key, named)
    return principal.role if principal is not None else None


def is_authorized(headers, api_key: str | None) -> bool:
    """Validate API credentials when authentication is configured."""
    if not api_key:
        return True
    return role_for_request(headers, api_key) is not None


def _read_jsonl(paths: list[Path], *, text: str | None, severity: str | None, limit: int) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for path in paths:
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                record = json.loads(line)
                if severity and str(record.get("severity", "")).lower() != severity.lower():
                    continue
                if text:
                    haystack = json.dumps(record, sort_keys=True).lower()
                    if text.lower() not in haystack:
                        continue
                records.append(record)
    return records[-max(1, min(limit, 1000)):]


class AlertFileSync:
    """Incrementally import alert JSONL files into the alerts table.

    Each request only reads bytes appended since the previous one, so the
    dashboard stays fast however large the alert files grow.
    """

    def __init__(self, store: SqliteEventStore, paths: list[Path]) -> None:
        self.store = store
        self.paths = paths
        self.offsets: dict[Path, tuple[int, int]] = {}
        self.lock = threading.Lock()

    def sync(self) -> int:
        imported = 0
        with self.lock:
            for path in self.paths:
                try:
                    stat = path.stat()
                except FileNotFoundError:
                    continue
                inode, offset = self.offsets.get(path, (stat.st_ino, 0))
                if inode != stat.st_ino or stat.st_size < offset:
                    offset = 0
                with path.open("rb") as stream:
                    stream.seek(offset)
                    chunk = stream.read()
                end = chunk.rfind(b"\n") + 1
                records = []
                for line in chunk[:end].splitlines():
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(record, dict):
                        records.append(record)
                imported += len(self.store.append_alerts(records))
                self.offsets[path] = (stat.st_ino, offset + end)
        return imported


def render_metrics(metrics: dict[str, int]) -> str:
    lines = ["# HELP siem_up SIEM API availability.", "# TYPE siem_up gauge", "siem_up 1"]
    for name, value in metrics.items():
        lines.extend([f"# TYPE siem_{name} gauge", f"siem_{name} {int(value)}"])
    return "\n".join(lines) + "\n"


def parse_trusted_proxies(value: str | None) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """CIDRs of reverse proxies whose X-Real-IP / X-Forwarded-For header is trusted."""
    return [ipaddress.ip_network(item.strip(), strict=False) for item in (value or "").split(",") if item.strip()]


def client_address(peer: str, headers, trusted: list) -> str:
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if not any(address in network for network in trusted):
        return peer
    forwarded = headers.get("X-Real-IP") or headers.get("X-Forwarded-For", "").split(",")[-1]
    return forwarded.strip() or peer


class _SlidingLimiter:
    """Per-key request counter over a sliding window (thread-safe, self-pruning)."""

    def __init__(self, limit: int, window_seconds: float) -> None:
        self.limit, self.window = limit, window_seconds
        self.hits: dict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def _recent(self, key: str, now: float) -> deque[float]:
        if len(self.hits) > 10000:
            for stale in [k for k, times in self.hits.items() if not times or now - times[-1] > self.window]:
                del self.hits[stale]
        recent = self.hits[key]
        while recent and now - recent[0] > self.window:
            recent.popleft()
        return recent

    def allow(self, key: str) -> bool:
        """Count a hit unless the key is already at its limit."""
        now = time.monotonic()
        with self.lock:
            recent = self._recent(key, now)
            if len(recent) >= self.limit:
                return False
            recent.append(now)
            return True

    def blocked(self, key: str) -> bool:
        with self.lock:
            return len(self._recent(key, time.monotonic())) >= self.limit

    def record(self, key: str) -> None:
        with self.lock:
            self._recent(key, time.monotonic()).append(time.monotonic())


def make_handler(database: Path, api_key: str | None = None, alert_paths: list[Path] | None = None,
                 api_keys: dict[str, str] | dict[str, tuple[str, str]] | None = None,
                 trusted_proxies: list | None = None, *, allow_anonymous: bool = False):
    store = SqliteEventStore(database)
    alert_sync = AlertFileSync(store, alert_paths or [])
    alert_sync.sync()
    named_keys = {key: (value if isinstance(value, tuple) else (value, "")) for key, value in (api_keys or {}).items()}
    trusted = trusted_proxies or []
    requests = _SlidingLimiter(120, 60.0)
    failed_logins = _SlidingLimiter(10, 300.0)

    class Handler(BaseHTTPRequestHandler):
        def _client(self) -> str:
            return client_address(self.client_address[0], self.headers, trusted)

        def _session_token(self) -> str | None:
            try:
                cookie = SimpleCookie(self.headers.get("Cookie", ""))
            except CookieError:
                return None
            morsel = cookie.get(SESSION_COOKIE)
            return morsel.value if morsel else None

        def _principal(self) -> Principal | None:
            principal = principal_for_request(self.headers, api_key, named_keys)
            if principal:
                return principal
            token = self._session_token()
            if token and (user := store.session_user(token)):
                return Principal(user[1], user[0], via_session=True)
            return principal_for_request(self.headers, api_key, named_keys, allow_anonymous=allow_anonymous)

        def _json(self, status: int, payload: object, *, cookie: str | None = None) -> None:
            body = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cache-Control", "no-store")
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(body)

        def _static(self, content_type: str, body: str) -> None:
            encoded = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            # Scripts load only from /dashboard.js, so injected inline script cannot run.
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(encoded)

        def _metrics(self) -> None:
            body = render_metrics(store.metrics()).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _stats(self, hours: int) -> dict[str, object]:
            alert_sync.sync()
            since = datetime.now(timezone.utc) - timedelta(hours=hours)
            return {
                "window_hours": hours,
                "events_by_severity": store.severity_counts(since=since),
                "top_failed_login_ips": store.top_values("src_ip", since=since, event_type="login.failed", limit=5),
                "top_failed_login_users": store.top_values("username", since=since, event_type="login.failed", limit=5),
                "alerts": store.alert_summary(since=since),
            }

        def do_GET(self) -> None:  # noqa: N802
            if not requests.allow(self._client()):
                self._json(429, {"error": "rate limit exceeded"})
                return
            parsed = urlparse(self.path)
            if parsed.path == "/":
                self._static("text/html; charset=utf-8", DASHBOARD_HTML)
                return
            if parsed.path == "/dashboard.js":
                self._static("text/javascript; charset=utf-8", DASHBOARD_JS)
                return
            if parsed.path == "/health":
                self._json(200, {"status": "ok"})
                return
            principal = self._principal()
            if principal is None:
                self._json(401, {"error": "authentication required"})
                return
            if parsed.path == "/me":
                self._json(200, {"role": principal.role, "name": principal.name})
                return
            if parsed.path == "/metrics":
                self._metrics()
                return
            if parsed.path == "/stats":
                try:
                    hours = max(1, min(int(parse_qs(parsed.query).get("hours", [24])[0]), 24 * 30))
                    self._json(200, self._stats(hours))
                except (OSError, ValueError):
                    self._json(400, {"error": "invalid stats query"})
                return
            if parsed.path == "/events":
                query = parse_qs(parsed.query)
                text = query.get("text", [None])[0]
                severity = query.get("severity", [None])[0]
                try:
                    limit = int(query.get("limit", [100])[0])
                    events = store.search(text=text, severity=severity, limit=limit)
                except (TypeError, ValueError):
                    self._json(400, {"error": "limit must be an integer"})
                    return
                self._json(200, {"count": len(events), "events": events})
                return
            if parsed.path == "/alerts":
                query = parse_qs(parsed.query)
                try:
                    alert_sync.sync()
                    alerts = store.search_alerts(
                        text=query.get("text", [None])[0],
                        severity=query.get("severity", [None])[0],
                        rule_id=query.get("rule", [None])[0],
                        limit=min(int(query.get("limit", [100])[0]), 1000),
                    )
                except (OSError, ValueError):
                    self._json(400, {"error": "invalid alert query"})
                    return
                self._json(200, {"count": len(alerts), "alerts": alerts})
                return
            if parsed.path == "/incidents":
                query = parse_qs(parsed.query)
                try:
                    incidents = store.list_incidents(query.get("status", [None])[0], int(query.get("limit", [100])[0]))
                except ValueError:
                    self._json(400, {"error": "invalid incident query"})
                    return
                self._json(200, {"count": len(incidents), "incidents": incidents})
                return
            if parsed.path.startswith("/incidents/"):
                incident_id = parsed.path.rsplit("/", 1)[-1]
                incident = store.get_incident(incident_id)
                if incident is None:
                    self._json(404, {"error": "incident not found"})
                    return
                self._json(200, {"incident": incident, "audit": store.audit_for_incident(incident_id)})
                return
            self._json(404, {"error": "not found"})

        def _json_request(self) -> bool:
            # Browsers cannot send application/json cross-site without a CORS
            # preflight, which this server never approves: this blocks CSRF.
            return self.headers.get("Content-Type", "").split(";")[0].strip().lower() == "application/json"

        def _body(self) -> dict[str, object]:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 64 * 1024:
                raise ValueError("request body too large")
            value = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(value, dict):
                raise ValueError("request body must be an object")
            return value

        def _writer(self) -> Principal | None:
            principal = self._principal()
            if principal is None:
                self._json(401, {"error": "authentication required"})
                return None
            if principal.via_session and not self._json_request():
                self._json(415, {"error": "Content-Type must be application/json"})
                return None
            if principal.role not in {"analyst", "admin"}:
                self._json(403, {"error": "analyst or admin role required"})
                return None
            return principal

        def _cookie(self, value: str, max_age: int) -> str:
            secure = "; Secure" if (self.headers.get("X-Forwarded-Proto") == "https" or os.getenv("SIEM_COOKIE_SECURE") == "1") else ""
            return f"{SESSION_COOKIE}={value}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure}"

        def _login(self) -> None:
            client = self._client()
            if failed_logins.blocked(client):
                self._json(429, {"error": "too many failed logins; try again later"})
                return
            if not self._json_request():
                self._json(415, {"error": "Content-Type must be application/json"})
                return
            try:
                body = self._body()
            except (ValueError, json.JSONDecodeError):
                self._json(400, {"error": "invalid login payload"})
                return
            username, password = body.get("username"), body.get("password")
            if not isinstance(username, str) or not isinstance(password, str) or not username:
                self._json(400, {"error": "username and password are required"})
                return
            role = store.authenticate(username, password)
            # The SIEM monitors its own front door: logins become security events.
            store.append(SecurityEvent.now(
                source="siem-dashboard", event_type="login.success" if role else "login.failed",
                message=f"Dashboard login {'succeeded' if role else 'failed'} for {username[:64]}",
                severity="info" if role else "medium",
                attributes={"username": username[:64], "src_ip": client, "program": "siem-dashboard"},
            ))
            if role is None:
                failed_logins.record(client)
                self._json(401, {"error": "invalid username or password"})
                return
            token = store.create_session(username, ttl=SESSION_TTL)
            self._json(200, {"name": username, "role": role}, cookie=self._cookie(token, int(SESSION_TTL.total_seconds())))

        def do_POST(self) -> None:  # noqa: N802
            if not requests.allow(self._client()):
                self._json(429, {"error": "rate limit exceeded"})
                return
            path = urlparse(self.path).path
            if path == "/login":
                self._login()
                return
            if path == "/logout":
                if token := self._session_token():
                    store.delete_session(token)
                self._json(200, {"status": "signed out"}, cookie=self._cookie("", 0))
                return
            principal = self._writer()
            if principal is None:
                return
            if path != "/incidents":
                self._json(404, {"error": "not found"})
                return
            try:
                body = self._body()
                incident = store.create_incident(
                    str(body.get("title", "")), str(body.get("severity", "medium")),
                    [str(value) for value in body.get("alert_ids", [])],
                    actor=principal.name,
                )
            except (ValueError, TypeError, json.JSONDecodeError):
                self._json(400, {"error": "invalid incident payload"})
                return
            self._json(201, {"incident": incident})

        def do_PATCH(self) -> None:  # noqa: N802
            if not requests.allow(self._client()):
                self._json(429, {"error": "rate limit exceeded"})
                return
            principal = self._writer()
            if principal is None:
                return
            path = urlparse(self.path).path
            if not path.startswith("/incidents/"):
                self._json(404, {"error": "not found"})
                return
            try:
                body = self._body()
                incident = store.update_incident(
                    path.rsplit("/", 1)[-1], actor=principal.name,
                    status=body.get("status"), assignee=body.get("assignee"),
                )
            except (ValueError, TypeError, json.JSONDecodeError):
                self._json(400, {"error": "invalid incident update"})
                return
            if incident is None:
                self._json(404, {"error": "incident not found"})
                return
            self._json(200, {"incident": incident})

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def create_server(host: str, port: int, database: Path, api_key: str | None = None, alert_paths: list[Path] | None = None,
                  api_keys: dict[str, str] | dict[str, tuple[str, str]] | None = None,
                  *, allow_insecure_local: bool = False) -> ThreadingHTTPServer:
    """Build the server. Some credential (API key or dashboard user) is required,
    unless `allow_insecure_local` is set and the server binds to loopback only."""
    configured_key = api_key or os.getenv("SIEM_API_KEY")
    configured_keys = api_keys or parse_named_api_keys(os.getenv("SIEM_API_KEYS"))
    local = host in LOCAL_HOSTS
    if allow_insecure_local and not local:
        raise ValueError("--insecure-local only works when binding to 127.0.0.1, localhost or ::1")
    if not (configured_key or configured_keys or SqliteEventStore(database).has_users() or allow_insecure_local):
        raise ValueError("no credentials configured: set SIEM_API_KEY/SIEM_API_KEYS, create a dashboard user "
                         "with `python database.py user-add`, or use --insecure-local for local development")
    trusted = parse_trusted_proxies(os.getenv("SIEM_TRUSTED_PROXIES"))
    handler = make_handler(database, configured_key, alert_paths, configured_keys, trusted,
                           allow_anonymous=allow_insecure_local and not (configured_key or configured_keys))
    return ThreadingHTTPServer((host, port), handler)
