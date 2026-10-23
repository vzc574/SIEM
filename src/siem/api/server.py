"""Small read-only HTTP API for local development."""

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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

from siem.storage.sqlite import SqliteEventStore
from siem.api.dashboard import DASHBOARD_HTML, DASHBOARD_JS


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated caller: its role and the key holder's name for auditing."""

    role: str
    name: str


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


def principal_for_request(headers: dict[str, str], api_key: str | None,
                          api_keys: dict[str, tuple[str, str]] | None = None) -> Principal | None:
    supplied = headers.get("X-API-Key", "")
    authorization = headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    configured = api_keys or ({api_key: ("admin", "api-key")} if api_key else {})
    for candidate, (role, name) in configured.items():
        if supplied and hmac.compare_digest(supplied, candidate):
            return Principal(role, name)
    return Principal("admin", "local-dev") if not configured else None


def role_for_request(headers: dict[str, str], api_key: str | None, api_keys: dict[str, str] | None = None) -> str | None:
    named = {key: (role, "") for key, role in (api_keys or {}).items()}
    principal = principal_for_request(headers, api_key, named)
    return principal.role if principal is not None else None


def is_authorized(headers: dict[str, str], api_key: str | None) -> bool:
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


def alert_summary(paths: list[Path], *, since: datetime | None = None) -> dict[str, dict[str, int]]:
    """Alert counts by severity and rule, optionally only those created since `since`."""
    severities: Counter[str] = Counter()
    rules: Counter[str] = Counter()
    cutoff = since.isoformat() if since else ""
    for record in _read_jsonl(paths, text=None, severity=None, limit=10**9):
        if cutoff and str(record.get("created_at", "")) < cutoff:
            continue
        severities[str(record.get("severity", "unknown"))] += 1
        rules[str(record.get("rule_id", "unknown"))] += 1
    return {"by_severity": dict(severities), "by_rule": dict(rules.most_common(10))}


def render_metrics(metrics: dict[str, int]) -> str:
    lines = ["# HELP siem_up SIEM API availability.", "# TYPE siem_up gauge", "siem_up 1"]
    for name, value in metrics.items():
        lines.extend([f"# TYPE siem_{name} gauge", f"siem_{name} {int(value)}"])
    return "\n".join(lines) + "\n"


def parse_trusted_proxies(value: str | None) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """CIDRs of reverse proxies whose X-Real-IP / X-Forwarded-For header is trusted."""
    return [ipaddress.ip_network(item.strip(), strict=False) for item in (value or "").split(",") if item.strip()]


def client_address(peer: str, headers: dict[str, str], trusted: list) -> str:
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if not any(address in network for network in trusted):
        return peer
    forwarded = headers.get("X-Real-IP") or headers.get("X-Forwarded-For", "").split(",")[-1]
    return forwarded.strip() or peer


def make_handler(database: Path, api_key: str | None = None, alert_paths: list[Path] | None = None,
                 api_keys: dict[str, str] | dict[str, tuple[str, str]] | None = None,
                 trusted_proxies: list | None = None):
    store = SqliteEventStore(database)
    alert_paths = alert_paths or []
    named_keys = {key: (value if isinstance(value, tuple) else (value, "")) for key, value in (api_keys or {}).items()}
    trusted = trusted_proxies or []
    request_times: dict[str, deque[float]] = defaultdict(deque)
    rate_lock = threading.Lock()
    max_requests = 120
    window_seconds = 60.0

    class Handler(BaseHTTPRequestHandler):
        def _principal(self) -> Principal | None:
            return principal_for_request(self.headers, api_key, named_keys)

        def _json(self, status: int, payload: object) -> None:
            body = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cache-Control", "no-store")
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
            since = datetime.now(timezone.utc) - timedelta(hours=hours)
            return {
                "window_hours": hours,
                "events_by_severity": store.severity_counts(since=since),
                "top_failed_login_ips": store.top_values("src_ip", since=since, event_type="login.failed", limit=5),
                "top_failed_login_users": store.top_values("username", since=since, event_type="login.failed", limit=5),
                "alerts": alert_summary(alert_paths, since=since),
            }

        def do_GET(self) -> None:  # noqa: N802
            if not self._within_rate_limit():
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
                except (OSError, ValueError, json.JSONDecodeError):
                    self._json(400, {"error": "invalid stats query or alert data"})
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
                    alerts = _read_jsonl(
                        alert_paths,
                        text=query.get("text", [None])[0],
                        severity=query.get("severity", [None])[0],
                        limit=int(query.get("limit", [100])[0]),
                    )
                except (OSError, ValueError, json.JSONDecodeError):
                    self._json(400, {"error": "invalid alert query or alert data"})
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
            if principal.role not in {"analyst", "admin"}:
                self._json(403, {"error": "analyst or admin role required"})
                return None
            return principal

        def do_POST(self) -> None:  # noqa: N802
            if not self._within_rate_limit():
                self._json(429, {"error": "rate limit exceeded"})
                return
            principal = self._writer()
            if principal is None:
                return
            if urlparse(self.path).path != "/incidents":
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
            if not self._within_rate_limit():
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

        def _within_rate_limit(self) -> bool:
            now = time.monotonic()
            address = client_address(self.client_address[0], self.headers, trusted)
            with rate_lock:
                if len(request_times) > 10000:
                    for stale in [key for key, times in request_times.items() if not times or now - times[-1] > window_seconds]:
                        del request_times[stale]
                recent = request_times[address]
                while recent and now - recent[0] > window_seconds:
                    recent.popleft()
                if len(recent) >= max_requests:
                    return False
                recent.append(now)
                return True

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def create_server(host: str, port: int, database: Path, api_key: str | None = None, alert_paths: list[Path] | None = None,
                  api_keys: dict[str, str] | dict[str, tuple[str, str]] | None = None) -> ThreadingHTTPServer:
    configured_key = api_key or os.getenv("SIEM_API_KEY")
    configured_keys = api_keys or parse_named_api_keys(os.getenv("SIEM_API_KEYS"))
    if host not in {"127.0.0.1", "localhost", "::1"} and not (configured_key or configured_keys):
        raise ValueError("SIEM_API_KEY is required when binding outside localhost")
    trusted = parse_trusted_proxies(os.getenv("SIEM_TRUSTED_PROXIES"))
    return ThreadingHTTPServer((host, port), make_handler(database, configured_key, alert_paths, configured_keys, trusted))
