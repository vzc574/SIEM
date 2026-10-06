"""Small read-only HTTP API for local development."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import hmac
import os
from pathlib import Path
import time
from collections import defaultdict, deque
from urllib.parse import parse_qs, urlparse

from siem.storage.sqlite import SqliteEventStore
from siem.api.dashboard import DASHBOARD_HTML


def parse_api_keys(value: str | None) -> dict[str, str]:
    """Parse `key=role,key=role` credentials from environment configuration."""
    if not value:
        return {}
    result: dict[str, str] = {}
    for item in value.split(","):
        key, separator, role = item.partition("=")
        if separator and key and role in {"viewer", "analyst", "admin"}:
            result[key] = role
    return result


def role_for_request(headers: dict[str, str], api_key: str | None, api_keys: dict[str, str] | None = None) -> str | None:
    supplied = headers.get("X-API-Key", "")
    authorization = headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    configured = api_keys or ({api_key: "admin"} if api_key else {})
    for candidate, role in configured.items():
        if supplied and hmac.compare_digest(supplied, candidate):
            return role
    return "admin" if not configured else None


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


def render_metrics(metrics: dict[str, int]) -> str:
    lines = ["# HELP siem_up SIEM API availability.", "# TYPE siem_up gauge", "siem_up 1"]
    for name, value in metrics.items():
        lines.extend([f"# TYPE siem_{name} gauge", f"siem_{name} {int(value)}"])
    return "\n".join(lines) + "\n"


def make_handler(database: Path, api_key: str | None = None, alert_paths: list[Path] | None = None, api_keys: dict[str, str] | None = None):
    store = SqliteEventStore(database)
    alert_paths = alert_paths or []
    request_times: dict[str, deque[float]] = defaultdict(deque)
    max_requests = 120
    window_seconds = 60.0

    class Handler(BaseHTTPRequestHandler):
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

        def _html(self, status: int, body: str) -> None:
            encoded = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
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

        def do_GET(self) -> None:  # noqa: N802
            if not self._within_rate_limit():
                self._json(429, {"error": "rate limit exceeded"})
                return
            parsed = urlparse(self.path)
            if parsed.path == "/":
                self._html(200, DASHBOARD_HTML)
                return
            if parsed.path == "/health":
                self._json(200, {"status": "ok"})
                return
            if parsed.path == "/me":
                role = role_for_request(dict(self.headers), api_key, api_keys)
                if role is None:
                    self._json(401, {"error": "authentication required"})
                    return
                self._json(200, {"role": role})
                return
            if parsed.path == "/metrics":
                if role_for_request(dict(self.headers), api_key, api_keys) is None:
                    self._json(401, {"error": "authentication required"})
                    return
                self._metrics()
                return
            if role_for_request(dict(self.headers), api_key, api_keys) is None:
                self._json(401, {"error": "authentication required"})
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

        def do_POST(self) -> None:  # noqa: N802
            if not self._within_rate_limit():
                self._json(429, {"error": "rate limit exceeded"})
                return
            if role_for_request(dict(self.headers), api_key, api_keys) not in {"analyst", "admin"}:
                self._json(401, {"error": "authentication required"})
                return
            if self.path != "/incidents":
                self._json(404, {"error": "not found"})
                return
            try:
                body = self._body()
                incident = store.create_incident(
                    str(body.get("title", "")), str(body.get("severity", "medium")),
                    [str(value) for value in body.get("alert_ids", [])],
                    actor=str(self.headers.get("X-Actor", "api-user")),
                )
            except (ValueError, TypeError, json.JSONDecodeError):
                self._json(400, {"error": "invalid incident payload"})
                return
            self._json(201, {"incident": incident})

        def do_PATCH(self) -> None:  # noqa: N802
            if not self._within_rate_limit():
                self._json(429, {"error": "rate limit exceeded"})
                return
            if role_for_request(dict(self.headers), api_key, api_keys) not in {"analyst", "admin"}:
                self._json(401, {"error": "authentication required"})
                return
            if not self.path.startswith("/incidents/"):
                self._json(404, {"error": "not found"})
                return
            try:
                body = self._body()
                incident = store.update_incident(
                    self.path.rsplit("/", 1)[-1], actor=str(self.headers.get("X-Actor", "api-user")),
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
            address = self.client_address[0]
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


def create_server(host: str, port: int, database: Path, api_key: str | None = None, alert_paths: list[Path] | None = None, api_keys: dict[str, str] | None = None) -> ThreadingHTTPServer:
    configured_key = api_key or os.getenv("SIEM_API_KEY")
    configured_keys = api_keys or parse_api_keys(os.getenv("SIEM_API_KEYS"))
    if host not in {"127.0.0.1", "localhost", "::1"} and not (configured_key or configured_keys):
        raise ValueError("SIEM_API_KEY is required when binding outside localhost")
    return ThreadingHTTPServer((host, port), make_handler(database, configured_key, alert_paths, configured_keys))
