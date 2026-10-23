"""SQLite persistence for normalized security events."""

from contextlib import contextmanager
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Iterable, Iterator
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from siem.domain.alerts import alert_record_key
from siem.domain.events import SecurityEvent
from siem.security import DUMMY_HASH, hash_password, new_token, token_digest, verify_password


SCHEMA_VERSION = 3
ROLES = ("viewer", "analyst", "admin")
_USERNAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
# Attribute fields promoted to indexed generated columns for fast pivots.
INDEXED_ATTRIBUTES = ("username", "src_ip")
_PIVOT_COLUMNS = {"source", "host", "event_type", "severity", *INDEXED_ATTRIBUTES}


def to_utc(value: str | datetime) -> str:
    """Normalize a timestamp to UTC ISO-8601 so text order equals time order."""
    parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


@contextmanager
def connect(path: Path) -> Iterator[sqlite3.Connection]:
    """Open a connection, commit (or roll back) the block, and always close it."""
    connection = sqlite3.connect(path, timeout=10.0)
    connection.row_factory = sqlite3.Row
    try:
        with connection:
            yield connection
    finally:
        connection.close()


class SqliteEventStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self):
        return connect(self.path)

    def _initialize(self) -> None:
        with self._connect() as connection:
            # WAL lets the API read while the worker writes to the same file.
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    message TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    host TEXT,
                    attributes_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_observed_at ON security_events(observed_at);
                CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);
                CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type);
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    assignee TEXT,
                    alert_ids_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    audit_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
                CREATE INDEX IF NOT EXISTS idx_incidents_title ON incidents(title);
                CREATE INDEX IF NOT EXISTS idx_audit_incident ON audit_log(incident_id);
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    alert_key TEXT NOT NULL UNIQUE,
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    recommended_action TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity, created_at);
                CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id, created_at);
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    role TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    disabled INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
            """)
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version < 2:
                self._migrate_v2(connection)
            if version < SCHEMA_VERSION:
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    @staticmethod
    def _migrate_v2(connection: sqlite3.Connection) -> None:
        columns = {row["name"] for row in connection.execute("PRAGMA table_xinfo(security_events)")}
        for name in INDEXED_ATTRIBUTES:
            if name not in columns:
                connection.execute(
                    f"ALTER TABLE security_events ADD COLUMN {name} TEXT "
                    f"GENERATED ALWAYS AS (json_extract(attributes_json, '$.{name}')) VIRTUAL"
                )
            connection.execute(f"CREATE INDEX IF NOT EXISTS idx_events_{name} ON security_events({name}, observed_at)")
        # Version 1 stored mixed UTC offsets, which broke ordering and retention.
        rows = connection.execute("SELECT event_id, observed_at FROM security_events WHERE observed_at NOT LIKE '%+00:00'").fetchall()
        for row in rows:
            try:
                connection.execute("UPDATE security_events SET observed_at = ? WHERE event_id = ?",
                                   (to_utc(row["observed_at"]), row["event_id"]))
            except ValueError:
                continue

    def append(self, event: SecurityEvent) -> None:
        self.append_records([event.to_record()])

    def append_records(self, records: Iterable[dict[str, Any]]) -> int:
        count = 0
        with self._connect() as connection:
            for record in records:
                connection.execute(
                    """INSERT OR IGNORE INTO security_events
                    (event_id, source, event_type, message, observed_at, severity, host, attributes_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (str(record["event_id"]), record["source"], record["event_type"], record["message"],
                     to_utc(record["observed_at"]), record.get("severity", "info"), record.get("host"),
                     json.dumps(record.get("attributes", {}), sort_keys=True)),
                )
                count += 1
        return count

    @staticmethod
    def _event_record(row: sqlite3.Row) -> dict[str, Any]:
        item = {key: row[key] for key in row.keys() if key not in INDEXED_ATTRIBUTES}
        item["attributes"] = json.loads(item.pop("attributes_json"))
        return item

    def search(self, *, text: str | None = None, severity: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if text:
            clauses.append("(message LIKE ? OR event_type LIKE ? OR source LIKE ?)")
            needle = f"%{text}%"
            parameters.extend([needle, needle, needle])
        if severity:
            clauses.append("severity = ?")
            parameters.append(severity.lower())
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        parameters.append(max(1, min(limit, 1000)))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM security_events" + where + " ORDER BY observed_at DESC LIMIT ?",
                parameters,
            ).fetchall()
        return [self._event_record(row) for row in rows]

    def events_since(self, since: datetime, *, event_types: Iterable[str] | None = None, limit: int = 50000) -> list[dict[str, Any]]:
        """Events observed at or after `since`, oldest first (correlation lookback)."""
        query = "SELECT * FROM security_events WHERE observed_at >= ?"
        parameters: list[Any] = [to_utc(since)]
        types = list(event_types or [])
        if types:
            query += f" AND event_type IN ({', '.join('?' for _ in types)})"
            parameters.extend(types)
        query += " ORDER BY observed_at ASC LIMIT ?"
        parameters.append(max(1, limit))
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._event_record(row) for row in rows]

    def top_values(self, column: str, *, since: datetime | None = None, event_type: str | None = None, limit: int = 10) -> list[dict[str, Any]]:
        """Most frequent values of one pivot column, e.g. top attacking `src_ip`."""
        if column not in _PIVOT_COLUMNS:
            raise ValueError(f"unsupported pivot column: {column}")
        clauses = [f"{column} IS NOT NULL"]
        parameters: list[Any] = []
        if since:
            clauses.append("observed_at >= ?")
            parameters.append(to_utc(since))
        if event_type:
            clauses.append("event_type = ?")
            parameters.append(event_type)
        parameters.append(max(1, min(limit, 100)))
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {column} AS value, COUNT(*) AS count FROM security_events WHERE {' AND '.join(clauses)} "
                "GROUP BY value ORDER BY count DESC, value LIMIT ?",
                parameters,
            ).fetchall()
        return [dict(row) for row in rows]

    def severity_counts(self, *, since: datetime | None = None) -> dict[str, int]:
        query = "SELECT severity, COUNT(*) FROM security_events"
        parameters: list[Any] = []
        if since:
            query += " WHERE observed_at >= ?"
            parameters.append(to_utc(since))
        with self._connect() as connection:
            return {row[0]: row[1] for row in connection.execute(query + " GROUP BY severity", parameters)}

    def append_alerts(self, records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        """Store alert records; returns only those not already stored (by alert key)."""
        inserted: list[dict[str, Any]] = []
        with self._connect() as connection:
            for record in records:
                cursor = connection.execute(
                    "INSERT OR IGNORE INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (str(record.get("alert_id") or uuid4()), alert_record_key(record), str(record.get("rule_id", "unknown")),
                     str(record.get("title", "Untitled alert")), str(record.get("severity", "medium")),
                     str(record.get("event_id", "unknown")), str(record.get("reason", "")),
                     str(record.get("recommended_action", "")), json.dumps(record.get("evidence") or {}, sort_keys=True),
                     to_utc(record.get("created_at") or datetime.now(timezone.utc))),
                )
                if cursor.rowcount == 1:
                    inserted.append(record)
        return inserted

    @staticmethod
    def _alert_record(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item.pop("alert_key")
        item["evidence"] = json.loads(item.pop("evidence_json"))
        return item

    def search_alerts(self, *, text: str | None = None, severity: str | None = None, rule_id: str | None = None,
                      since: datetime | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """Newest alerts first."""
        clauses: list[str] = []
        parameters: list[Any] = []
        if text:
            clauses.append("(title LIKE ? OR reason LIKE ? OR rule_id LIKE ? OR evidence_json LIKE ?)")
            parameters.extend([f"%{text}%"] * 4)
        if severity:
            clauses.append("severity = ?")
            parameters.append(severity.lower())
        if rule_id:
            clauses.append("rule_id = ?")
            parameters.append(rule_id)
        if since:
            clauses.append("created_at >= ?")
            parameters.append(to_utc(since))
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        parameters.append(max(1, min(limit, 10000)))
        with self._connect() as connection:
            rows = connection.execute(f"SELECT * FROM alerts{where} ORDER BY created_at DESC LIMIT ?", parameters).fetchall()
        return [self._alert_record(row) for row in rows]

    def alert_summary(self, *, since: datetime | None = None) -> dict[str, dict[str, int]]:
        where, parameters = (" WHERE created_at >= ?", [to_utc(since)]) if since else ("", [])
        with self._connect() as connection:
            severities = connection.execute(f"SELECT severity, COUNT(*) FROM alerts{where} GROUP BY severity", parameters).fetchall()
            rules = connection.execute(f"SELECT rule_id, COUNT(*) AS n FROM alerts{where} GROUP BY rule_id ORDER BY n DESC, rule_id LIMIT 10",
                                       parameters).fetchall()
        return {"by_severity": {row[0]: row[1] for row in severities}, "by_rule": {row[0]: row[1] for row in rules}}

    # --- dashboard users and sessions -------------------------------------

    def create_user(self, username: str, password: str, role: str) -> None:
        if not _USERNAME.match(username):
            raise ValueError("username may contain letters, digits, '.', '_' and '-' (max 64)")
        if role not in ROLES:
            raise ValueError(f"role must be one of {', '.join(ROLES)}")
        password_hash = hash_password(password)
        with self._connect() as connection:
            try:
                connection.execute("INSERT INTO users VALUES (?, ?, ?, 0, ?)",
                                   (username, role, password_hash, datetime.now(timezone.utc).isoformat()))
            except sqlite3.IntegrityError as exc:
                raise ValueError(f"user already exists: {username}") from exc

    def update_user(self, username: str, *, password: str | None = None, role: str | None = None,
                    disabled: bool | None = None) -> None:
        """Change a user; any change signs the user out everywhere."""
        changes: dict[str, Any] = {}
        if password is not None:
            changes["password_hash"] = hash_password(password)
        if role is not None:
            if role not in ROLES:
                raise ValueError(f"role must be one of {', '.join(ROLES)}")
            changes["role"] = role
        if disabled is not None:
            changes["disabled"] = int(disabled)
        if not changes:
            return
        with self._connect() as connection:
            assignments = ", ".join(f"{key} = ?" for key in changes)
            if connection.execute(f"UPDATE users SET {assignments} WHERE username = ?", [*changes.values(), username]).rowcount != 1:
                raise ValueError(f"no such user: {username}")
            connection.execute("DELETE FROM sessions WHERE username = ?", (username,))

    def list_users(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT username, role, disabled, created_at FROM users ORDER BY username").fetchall()
        return [{**dict(row), "disabled": bool(row["disabled"])} for row in rows]

    def has_users(self) -> bool:
        with self._connect() as connection:
            return connection.execute("SELECT 1 FROM users WHERE disabled = 0 LIMIT 1").fetchone() is not None

    def authenticate(self, username: str, password: str) -> str | None:
        """The user's role if the password is right and the account is enabled."""
        with self._connect() as connection:
            row = connection.execute("SELECT role, password_hash, disabled FROM users WHERE username = ?", (username,)).fetchone()
        valid = verify_password(password, row["password_hash"] if row else DUMMY_HASH)
        return row["role"] if row and valid and not row["disabled"] else None

    def create_session(self, username: str, *, ttl: timedelta = timedelta(hours=8)) -> str:
        token = new_token()
        now = datetime.now(timezone.utc)
        with self._connect() as connection:
            connection.execute("DELETE FROM sessions WHERE expires_at < ?", (now.isoformat(),))
            connection.execute("INSERT INTO sessions VALUES (?, ?, ?)", (token_digest(token), username, (now + ttl).isoformat()))
        return token

    def session_user(self, token: str) -> tuple[str, str] | None:
        """(username, role) for a live session of an enabled user."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT users.username, users.role FROM sessions JOIN users USING (username) "
                "WHERE token_hash = ? AND expires_at > ? AND users.disabled = 0",
                (token_digest(token), datetime.now(timezone.utc).isoformat()),
            ).fetchone()
        return (row["username"], row["role"]) if row else None

    def delete_session(self, token: str) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_digest(token),))

    def create_incident(self, title: str, severity: str, alert_ids: list[str], *, actor: str) -> dict[str, Any]:
        if not title.strip():
            raise ValueError("incident title must not be empty")
        if severity not in {"low", "medium", "high", "critical"}:
            raise ValueError("invalid incident severity")
        now = datetime.now(timezone.utc).isoformat()
        incident_id = str(uuid4())
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO incidents VALUES (?, ?, ?, 'open', NULL, ?, ?, ?)",
                (incident_id, title, severity, json.dumps(alert_ids), now, now),
            )
            self._audit(connection, incident_id, "created", actor, {"alert_ids": alert_ids})
        return self.get_incident(incident_id)  # type: ignore[return-value]

    def find_open_incident(self, title: str) -> dict[str, Any] | None:
        """The most recent open/investigating incident with this exact title."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM incidents WHERE title = ? AND status IN ('open', 'investigating') ORDER BY updated_at DESC LIMIT 1",
                (title,),
            ).fetchone()
        return self._incident_record(row) if row else None

    def attach_alerts(self, incident_id: str, alert_ids: list[str], *, actor: str, severity: str | None = None) -> dict[str, Any] | None:
        """Add alerts to an existing incident, optionally escalating its severity."""
        current = self.get_incident(incident_id)
        if current is None:
            return None
        ranks = ["low", "medium", "high", "critical"]
        new_severity = current["severity"]
        if severity in ranks and ranks.index(severity) > ranks.index(new_severity):
            new_severity = severity
        merged = current["alert_ids"] + [alert_id for alert_id in alert_ids if alert_id not in current["alert_ids"]]
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            connection.execute("UPDATE incidents SET alert_ids_json = ?, severity = ?, updated_at = ? WHERE incident_id = ?",
                               (json.dumps(merged), new_severity, now, incident_id))
            self._audit(connection, incident_id, "alerts_attached", actor, {"alert_ids": alert_ids, "severity": new_severity})
        return self.get_incident(incident_id)

    def list_incidents(self, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        query = "SELECT * FROM incidents"
        parameters: list[Any] = []
        if status:
            query += " WHERE status = ?"
            parameters.append(status)
        query += " ORDER BY updated_at DESC LIMIT ?"
        parameters.append(max(1, min(limit, 1000)))
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._incident_record(row) for row in rows]

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        return self._incident_record(row) if row else None

    def update_incident(self, incident_id: str, *, actor: str, status: str | None = None, assignee: str | None = None) -> dict[str, Any] | None:
        if status is not None and status not in {"open", "investigating", "resolved", "closed"}:
            raise ValueError("invalid incident status")
        if assignee is not None and (not isinstance(assignee, str) or len(assignee) > 200):
            raise ValueError("assignee must be a string of at most 200 characters")
        current = self.get_incident(incident_id)
        if current is None:
            return None
        changes: dict[str, Any] = {}
        if status is not None:
            changes["status"] = status
        if assignee is not None:
            changes["assignee"] = assignee
        if not changes:
            return current
        now = datetime.now(timezone.utc).isoformat()
        assignments = ", ".join(f"{key} = ?" for key in changes)
        values = list(changes.values()) + [now, incident_id]
        with self._connect() as connection:
            connection.execute(f"UPDATE incidents SET {assignments}, updated_at = ? WHERE incident_id = ?", values)
            self._audit(connection, incident_id, "updated", actor, changes)
        return self.get_incident(incident_id)

    def audit_for_incident(self, incident_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM audit_log WHERE incident_id = ? ORDER BY created_at", (incident_id,)).fetchall()
        return [{**dict(row), "details": json.loads(row["details_json"])} for row in rows]

    def metrics(self) -> dict[str, int]:
        with self._connect() as connection:
            events = connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
            incidents = connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
            open_incidents = connection.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('open', 'investigating')").fetchone()[0]
            audit_entries = connection.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        return {"security_events": events, "incidents": incidents, "open_incidents": open_incidents, "audit_entries": audit_entries}

    @staticmethod
    def _audit(connection: sqlite3.Connection, incident_id: str, action: str, actor: str, details: dict[str, Any]) -> None:
        connection.execute(
            "INSERT INTO audit_log VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid4()), incident_id, action, actor, json.dumps(details, sort_keys=True), datetime.now(timezone.utc).isoformat()),
        )

    @staticmethod
    def _incident_record(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["alert_ids"] = json.loads(item.pop("alert_ids_json"))
        return item
