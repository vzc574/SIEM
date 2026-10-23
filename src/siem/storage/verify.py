"""Validate SQLite database integrity and expected schema."""

from pathlib import Path
from siem.storage.sqlite import connect


def verify_database(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"Database does not exist: {path}")
    with connect(path) as connection:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    required = {"security_events", "incidents", "audit_log"}
    return {"path": str(path), "integrity": integrity, "required_tables": sorted(required), "missing_tables": sorted(required - tables), "valid": integrity == "ok" and required.issubset(tables)}

