"""Local indicator-of-compromise store."""

from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from uuid import uuid4


class IOCStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS indicators (
                indicator_id TEXT PRIMARY KEY, kind TEXT NOT NULL, value TEXT NOT NULL,
                source TEXT NOT NULL, confidence INTEGER NOT NULL, created_at TEXT NOT NULL,
                UNIQUE(kind, value)
            )""")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_indicators_lookup ON indicators(kind, value)")

    def add(self, kind: str, value: str, *, source: str, confidence: int = 50) -> None:
        if kind not in {"md5", "sha1", "sha256", "ip", "domain", "url"} or not value.strip():
            raise ValueError("invalid indicator kind or value")
        if not 0 <= confidence <= 100:
            raise ValueError("confidence must be between 0 and 100")
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "INSERT INTO indicators VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(kind, value) DO UPDATE SET source=excluded.source, confidence=excluded.confidence",
                (str(uuid4()), kind, value.strip().lower(), source, confidence, datetime.now(timezone.utc).isoformat()),
            )

    def find(self, kind: str, value: str) -> dict[str, object] | None:
        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute("SELECT * FROM indicators WHERE kind = ? AND value = ?", (kind, value.lower())).fetchone()
        return dict(row) if row else None

