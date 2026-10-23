"""Safe event-retention operations."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from siem.storage.backup import backup_database
from siem.storage.sqlite import connect


def prune_events(database: Path, *, older_than_days: int, apply: bool = False, backup_path: Path | None = None) -> int:
    if older_than_days < 1:
        raise ValueError("older_than_days must be at least one")
    if not database.is_file():
        raise FileNotFoundError(f"Database does not exist: {database}")
    cutoff = (datetime.now(timezone.utc) - timedelta(days=older_than_days)).isoformat()
    if apply and backup_path:
        backup_database(database, backup_path)
    with connect(database) as connection:
        count = connection.execute("SELECT COUNT(*) FROM security_events WHERE observed_at < ?", (cutoff,)).fetchone()[0]
        if apply:
            connection.execute("DELETE FROM security_events WHERE observed_at < ?", (cutoff,))
    return int(count)

