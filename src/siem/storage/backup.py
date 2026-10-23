"""SQLite backup utility."""

from pathlib import Path
from siem.storage.sqlite import connect


def backup_database(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise FileNotFoundError(f"Database does not exist: {source}")
    if source.resolve() == destination.resolve():
        raise ValueError("backup destination must differ from source")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with connect(source) as source_connection, connect(destination) as destination_connection:
        source_connection.backup(destination_connection)

