"""Import syslog events into the JSONL event store."""

from pathlib import Path

from siem.ingestion.syslog import collect_syslog
from siem.storage.jsonl import JsonlEventStore


def ingest_syslog(input_path: Path, output_path: Path, *, source: str = "syslog") -> int:
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file does not exist: {input_path}")
    store = JsonlEventStore(output_path)
    count = 0
    for event in collect_syslog(input_path, source=source):
        store.append(event)
        count += 1
    return count

