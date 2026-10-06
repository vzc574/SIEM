from pathlib import Path

from siem.ingestion.network import collect_network
from siem.storage.jsonl import JsonlEventStore


def ingest_network(path: Path, output: Path, *, format_name: str, source: str) -> int:
    if not path.is_file():
        raise FileNotFoundError(f"Input file does not exist: {path}")
    store = JsonlEventStore(output)
    count = 0
    for event in collect_network(path, format_name=format_name, source=source):
        store.append(event)
        count += 1
    return count

