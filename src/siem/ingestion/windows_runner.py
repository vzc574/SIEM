from pathlib import Path

from siem.ingestion.windows import collect_windows_json
from siem.storage.jsonl import JsonlEventStore


def ingest_windows_json(input_path: Path, output_path: Path, *, source: str = "windows-eventlog") -> int:
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file does not exist: {input_path}")
    store = JsonlEventStore(output_path)
    count = 0
    for event in collect_windows_json(input_path, source=source):
        store.append(event)
        count += 1
    return count

