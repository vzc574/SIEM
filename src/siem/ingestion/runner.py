"""Application service for importing JSONL logs into the event store."""

from dataclasses import dataclass
from pathlib import Path

from siem.ingestion.json_lines import collect_json_lines
from siem.storage.jsonl import JsonlEventStore


@dataclass(frozen=True, slots=True)
class IngestionResult:
    input_path: Path
    output_path: Path
    events_written: int


def ingest_file(input_path: Path, output_path: Path, *, default_source: str) -> IngestionResult:
    """Import one JSONL file into append-only event storage."""
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file does not exist: {input_path}")

    store = JsonlEventStore(output_path)
    events_written = 0
    for event in collect_json_lines(input_path, default_source=default_source):
        store.append(event)
        events_written += 1
    return IngestionResult(input_path, output_path, events_written)

