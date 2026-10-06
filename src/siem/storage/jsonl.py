"""Append-only JSON Lines storage for the foundation milestone."""

import json
from pathlib import Path

from siem.domain.events import SecurityEvent


class JsonlEventStore:
    """Store normalized events without modifying previously written records."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, event: SecurityEvent) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event.to_record(), sort_keys=True) + "\n")

    def read_all(self) -> list[dict[str, object]]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as stream:
            return [json.loads(line) for line in stream if line.strip()]

