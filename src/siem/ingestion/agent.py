"""Tailing collector agent: follow a live log file and append normalized events.

The agent keeps a byte offset plus the file's inode, so it survives restarts,
detects log rotation and truncation, and never re-reads the whole file.
Malformed lines are reported and skipped instead of stopping collection.
"""

from dataclasses import dataclass, field, replace
import json
from pathlib import Path
import time
from typing import Callable
from uuid import NAMESPACE_URL, uuid5

from siem.ingestion.formats import LogLineError, parse_line
from siem.storage.jsonl import JsonlEventStore


@dataclass(slots=True)
class PollResult:
    events_written: int = 0
    errors: list[str] = field(default_factory=list)


def _load_state(path: Path) -> dict[str, int]:
    if not path.exists():
        return {"inode": 0, "offset": 0}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return {"inode": int(value.get("inode", 0)), "offset": int(value.get("offset", 0))}
    except (OSError, ValueError, json.JSONDecodeError):
        return {"inode": 0, "offset": 0}


def _save_state(path: Path, inode: int, offset: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps({"inode": inode, "offset": offset}, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def poll(
    input_path: Path,
    output_path: Path,
    state_path: Path,
    *,
    input_format: str,
    source: str,
    max_bytes: int = 8 * 1024 * 1024,
) -> PollResult:
    """Collect complete lines appended since the last poll."""
    stat = input_path.stat()
    state = _load_state(state_path)
    offset = state["offset"]
    if state["inode"] != stat.st_ino or stat.st_size < offset:
        offset = 0  # rotated or truncated: start the new file from the top
    with input_path.open("rb") as stream:
        stream.seek(offset)
        chunk = stream.read(max_bytes)
    result = PollResult()
    end = chunk.rfind(b"\n") + 1
    if end == 0:
        if len(chunk) == max_bytes:
            result.errors.append(f"{input_path}@{offset}: line longer than {max_bytes} bytes skipped")
            _save_state(state_path, stat.st_ino, offset + len(chunk))
        return result  # otherwise wait for the writer to finish the line
    store = JsonlEventStore(output_path)
    position = offset
    for raw in chunk[:end].splitlines(keepends=True):
        line = raw.decode("utf-8", errors="replace").strip()
        if line:
            try:
                event = parse_line(line, input_format, source=source)
                # Deterministic IDs make a replay after a crash idempotent downstream.
                store.append(replace(event, event_id=uuid5(NAMESPACE_URL, f"{source}\n{line}")))
                result.events_written += 1
            except LogLineError as exc:
                result.errors.append(f"{input_path}@{position}: {exc}")
        position += len(raw)
    _save_state(state_path, stat.st_ino, offset + end)
    return result


def follow(
    input_path: Path,
    output_path: Path,
    state_path: Path,
    *,
    input_format: str,
    source: str,
    interval_seconds: float = 5.0,
    on_poll: Callable[[PollResult], None] | None = None,
) -> None:
    if interval_seconds <= 0:
        raise ValueError("interval must be positive")
    while True:
        try:
            result = poll(input_path, output_path, state_path, input_format=input_format, source=source)
        except FileNotFoundError:
            result = PollResult()  # the log may not exist yet or is mid-rotation
        if on_poll:
            on_poll(result)
        time.sleep(interval_seconds)
