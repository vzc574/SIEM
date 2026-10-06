"""Explicit quarantine action with dry-run default."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class QuarantineResult:
    source: Path
    destination: Path
    applied: bool
    sha256: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def quarantine_file(source: Path, quarantine_dir: Path, *, apply: bool = False) -> QuarantineResult:
    """Plan or apply quarantine for one file.

    The default is a dry-run. Applying moves the file to a generated unique
    name and writes an append-only manifest entry containing its original path.
    """
    if not source.is_file():
        raise FileNotFoundError(f"File does not exist: {source}")
    digest = _sha256(source)
    destination = quarantine_dir / f"{digest[:16]}-{uuid4().hex}{source.suffix}.quarantined"
    if not apply:
        return QuarantineResult(source, destination, False, digest)

    quarantine_dir.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source), str(destination))
    manifest = quarantine_dir / "manifest.jsonl"
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": str(source),
        "destination": str(destination),
        "sha256": digest,
    }
    with manifest.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")
    return QuarantineResult(source, destination, True, digest)

