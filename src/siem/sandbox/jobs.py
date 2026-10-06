"""Create sandbox jobs without executing or interpreting samples."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class SandboxJob:
    job_id: str
    sha256: str
    original_path: str
    status: str
    created_at: str
    sample_path: str | None = None

    def to_record(self) -> dict[str, object]:
        return asdict(self)


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_job(path: Path, spool_dir: Path, *, spool_sample: bool = False) -> SandboxJob:
    """Create a pending job; this function never executes the sample."""
    if not path.is_file():
        raise FileNotFoundError(f"File does not exist: {path}")
    digest = _hash_file(path)
    sample_path: Path | None = None
    if spool_sample:
        sample_dir = spool_dir / "samples"
        sample_dir.mkdir(parents=True, exist_ok=True)
        sample_path = sample_dir / f"{digest}.sample"
        if not sample_path.exists():
            shutil.copyfile(path, sample_path)
    job = SandboxJob(
        job_id=str(uuid4()),
        sha256=digest,
        original_path=str(path),
        status="pending",
        created_at=datetime.now(timezone.utc).isoformat(),
        sample_path=str(sample_path) if sample_path else None,
    )
    spool_dir.mkdir(parents=True, exist_ok=True)
    with (spool_dir / "jobs.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(job.to_record(), sort_keys=True) + "\n")
    return job

