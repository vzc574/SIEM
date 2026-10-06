"""Non-executing static analysis for suspicious files.

This module reads bytes only. It does not load binaries, invoke interpreters,
follow embedded links, or make changes to the input file.
"""

from dataclasses import asdict, dataclass, field
import hashlib
import math
from pathlib import Path
import re
from typing import Any


_PRINTABLE = re.compile(rb"[ -~]{6,}")
_SUSPICIOUS_TERMS = (
    b"powershell",
    b"cmd.exe",
    b"rundll32",
    b"regsvr32",
    b"schtasks",
    b"/bin/sh",
    b"/bin/bash",
    b"downloadstring",
    b"invoke-expression",
)


@dataclass(frozen=True, slots=True)
class FileAnalysis:
    path: str
    sha256: str
    size: int
    extension: str
    magic: str
    entropy: float
    strings: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    classification: str = "unknown"

    def to_record(self) -> dict[str, Any]:
        return asdict(self)


def _magic(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "windows-pe"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith(b"PK\x03\x04"):
        return "zip-or-office-archive"
    if data.startswith(b"#!"):
        return "script"
    return "unknown"


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)


def analyze_file(path: Path, *, max_strings: int = 100) -> FileAnalysis:
    """Analyze a file without executing it or changing it."""
    if not path.is_file():
        raise FileNotFoundError(f"File does not exist: {path}")
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    extracted = [match.decode("utf-8", errors="replace") for match in _PRINTABLE.findall(data)[:max_strings]]
    lower_data = data.lower()
    indicators: list[str] = []
    for term in _SUSPICIOUS_TERMS:
        if term in lower_data:
            indicators.append(f"contains:{term.decode('ascii')}")
    if _magic(data) in {"windows-pe", "elf"}:
        indicators.append(f"binary:{_magic(data)}")
    if _entropy(data) >= 7.2:
        indicators.append("high-entropy")

    if len(indicators) >= 2:
        classification = "suspicious"
    elif indicators:
        classification = "potentially-suspicious"
    else:
        classification = "no-obvious-indicators"

    return FileAnalysis(
        path=str(path),
        sha256=digest,
        size=len(data),
        extension=path.suffix.lower(),
        magic=_magic(data),
        entropy=round(_entropy(data), 4),
        strings=extracted,
        indicators=indicators,
        classification=classification,
    )

