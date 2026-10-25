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
# Windows stores many strings (registry paths, URLs) as UTF-16LE.
_WIDE_PRINTABLE = re.compile(rb"(?:[ -~]\x00){6,}")
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
# Imported API names and strings that reveal what a binary can do. Benign
# software uses some of these too, so they explain a verdict, not prove one.
_CAPABILITIES = {
    "kernel-driver": ("ntoskrnl.exe", "iocreatedevice", "keservicedescriptortable"),
    "registry-modification": ("regsetvalue", "regcreatekey", "rtlwriteregistryvalue", "rtlcreateregistrykey", "zwsetvaluekey"),
    "process-injection": ("virtualallocex", "writeprocessmemory", "createremotethread", "ntunmapviewofsection",
                          "queueuserapc", "setthreadcontext"),
    "keylogging": ("setwindowshookex", "getasynckeystate"),
    "network-download": ("urldownloadtofile", "internetopen", "httpsendrequest", "winhttpopen", "wsastartup"),
    "service-persistence": ("createservice", "openscmanager", "currentversion\\run"),
    "process-execution": ("winexec", "shellexecute", "createprocess"),
    "privilege-escalation": ("adjusttokenprivileges", "lookupprivilegevalue"),
    "anti-debugging": ("isdebuggerpresent", "checkremotedebuggerpresent"),
    "security-tampering": ("windowsfirewall", "firewallpolicy", "disableantispyware"),
}


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
    capabilities: dict[str, list[str]] = field(default_factory=dict)

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
    wide = [match.decode("utf-16-le", errors="replace") for match in _WIDE_PRINTABLE.findall(data)]
    extracted += wide[:max(0, max_strings - len(extracted))]
    lower_data = data.lower() + "\n".join(wide).lower().encode("utf-8", errors="replace")
    indicators: list[str] = []
    for term in _SUSPICIOUS_TERMS:
        if term in lower_data:
            indicators.append(f"contains:{term.decode('ascii')}")
    capabilities: dict[str, list[str]] = {}
    for capability, terms in _CAPABILITIES.items():
        matched = [term for term in terms if term.encode("ascii") in lower_data]
        if matched:
            capabilities[capability] = matched
            indicators.append(f"capability:{capability}")
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
        capabilities=capabilities,
    )

