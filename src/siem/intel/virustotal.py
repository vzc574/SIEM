"""Optional VirusTotal hash-reputation lookup.

Only a hash is sent. This adapter never uploads or downloads a sample.
"""

from dataclasses import asdict, dataclass
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class VirusTotalError(RuntimeError):
    """Raised when a VirusTotal lookup cannot be completed."""


@dataclass(frozen=True, slots=True)
class HashReputation:
    sha256: str
    found: bool
    malicious: int = 0
    suspicious: int = 0
    total_engines: int = 0
    tags: tuple[str, ...] = ()

    def to_record(self) -> dict[str, object]:
        return asdict(self)


def parse_file_response(sha256: str, payload: dict[str, object]) -> HashReputation:
    data = payload.get("data")
    if not isinstance(data, dict):
        raise VirusTotalError("VirusTotal response did not contain file data")
    attributes = data.get("attributes", {})
    if not isinstance(attributes, dict):
        raise VirusTotalError("VirusTotal response did not contain file attributes")
    stats = attributes.get("last_analysis_stats", {})
    if not isinstance(stats, dict):
        stats = {}
    raw_tags = attributes.get("tags", [])
    tags = tuple(str(tag) for tag in raw_tags) if isinstance(raw_tags, list) else ()
    total = sum(int(stats.get(key, 0) or 0) for key in ("malicious", "suspicious", "undetected", "harmless", "timeout", "type-unsupported"))
    return HashReputation(sha256=sha256, found=True, malicious=int(stats.get("malicious", 0) or 0), suspicious=int(stats.get("suspicious", 0) or 0), total_engines=total, tags=tags)


def lookup_hash(sha256: str, api_key: str, *, timeout: float = 10.0) -> HashReputation:
    if len(sha256) != 64 or any(character not in "0123456789abcdefABCDEF" for character in sha256):
        raise ValueError("sha256 must be a 64-character hexadecimal hash")
    request = Request(
        f"https://www.virustotal.com/api/v3/files/{sha256.lower()}",
        headers={"x-apikey": api_key, "Accept": "application/json"},
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            return parse_file_response(sha256.lower(), json.loads(response.read()))
    except HTTPError as exc:
        if exc.code == 404:
            return HashReputation(sha256=sha256.lower(), found=False)
        raise VirusTotalError(f"VirusTotal HTTP error: {exc.code}") from exc
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise VirusTotalError(f"VirusTotal lookup failed: {exc}") from exc

