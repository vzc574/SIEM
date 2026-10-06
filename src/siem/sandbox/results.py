"""Validate and normalize results returned by an external sandbox."""

from datetime import datetime, timezone
import hashlib
import hmac
import json
from typing import Any

from siem.domain.events import SecurityEvent


class SandboxResultError(ValueError):
    """Raised when an external sandbox result is not trustworthy or valid."""


def _canonical_payload(result: dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in result.items() if key != "signature"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def validate_result(result: dict[str, Any], *, expected_sha256: str | None = None, signing_key: str | None = None) -> None:
    required = {"job_id", "sha256", "status", "findings"}
    if not required.issubset(result):
        raise SandboxResultError("result is missing required fields")
    if result["status"] not in {"completed", "failed", "timeout"}:
        raise SandboxResultError("invalid sandbox status")
    if not isinstance(result["findings"], list):
        raise SandboxResultError("findings must be a list")
    if expected_sha256 and str(result["sha256"]).lower() != expected_sha256.lower():
        raise SandboxResultError("result hash does not match submitted sample")
    if signing_key:
        signature = result.get("signature")
        if not isinstance(signature, str):
            raise SandboxResultError("signed result is missing signature")
        expected = hmac.new(signing_key.encode("utf-8"), _canonical_payload(result), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise SandboxResultError("sandbox result signature is invalid")


def result_to_events(result: dict[str, Any], *, source: str = "sandbox") -> list[SecurityEvent]:
    validate_result(result)
    observed_at = datetime.now(timezone.utc)
    events = [SecurityEvent(
        source=source,
        event_type="sandbox.completed",
        message=f"Sandbox analysis {result['status']} for {result['sha256']}",
        observed_at=observed_at,
        severity="high" if result["status"] == "completed" else "medium",
        attributes={"job_id": result["job_id"], "sha256": result["sha256"], "finding_count": len(result["findings"])},
    )]
    for finding in result["findings"]:
        if not isinstance(finding, dict) or not finding.get("type"):
            raise SandboxResultError("each finding must be an object with a type")
        events.append(SecurityEvent(
            source=source,
            event_type=f"sandbox.{finding['type']}",
            message=str(finding.get("message", finding["type"])),
            observed_at=observed_at,
            severity=str(finding.get("severity", "medium")).lower(),
            attributes={"job_id": result["job_id"], "sha256": result["sha256"], **finding},
        ))
    return events

