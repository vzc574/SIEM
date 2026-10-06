"""Normalized security events used by all collectors and detectors."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """A normalized, append-only security event."""

    source: str
    event_type: str
    message: str
    observed_at: datetime
    severity: str = "info"
    event_id: UUID = field(default_factory=uuid4)
    host: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise ValueError("source must not be empty")
        if not self.event_type.strip():
            raise ValueError("event_type must not be empty")
        if not self.message.strip():
            raise ValueError("message must not be empty")
        if self.severity not in {"debug", "info", "low", "medium", "high", "critical"}:
            raise ValueError("invalid severity")
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must include a timezone")

    @classmethod
    def now(cls, *, source: str, event_type: str, message: str, **kwargs: Any) -> "SecurityEvent":
        return cls(
            source=source,
            event_type=event_type,
            message=message,
            observed_at=datetime.now(timezone.utc),
            **kwargs,
        )

    def to_record(self) -> dict[str, Any]:
        record = asdict(self)
        record["event_id"] = str(self.event_id)
        record["observed_at"] = self.observed_at.isoformat()
        return record

