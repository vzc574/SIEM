"""Detection alerts produced from security events."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class Alert:
    rule_id: str
    title: str
    severity: str
    event_id: str
    reason: str
    recommended_action: str
    alert_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_record(self) -> dict[str, Any]:
        record = asdict(self)
        record["alert_id"] = str(self.alert_id)
        record["created_at"] = self.created_at.isoformat()
        return record

