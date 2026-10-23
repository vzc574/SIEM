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


def alert_record_key(record: dict[str, Any]) -> str:
    """Identity of one finding: the same rule firing on the same event and indicator.

    Per-event rules are keyed by event, so separate events from one source are
    never merged; correlation/intel alerts also carry the indicator they matched.
    """
    evidence = record.get("evidence") or {}
    indicator = evidence.get("identity") or evidence.get("value") or evidence.get("sha256") or ""
    return f"{record.get('rule_id')}|{record.get('event_id')}|{indicator}"

