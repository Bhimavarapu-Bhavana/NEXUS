from __future__ import annotations

from typing import Any

from app.comms.service import communication_observatory
from app.security.audit_logger import record_audit_event
from app.security.sensitive_data import redact_sensitive_data


def observe_comms(provider: str = "comms", *, capability_context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read-only provider-independent communication observation tool.

    Never sends or mutates any communication state. Returns a bounded, redacted
    snapshot of conversations, messages, classifications, deadlines,
    commitments, meetings, follow-ups, decisions, task references, and possible
    unanswered conversations for use as planning and reasoning evidence.
    """
    result = communication_observatory(provider_name=str(provider or "comms"))
    record_audit_event("comms_observation_completed", actor="comms_observer", tool="comms_observer", risk_level="READ_ONLY", approved=False, target=str(provider or "comms"), result="OK", metadata={"message_count": result.get("message_count", 0)})
    return redact_sensitive_data(result)


__all__ = ["observe_comms"]