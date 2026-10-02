from __future__ import annotations

from typing import Any

from app.email.service import email_observatory
from app.security.audit_logger import record_audit_event
from app.security.sensitive_data import redact_sensitive_data


def observe_email(provider: str = "fixture", *, capability_context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read-only email observation tool.

    Never sends or mutates email state. Returns a bounded, redacted snapshot
    of messages, classifications, deadlines, commitments, meetings, follow-ups,
    and possible unanswered threads for use as planning and reasoning evidence.
    """
    result = email_observatory(provider_name=str(provider or "fixture"))
    record_audit_event("email_observation_completed", actor="email_observer", tool="email_observer", risk_level="READ_ONLY", approved=False, target=str(provider or "fixture"), result="OK", metadata={"message_count": result.get("message_count", 0)})
    return redact_sensitive_data(result)


__all__ = ["observe_email"]