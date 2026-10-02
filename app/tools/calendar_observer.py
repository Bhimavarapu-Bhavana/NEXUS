from __future__ import annotations

from typing import Any

from app.calendar.service import provider_observatory
from app.security.audit_logger import record_audit_event
from app.security.sensitive_data import redact_sensitive_data


def observe_calendar(provider: str = "fixture", *, capability_context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read-only calendar observation tool.

    Never mutates calendar state. Returns a bounded, redacted snapshot of
    events, upcoming events, deadline candidates, and verified conflicts for
    use as planning and deadline-reasoning evidence.
    """
    result = provider_observatory(provider_name=str(provider or "fixture"))
    record_audit_event("calendar_observation_completed", actor="calendar_observer", tool="calendar_observer", risk_level="READ_ONLY", approved=False, target=str(provider or "fixture"), result="OK", metadata={"event_count": result.get("event_count", 0)})
    return redact_sensitive_data(result)


__all__ = ["observe_calendar"]