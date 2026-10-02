from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from app.calendar.models import parse_calendar_datetime
from app.calendar.providers import MUTATION_OPERATIONS, get_provider
from app.security.audit_logger import record_audit_event
from app.security.risk_engine import BLOCKED, evaluate_risk
from app.security.sensitive_data import redact_sensitive_data, redact_text

CALENDAR_ACTION_TOOL = "calendar_event_action"
_MAX_EVENT_TITLE_CHARS = 500
_DATETIME_PATTERNS = (
    re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:?\d{2}|Z)?"),
    re.compile(r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:?\d{2}|Z)?"),
    re.compile(r"\d{4}-\d{2}-\d{2}\s+at\s+\d{1,2}:\d{2}(?::\d{2})?(?:[+-]\d{2}:?\d{2}|\s+(?:UTC|GMT))?", flags=re.IGNORECASE),
    re.compile(r"\d{4}-\d{2}-\d{2}"),
)

_OPERATION_PATTERNS = (
    ("create", ("add a", "create", "add a calendar", "create a calendar", "add an event", "new event", "new calendar", "schedule a", "schedule the", "set a reminder for", "add a deadline")),
    ("update", ("update the event", "update event", "change the event", "change event", "modify the event", "reschedule the event", "reschedule event", "update the calendar")),
    ("delete", ("delete the event", "delete event", "delete the calendar entry", "remove the event", "remove event", "remove the calendar entry")),
    ("cancel", ("cancel the event", "cancel event", "cancel the meeting", "cancel the appointment", "cancel the calendar")),
)


def _audit(event: str, **payload: Any) -> bool:
    payload["tool"] = payload.get("tool") or CALENDAR_ACTION_TOOL
    return record_audit_event(event, **payload)


def _snapshot_matches(expected: dict[str, Any] | None, current: dict[str, Any] | None) -> bool:
    if not isinstance(expected, dict) or not isinstance(current, dict):
        return False
    for key in ("event_id", "title", "start_time"):
        if str(expected.get(key) or "") != str(current.get(key) or ""):
            return False
    return True


def _bounded_result(status: str, *, verification: str, approved: bool, **payload: Any) -> dict[str, Any]:
    return redact_sensitive_data({"source": "calendar_action", "tool": CALENDAR_ACTION_TOOL, "status": status, "verification": verification, "approved": bool(approved), "risk_decision": payload.pop("risk_decision", {}), **payload})


def calendar_event_action(spec: Any, *, approved: bool = False, provider: str = "fixture", task_id: str = "", actor: str = "calendar_action", calendar_state: Any = None) -> dict[str, Any]:
    """Execute one bounded calendar mutation through the shared approval path.

    Only the fixed operation set is accepted. Update/delete/cancel require a
    grounded event identifier with a matching observation snapshot. Create
    requires explicit title and start time. Anything else fails closed.
    This is not a generic calendar execution endpoint.
    """
    if not isinstance(spec, dict):
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=False, risk_decision={"risk_level": BLOCKED, "allowed": False, "approval_required": False, "reason": "Calendar actions require a structured specification.", "category": "CALENDAR_ACTION"}, action_result="Calendar actions require a structured specification.")

    operation = str(spec.get("operation") or "").strip().lower()
    if operation not in MUTATION_OPERATIONS:
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=bool(approved), risk_decision={"risk_level": BLOCKED, "allowed": False, "approval_required": True, "reason": "Unknown or arbitrary calendar operations are blocked.", "category": "CALENDAR_ACTION"}, action_result="Unsupported calendar operation.")

    provider_instance = get_provider(provider)
    if not provider_instance.supports_mutation():
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=bool(approved), risk_decision={"risk_level": BLOCKED, "allowed": False, "approval_required": False, "reason": "The calendar provider does not support mutations.", "category": "CALENDAR_ACTION"}, action_result="The calendar provider does not support mutations.")

    risk_decision = evaluate_risk("execute calendar_event_action", tool_name=CALENDAR_ACTION_TOOL)
    _audit("calendar_action_risk_decision", actor=actor, risk_level=risk_decision["risk_level"], approval_required=risk_decision["approval_required"], approved=False, target=redact_text(str(spec.get("event_id") or spec.get("title") or provider)), result=str(risk_decision["allowed"]), reason=risk_decision["reason"])
    if not risk_decision["allowed"] or risk_decision["risk_level"] == BLOCKED:
        _audit("calendar_action_blocked", actor=actor, risk_level=BLOCKED, approved=False, target=redact_text(str(spec.get("event_id") or "")), result="BLOCKED", reason=risk_decision["reason"])
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=bool(approved), risk_decision=risk_decision, action_result=risk_decision["reason"])

    if not approved:
        _audit("calendar_action_approval_requested", actor=actor, risk_level=risk_decision["risk_level"], approval_required=True, approved=False, target=redact_text(str(spec.get("event_id") or spec.get("title") or "")), result="APPROVAL_REQUIRED", reason="Approval is required before calendar state changes.")
        return _bounded_result("APPROVAL_REQUIRED", verification="NOT_RUN", approved=False, risk_decision=risk_decision, action_result="Approval is required before calendar state changes.")

    if not _audit("calendar_action_approval_propagation", actor=actor, risk_level=risk_decision["risk_level"], approval_required=True, approved=True, target=redact_text(str(spec.get("event_id") or spec.get("title") or "")), result="APPROVED", reason="Approval propagated to the bounded calendar action."):
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=True, risk_decision=risk_decision, action_result="Audit persistence failed before calendar action execution.")

    target = redact_text(str(spec.get("event_id") or spec.get("title") or ""))
    try:
        if operation in {"update", "delete", "cancel"}:
            event_id = str(spec.get("event_id") or "").strip()
            grounded = spec.get("grounded_snapshot")
            if not event_id:
                raise ValueError("Update, delete, and cancel require a grounded event identifier.")
            existing = provider_instance.get_event(event_id)
            if existing is None:
                raise ValueError("The target calendar event was not observed and cannot be modified.")
            if not _snapshot_matches(grounded, existing.snapshot()):
                raise ValueError("The observed calendar event changed before execution; revalidation required.")
        if operation == "create":
            title = redact_text(spec.get("title"))[: _MAX_EVENT_TITLE_CHARS].strip()
            start = spec.get("start_time")
            if not title:
                raise ValueError("Creating a calendar event requires an explicit title.")
            if not start:
                raise ValueError("Creating a calendar event requires an explicit start time; NEXUS does not invent times.")
            start_time = parse_calendar_datetime(start)
            end_time = parse_calendar_datetime(spec.get("end_time")) if spec.get("end_time") else None
            if end_time is not None and end_time <= start_time:
                raise ValueError("Calendar event end time must be after its start time.")
            created = provider_instance.create_event(
                title=title,
                start_time=start_time,
                end_time=end_time,
                summary=redact_text(spec.get("summary") or "")[:1000],
                description=redact_text(spec.get("description") or "")[:2000],
                timezone=str(spec.get("timezone") or "UTC")[:64],
                status="CONFIRMED",
                confidence=str(spec.get("confidence") or "MEDIUM").upper(),
            )
            _audit("calendar_action_executed", actor=actor, risk_level=risk_decision["risk_level"], approved=True, target=created.event_id, result="COMPLETED", metadata={"operation": operation, "task_id": task_id})
            return _bounded_result("COMPLETED", verification="SUCCESS", approved=True, risk_decision=risk_decision, operation=operation, event_id=created.event_id, event=created.to_dict(), action_result="Calendar event created through the approval path.")
        if operation == "update":
            event_id = str(spec.get("event_id") or "").strip()
            updates: dict[str, Any] = {}
            if spec.get("title"):
                updates["title"] = redact_text(spec["title"])
            if spec.get("start_time"):
                updates["start_time"] = parse_calendar_datetime(spec["start_time"])
            if spec.get("end_time"):
                updates["end_time"] = parse_calendar_datetime(spec["end_time"])
            if spec.get("summary"):
                updates["summary"] = redact_text(spec["summary"])
            if spec.get("description"):
                updates["description"] = redact_text(spec["description"])
            if spec.get("status"):
                updates["status"] = redact_text(spec["status"])
            if spec.get("confidence"):
                updates["confidence"] = redact_text(spec["confidence"])
            if not updates:
                raise ValueError("Update requires at least one explicit field.")
            updated = provider_instance.update_event(event_id, **updates)
            _audit("calendar_action_executed", actor=actor, risk_level=risk_decision["risk_level"], approved=True, target=event_id, result="COMPLETED", metadata={"operation": operation, "task_id": task_id})
            return _bounded_result("COMPLETED", verification="SUCCESS", approved=True, risk_decision=risk_decision, operation=operation, event_id=event_id, event=updated.to_dict(), action_result="Calendar event updated through the approval path.")
        if operation == "delete":
            event_id = str(spec.get("event_id") or "").strip()
            provider_instance.delete_event(event_id)
            _audit("calendar_action_executed", actor=actor, risk_level=risk_decision["risk_level"], approved=True, target=event_id, result="COMPLETED", metadata={"operation": operation, "task_id": task_id})
            return _bounded_result("COMPLETED", verification="SUCCESS", approved=True, risk_decision=risk_decision, operation=operation, event_id=event_id, action_result="Calendar event deleted through the approval path.")
        if operation == "cancel":
            event_id = str(spec.get("event_id") or "").strip()
            updated = provider_instance.cancel_event(event_id)
            _audit("calendar_action_executed", actor=actor, risk_level=risk_decision["risk_level"], approved=True, target=event_id, result="COMPLETED", metadata={"operation": operation, "task_id": task_id})
            return _bounded_result("COMPLETED", verification="SUCCESS", approved=True, risk_decision=risk_decision, operation=operation, event_id=event_id, event=updated.to_dict(), action_result="Calendar event cancelled through the approval path.")
        raise ValueError("Unsupported calendar operation.")
    except (TypeError, ValueError) as exc:
        reason = redact_text(str(exc))
        _audit("calendar_action_blocked", actor=actor, risk_level=BLOCKED, approved=False, target=target, result="BLOCKED", reason=reason)
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=True, risk_decision=risk_decision, action_result=reason)


def parse_calendar_request(request: str, observed_events: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Build a bounded, grounded calendar action specification or return None.

    Returns None whenever the request cannot be deterministically grounded:
    missing target event, missing explicit time, or ambiguous match. NEXUS
    never invents calendar content.
    """
    lowered = redact_text(request).lower()
    operation = ""
    for candidate, patterns in _OPERATION_PATTERNS:
        if any(pattern in lowered for pattern in patterns):
            operation = candidate
            break
    if not operation:
        return None
    events = [event for event in (observed_events or []) if isinstance(event, dict)]
    spec: dict[str, Any] = {"operation": operation}
    if operation in {"update", "delete", "cancel"}:
        title = _match_event_title(lowered, events)
        if not title:
            return None
        event = _find_event_by_title(title, events)
        if event is None:
            return None
        spec["event_id"] = event.get("event_id", "")
        spec["grounded_snapshot"] = {
            "event_id": event.get("event_id", ""),
            "title": event.get("title", ""),
            "start_time": event.get("start_time", ""),
        }
        new_time = _extract_datetime(request)
        if operation == "update" and new_time:
            spec["start_time"] = new_time
        return redact_sensitive_data(spec)
    if operation == "create":
        title = _extract_create_title(request)
        start = _extract_datetime(request)
        if not title or not start:
            return None
        spec["title"] = title
        spec["start_time"] = start
        return redact_sensitive_data(spec)
    return None


def _match_event_title(lowered: str, events: list[dict[str, Any]]) -> str:
    for event in events:
        title = str(event.get("title") or "")
        if title and title.lower() in lowered:
            return title
    return ""


def _find_event_by_title(title: str, events: list[dict[str, Any]]) -> dict[str, Any] | None:
    matches = [event for event in events if str(event.get("title") or "") == title]
    if len(matches) == 1:
        return matches[0]
    return None


def _extract_create_title(request: str) -> str:
    text = redact_text(request or "")
    explicit = re.search(r"(?:titled|title\s+as|named|called)\s+[\"']?([\w][\w .&'-]{2,120})[\"']?", text, flags=re.IGNORECASE)
    if explicit:
        captured = explicit.group(1)
        for pattern in _DATETIME_PATTERNS:
            inner_match = pattern.search(captured)
            if inner_match:
                captured = captured[: inner_match.start()].strip(" ,:;-")
                break
        captured = re.sub(r"\s+(?:on|at|starting|beginning)\s*$", "", captured).strip(" ,:;-")
        return redact_text(captured).strip()[: _MAX_EVENT_TITLE_CHARS]
    datetime_match = _DATETIME_PATTERNS[0].search(text) or _DATETIME_PATTERNS[1].search(text) or _DATETIME_PATTERNS[2].search(text) or _DATETIME_PATTERNS[3].search(text)
    if datetime_match:
        prefix = text[: datetime_match.start()]
        lower_prefix = prefix.lower()
        for pattern in ("add a calendar", "add a new calendar", "create a calendar", "add a calendar event", "create a calendar event", "add an event", "new calendar event", "schedule a"):
            marker = lower_prefix.rfind(pattern)
            if marker >= 0:
                candidate = prefix[marker + len(pattern):].strip(" ,:;-")
                candidate = re.sub(r"\s{2,}", " ", candidate).strip(" ,:;-")
                candidate = re.sub(r"\s+(?:on|at|starting|beginning)\s*$", "", candidate).strip(" ,:;-")
                if candidate:
                    return redact_text(candidate)[: _MAX_EVENT_TITLE_CHARS]
        return ""
    return ""


def _extract_datetime(request: str) -> str:
    for pattern in _DATETIME_PATTERNS:
        match = pattern.search(request or "")
        if not match:
            continue
        try:
            parsed = parse_calendar_datetime(match.group(0).strip().replace(" at ", " "))
        except ValueError:
            continue
        return parsed.isoformat()
    return ""


__all__ = ["CALENDAR_ACTION_TOOL", "calendar_event_action", "parse_calendar_request"]