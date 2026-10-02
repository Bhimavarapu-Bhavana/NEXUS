from __future__ import annotations

from typing import Any

from app.agent.task_commitments import deadline_state as _deadline_state

DEADLINE_STATE_PRIORITY = {
    "OVERDUE": "CRITICAL",
    "DUE_SOON": "HIGH",
    "UPCOMING": "MEDIUM",
    "INVALID": "LOW",
    "NONE": "LOW",
}
DEADLINE_STATE_URGENCY = {
    "OVERDUE": "IMMEDIATE",
    "DUE_SOON": "TODAY",
    "UPCOMING": "SOON",
    "INVALID": "NONE",
    "NONE": "NONE",
}
STATE_PRIORITY = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFORMATIONAL": 0,
}
_URGENCY_ORDER = {"NONE": 0, "LATER": 1, "SOON": 2, "TODAY": 3, "IMMEDIATE": 4}
_PRIORITY_BY_SCORE = (0, "INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")

TASK_STATUS_PRIORITY = {
    "BLOCKED": 4,
    "ERROR": 4,
    "FAILED": 4,
    "RECOVERING": 4,
    "OVERDUE": 4,
    "IN_PROGRESS": 3,
    "RUNNING": 3,
    "PENDING": 2,
    "QUEUED": 2,
    "WAITING_APPROVAL": 2,
    "APPROVED": 2,
    "COMPLETED": 1,
    "CANCELLED": 1,
    "NONE": 0,
}


def _max_priority(*priorities: str) -> str:
    best = 0
    result = "INFORMATIONAL"
    for priority in priorities:
        score = STATE_PRIORITY.get(priority, 0)
        if score > best:
            best = score
            result = priority
    return result


def max_priority(*priorities: str) -> str:
    return _max_priority(*priorities)


def deadline_attention_state(deadline: Any, confidence: Any, *, now: Any = None) -> tuple[str, str]:
    if not deadline:
        return "NONE", ""
    raw = str(deadline).strip()
    if not raw:
        return "NONE", ""
    state = _deadline_state(raw, now=now)
    if state == "INVALID":
        return "INVALID", _deadline_state(raw, now=now)
    return state, state


def calendar_event_attention_state(event: dict[str, Any], *, now: Any = None) -> tuple[str, str]:
    if not isinstance(event, dict):
        return "LOW", "NONE"
    if event.get("is_deadline"):
        deadline = event.get("start_time") or event.get("deadline") or ""
        state, _ = deadline_attention_state(deadline, event.get("confidence", "MEDIUM"), now=now)
        priority = DEADLINE_STATE_PRIORITY.get(state, "LOW")
        urgency = DEADLINE_STATE_URGENCY.get(state, "NONE")
        if state in {"OVERDUE", "DUE_SOON", "UPCOMING"}:
            priority = _max_priority(priority, "MEDIUM")
        return priority, urgency
    return "LOW", "NONE"


def task_attention_state(
    *,
    priority: Any = "LOW",
    status: Any = "NONE",
    deadline: Any = "",
    deadline_state: Any = "NONE",
    confidence: Any = "MEDIUM",
    blocked: bool = False,
    needs_user_attention: bool = False,
    consequential: bool = False,
    now: Any = None,
) -> tuple[str, str, str, str, bool]:
    priority_norm = str(priority or "LOW").upper()
    status_norm = str(status or "NONE").upper()
    status_weight = TASK_STATUS_PRIORITY.get(status_norm, 0)
    priority_score = max(status_weight, 0)
    base_priority = _PRIORITY_BY_SCORE[min(priority_score, 5)]

    want_priority = base_priority
    want_urgency = "NONE"
    if status_norm in {"BLOCKED", "ERROR", "FAILED", "RECOVERING"}:
        want_priority = _max_priority(want_priority, "HIGH")
        want_urgency = "TODAY"
    if deadline_state in {"OVERDUE", "DUE_SOON"}:
        state_priority = DEADLINE_STATE_PRIORITY.get(str(deadline_state).upper(), "LOW")
        state_urgency = DEADLINE_STATE_URGENCY.get(str(deadline_state).upper(), "NONE")
        want_priority = _max_priority(want_priority, state_priority)
        want_urgency = DEADLINE_STATE_URGENCY.get(str(deadline_state).upper(), want_urgency)
    if needs_user_attention:
        want_priority = _max_priority(want_priority, "MEDIUM")
    if blocked:
        want_priority = _max_priority(want_priority, "HIGH")
        if _URGENCY_ORDER.get(want_urgency, 0) < _URGENCY_ORDER["TODAY"]:
            want_urgency = "TODAY"
    requires_user = bool(needs_user_attention) or want_priority in {"CRITICAL", "HIGH", "MEDIUM"}
    return want_priority, want_urgency, priority_norm, status_norm, requires_user


def security_attention_state(severity: Any) -> tuple[str, str]:
    severity_norm = str(severity or "").upper()
    if severity_norm in {"CRITICAL", "BLOCKED", "DATA_BREACH", "THREAT_DETECTED"}:
        return "CRITICAL", "IMMEDIATE"
    if severity_norm in {"HIGH", "SECURITY"}:
        return "HIGH", "TODAY"
    if severity_norm in {"MEDIUM", "WARNING"}:
        return "MEDIUM", "SOON"
    return "LOW", "NONE"


def approval_attention_state(risk_level: Any) -> tuple[str, str]:
    risk_norm = str(risk_level or "").upper()
    if risk_norm in {"HIGH_RISK", "HIGH", "CRITICAL"}:
        return "HIGH", "TODAY"
    if risk_norm in {"MEDIUM_RISK", "MEDIUM"}:
        return "MEDIUM", "SOON"
    return "LOW", "NONE"


def informational_density_state(count: Any, *, threshold: int = 25, soft_threshold: int = 10) -> tuple[str, str]:
    """A deterministic, rule-based density state for informational workloads.

    High or sustained change density (many changed files, workspace events, or
    document fact groups) escalates a read-only informational item without any
    learned or generative scoring.
    """
    try:
        normalized_count = max(0, int(count or 0))
    except (TypeError, ValueError):
        normalized_count = 0
    if normalized_count >= max(1, int(threshold)):
        return "MEDIUM", "SOON"
    if normalized_count >= max(1, int(soft_threshold)):
        return "LOW", "SOON"
    return "LOW", "NONE"


__all__ = [
    "DEADLINE_STATE_PRIORITY",
    "DEADLINE_STATE_URGENCY",
    "approval_attention_state",
    "calendar_event_attention_state",
    "deadline_attention_state",
    "informational_density_state",
    "max_priority",
    "security_attention_state",
    "task_attention_state",
]