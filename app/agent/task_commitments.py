from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from app.security.sensitive_data import redact_sensitive_data, redact_text

PRIORITIES = {"LOW", "NORMAL", "HIGH", "CRITICAL"}
DEADLINE_CONFIDENCES = {"LOW", "MEDIUM", "HIGH"}
DEADLINE_STATES = {"NONE", "UPCOMING", "DUE_SOON", "OVERDUE", "INVALID"}


def parse_deadline(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError("Deadline must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def validate_deadline(*, deadline: str, source: str, evidence: list[dict[str, Any]], confidence: str) -> dict[str, Any]:
    parsed = parse_deadline(deadline)
    if parsed is None:
        raise ValueError("A deadline requires a timestamp.")
    if not str(source or "").strip():
        raise ValueError("A deadline requires a source.")
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("A deadline requires evidence provenance.")
    normalized_confidence = str(confidence or "").upper()
    if normalized_confidence not in DEADLINE_CONFIDENCES:
        raise ValueError("Deadline confidence must be LOW, MEDIUM, or HIGH.")
    return redact_sensitive_data({
        "deadline": parsed.isoformat(),
        "source": redact_text(source),
        "evidence": evidence[:20],
        "confidence": normalized_confidence,
        "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })


def deadline_state(deadline: str | None, *, now: datetime | None = None, due_soon_hours: int = 48) -> str:
    if not deadline:
        return "NONE"
    try:
        target = parse_deadline(deadline)
    except ValueError:
        return "INVALID"
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    if target < current:
        return "OVERDUE"
    if target <= current + timedelta(hours=max(1, int(due_soon_hours))):
        return "DUE_SOON"
    return "UPCOMING"


def dependency_state(*, dependencies: list[str], task_statuses: dict[str, str]) -> dict[str, Any]:
    normalized = [str(item).strip() for item in dependencies if str(item).strip()]
    blocked_by = [task_id for task_id in normalized if str(task_statuses.get(task_id, "MISSING")).upper() != "COMPLETED"]
    return {"blocked": bool(blocked_by), "blocked_by": blocked_by, "dependencies": normalized}


def deadline_conflicts(tasks: list[dict[str, Any]], *, window_minutes: int = 60) -> list[dict[str, Any]]:
    parsed: list[tuple[str, datetime]] = []
    for task in tasks:
        try:
            deadline = parse_deadline(task.get("deadline"))
        except ValueError:
            continue
        if deadline is not None:
            parsed.append((str(task.get("task_id") or ""), deadline))
    conflicts = []
    for index, (left_id, left_time) in enumerate(parsed):
        for right_id, right_time in parsed[index + 1:]:
            if abs((left_time - right_time).total_seconds()) <= max(1, int(window_minutes)) * 60:
                conflicts.append({"task_ids": [left_id, right_id], "relationship": "deadline_conflict"})
    return conflicts


def normalize_commitment_metadata(*, priority: str = "NORMAL", commitment: str = "", completion_criteria: list[str] | None = None, associated_files: list[str] | None = None, associated_conversations: list[str] | None = None, associated_applications: list[str] | None = None, browser_context: dict[str, Any] | None = None) -> dict[str, Any]:
    normalized_priority = str(priority or "NORMAL").upper()
    if normalized_priority not in PRIORITIES:
        raise ValueError("Unknown task priority.")
    return redact_sensitive_data({
        "priority": normalized_priority,
        "commitment": redact_text(commitment)[:1000],
        "completion_criteria": [redact_text(item)[:500] for item in (completion_criteria or [])[:20]],
        "associated_files": [redact_text(item)[:500] for item in (associated_files or [])[:20]],
        "associated_conversations": [redact_text(item)[:500] for item in (associated_conversations or [])[:20]],
        "associated_applications": [redact_text(item)[:200] for item in (associated_applications or [])[:20]],
        "associated_browser_context": redact_sensitive_data(browser_context or {}),
    })
