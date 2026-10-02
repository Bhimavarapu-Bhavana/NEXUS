from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from app.security.sensitive_data import redact_sensitive_data, redact_text

MAX_CONTEXT_TEXT = 500
MAX_CONTEXT_LIST = 50


def evidence_hash(value: Any) -> str:
    safe = redact_sensitive_data(value)
    payload = json.dumps(safe, sort_keys=True, ensure_ascii=True, default=str, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _text(value: Any, *, required: bool = False) -> str:
    result = redact_text(str(value or "")).strip()[:MAX_CONTEXT_TEXT]
    if required and not result:
        raise ValueError("Capability context contains a required empty field.")
    return result


def _list(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple, set)):
        raise ValueError("Capability context list fields must be sequences.")
    return [_text(item) for item in list(value)[:MAX_CONTEXT_LIST] if _text(item)]


def _deadline(value: Any) -> str:
    text = _text(value)
    if not text:
        return ""
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Capability context freshness_deadline is invalid.") from exc
    return text


def validate_capability_context(context: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(context, dict):
        raise ValueError("Capability context must be a mapping.")
    safe = {
        "task_id": _text(context.get("task_id"), required=True),
        "subgoal_id": _text(context.get("subgoal_id"), required=True),
        "application_id": _text(context.get("application_id"), required=True),
        "capability_id": _text(context.get("capability_id"), required=True),
        "tool_name": _text(context.get("tool_name"), required=True),
        "target": _text(context.get("target")),
        "session_id": _text(context.get("session_id")),
        "page_id": _text(context.get("page_id")),
        "window_identity": _text(context.get("window_identity")),
        "observation_id": _text(context.get("observation_id")),
        "evidence_refs": _list(context.get("evidence_refs")),
        "evidence_hash": _text(context.get("evidence_hash")),
        "freshness_deadline": _deadline(context.get("freshness_deadline")),
        "environment_fingerprint": _text(context.get("environment_fingerprint"), required=True),
    }
    if safe["application_id"] not in {"email", "workspace", "git", "browser", "desktop", "runtime", "terminal", "log", "security", "logic", "personal_data", "calendar", "comms", "attention", "job_search", "application"}:
        raise ValueError("Capability context application is not authorized.")
    if safe["application_id"] == "browser" and safe["tool_name"].startswith("browser_") and not safe["target"] and not safe["page_id"]:
        raise ValueError("Browser capability context requires a target or page identity.")
    if safe["application_id"] == "desktop" and safe["tool_name"].startswith("desktop_") and safe["tool_name"] not in {"desktop_observer"} and not safe["window_identity"]:
        raise ValueError("Desktop action capability context requires a window identity.")
    return redact_sensitive_data(safe)


def build_capability_context(*, task_id: str, subgoal_id: str, application_id: str, capability_id: str, tool_name: str, target: str = "", session_id: str = "", page_id: str = "", window_identity: str = "", observation_id: str = "", evidence_refs: list[str] | None = None, evidence: Any = None, freshness_deadline: str = "", environment_fingerprint: str) -> dict[str, Any]:
    context = {
        "task_id": task_id,
        "subgoal_id": subgoal_id,
        "application_id": application_id,
        "capability_id": capability_id,
        "tool_name": tool_name,
        "target": target,
        "session_id": session_id,
        "page_id": page_id,
        "window_identity": window_identity,
        "observation_id": observation_id,
        "evidence_refs": evidence_refs or [],
        "evidence_hash": evidence_hash(evidence) if evidence is not None else "",
        "freshness_deadline": freshness_deadline,
        "environment_fingerprint": environment_fingerprint,
    }
    return validate_capability_context(context)


def context_is_fresh(context: dict[str, Any], *, now: datetime | None = None) -> bool:
    safe = validate_capability_context(context)
    deadline = safe.get("freshness_deadline")
    if not deadline:
        return True
    expiry = datetime.fromisoformat(deadline.replace("Z", "+00:00"))
    current = now or datetime.now(timezone.utc)
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry > current


__all__ = ["build_capability_context", "context_is_fresh", "evidence_hash", "validate_capability_context"]
