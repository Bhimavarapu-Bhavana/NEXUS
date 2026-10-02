from __future__ import annotations

from typing import Any

from app.security.sensitive_data import redact_sensitive_data, redact_text

ATTENTION_PRIORITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
ATTENTION_URGENCIES = ("IMMEDIATE", "TODAY", "SOON", "LATER", "NONE")
ATTENTION_CONFIDENCES = ("HIGH", "MEDIUM", "LOW")
ATTENTION_CATEGORIES = (
    "deadline",
    "commitment",
    "overdue",
    "due_soon",
    "task",
    "blocked",
    "approval",
    "recovery",
    "security",
    "calendar",
    "meeting",
    "email",
    "email_action",
    "comms",
    "comms_action",
    "follow_up",
    "unanswered",
    "conflict",
    "git",
    "workspace",
    "document",
    "informational",
)
ATTENTION_SOURCES = (
    "task_ledger",
    "calendar_observer",
    "email_observer",
    "comms_observer",
    "git_inspector",
    "workspace_observer",
    "document_observer",
    "approval_authority",
    "security_events",
    "approval_pending",
    "runtime_recovery",
    "attention_rule_engine",
)
ATTENTION_DEADLINE_STATES = ("NONE", "UPCOMING", "DUE_SOON", "OVERDUE", "INVALID")

MAX_ATTENTION_ITEMS = 50
MAX_ATTENTION_ITEM_CHARS = 2000
MAX_ATTENTION_TITLE_CHARS = 200
MAX_ATTENTION_SUMMARY_CHARS = 600
MAX_ATTENTION_EVIDENCE_REFS = 12
MAX_ATTENTION_SOURCE_REFS = 64
MAX_ATTENTION_RELATED_IDS = 24
MAX_ATTENTION_CONFLICTS = 12
MAX_ATTENTION_REASON_CHARS = 400
MAX_ATTENTION_EXPLANATION_CHARS = 800
MAX_ATTENTION_NEXT_STEP_CHARS = 600
MAX_ATTENTION_SOURCES_BOUND = 12
MAX_ATTENTION_RISK_CHARS = 32
MAX_ATTENTION_DEADLINE_CONFIDENCE_CHARS = 16


def _bounded(value: Any, limit: int) -> str:
    return str(redact_text(value or ""))[:limit]


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def validate_attention_priority(value: Any) -> str:
    normalized = str(value or "").upper()
    if normalized not in ATTENTION_PRIORITIES:
        raise ValueError("Attention priority must be CRITICAL, HIGH, MEDIUM, LOW, or INFORMATIONAL.")
    return normalized


def validate_attention_urgency(value: Any) -> str:
    normalized = str(value or "").upper()
    if normalized not in ATTENTION_URGENCIES:
        raise ValueError("Attention urgency must be IMMEDIATE, TODAY, SOON, LATER, or NONE.")
    return normalized


def validate_attention_confidence(value: Any) -> str:
    normalized = str(value or "MEDIUM").upper()
    if normalized not in ATTENTION_CONFIDENCES:
        raise ValueError("Attention confidence must be HIGH, MEDIUM, or LOW.")
    return normalized


def validate_attention_item(item: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("An attention item must be a mapping.")
    safe = redact_sensitive_data(item)
    category = str(safe.get("category") or "").strip().lower()
    if not category:
        raise ValueError("An attention item requires a category.")
    priority = validate_attention_priority(safe.get("priority"))
    urgency = validate_attention_urgency(safe.get("urgency"))
    title = _bounded(safe.get("title"), MAX_ATTENTION_TITLE_CHARS)
    if not title:
        title = _bounded(safe.get("summary"), MAX_ATTENTION_TITLE_CHARS)
    if not title:
        raise ValueError("An attention item requires a bounded title or summary.")
    observed_at = str(safe.get("observed_at") or "")
    if not observed_at:
        raise ValueError("An attention item requires an observation timestamp.")
    return {
        "attention_id": str(safe.get("attention_id") or ""),
        "category": category,
        "title": title,
        "summary": _bounded(safe.get("summary"), MAX_ATTENTION_SUMMARY_CHARS) if safe.get("summary") else title,
        "priority": priority,
        "urgency": urgency,
        "confidence": validate_attention_confidence(safe.get("confidence")),
        "status": str(safe.get("status") or "OPEN").upper(),
        "source": str(safe.get("source") or ""),
        "source_reference": str(safe.get("source_reference") or ""),
        "evidence_refs": [str(redact_text(x))[:300] for x in (safe.get("evidence_refs") or [])][:MAX_ATTENTION_EVIDENCE_REFS],
        "related_ids": [str(redact_text(x))[:300] for x in (safe.get("related_ids") or [])][:MAX_ATTENTION_RELATED_IDS],
        "deadline": str(safe.get("deadline") or ""),
        "deadline_state": str(safe.get("deadline_state") or "NONE").upper(),
        "reason": _bounded(safe.get("reason"), MAX_ATTENTION_REASON_CHARS),
        "explanation": _bounded(safe.get("explanation"), MAX_ATTENTION_EXPLANATION_CHARS),
        "recommended_next_step": _bounded(safe.get("recommended_next_step"), MAX_ATTENTION_NEXT_STEP_CHARS),
        "blocked": bool(safe.get("blocked", False)),
        "blocked_reason": _bounded(safe.get("blocked_reason"), MAX_ATTENTION_REASON_CHARS),
        "requires_user_attention": bool(safe.get("requires_user_attention", priority in {"CRITICAL", "HIGH", "MEDIUM"})),
        "consequential_action_possible": bool(safe.get("consequential_action_possible", False)),
        "approval_required": bool(safe.get("approval_required", False)),
        "risk_level": _bounded(safe.get("risk_level") or "NONE", MAX_ATTENTION_RISK_CHARS).upper() or "NONE",
        "deadline_confidence": _bounded(validate_attention_confidence(safe.get("deadline_confidence")), MAX_ATTENTION_DEADLINE_CONFIDENCE_CHARS).upper(),
        "untrusted_content": bool(safe.get("untrusted_content", False)),
        "sources": [str(redact_text(x))[:300] for x in (safe.get("sources") or ([str(safe.get("source") or "")] if safe.get("source") else []))][:MAX_ATTENTION_SOURCES_BOUND],
        "source_count": max(0, int(safe.get("source_count") or (1 if safe.get("source") else 0))),
        "conflicts": list(safe.get("conflicts") or [])[:MAX_ATTENTION_CONFLICTS],
        "observed_at": observed_at,
        "provenance": {"origin": "attention_engine", "read_only": True, "observed_at": observed_at},
    }


def build_attention_item(
    *,
    attention_id: str = "",
    category: str,
    title: str,
    summary: str = "",
    priority: str,
    urgency: str = "NONE",
    confidence: str = "MEDIUM",
    status: str = "OPEN",
    source: str = "",
    source_reference: str = "",
    source_refs: list[str] | None = None,
    related_ids: list[str] | None = None,
    deadline: str = "",
    deadline_state: str = "NONE",
    reason: str = "",
    explanation: str = "",
    recommended_next_step: str = "",
    blocked: bool = False,
    blocked_reason: str = "",
    requires_user_attention: bool | None = None,
    consequential_action_possible: bool = False,
    approval_required: bool = False,
    risk_level: str = "NONE",
    deadline_confidence: str = "",
    untrusted_content: bool = False,
    sources: list[str] | None = None,
    source_count: int = 0,
    conflicts: list[Any] | None = None,
    evidence_refs: list[str] | None = None,
    observed_at: str = "",
) -> dict[str, Any]:
    if requires_user_attention is None:
        requires_user_attention = str(priority or "LOW").upper() in {"CRITICAL", "HIGH", "MEDIUM"}
    item = redact_sensitive_data({
        "attention_id": str(attention_id or "") or f"attn-{str(hash(title + summary + source))[-8:]}",
        "category": str(category or "").strip().lower(),
        "title": title,
        "summary": summary or title,
        "priority": str(priority or "LOW").upper(),
        "urgency": str(urgency or "NONE").upper(),
        "confidence": str(confidence or "MEDIUM").upper(),
        "status": str(status or "OPEN").upper(),
        "source": str(source or ""),
        "source_reference": str(source_reference or ""),
        "source_refs": list(source_refs or []),
        "related_ids": list(related_ids or []),
        "deadline": str(deadline or ""),
        "deadline_state": str(deadline_state or "NONE").upper(),
        "reason": reason,
        "explanation": explanation,
        "recommended_next_step": recommended_next_step,
        "blocked": bool(blocked),
        "blocked_reason": blocked_reason,
        "requires_user_attention": bool(requires_user_attention),
        "consequential_action_possible": bool(consequential_action_possible),
        "approval_required": bool(approval_required),
        "risk_level": str(risk_level or "NONE"),
        "deadline_confidence": str(deadline_confidence or "MEDIUM"),
        "untrusted_content": bool(untrusted_content),
        "sources": list(sources or []),
        "source_count": int(source_count or 0),
        "conflicts": list(conflicts or []),
        "evidence_refs": list(evidence_refs or []),
        "observed_at": observed_at or _now_iso(),
    })
    return validate_attention_item(item)


def attention_snapshot(
    *,
    items: list[dict[str, Any]] | None = None,
    counts: dict[str, Any] | None = None,
    system_health: dict[str, Any] | None = None,
    security_attention: list[dict[str, Any]] | None = None,
    provenance: dict[str, Any] | None = None,
    generated_at: str = "",
) -> dict[str, Any]:
    from datetime import datetime, timezone

    safe_items = [validate_attention_item(item) for item in (items or [])][:MAX_ATTENTION_ITEMS]
    summary_counts = dict(counts or {})
    reports = [
        {
            "_category": "attention",
            "attention_id": item["attention_id"],
            "source": item["source"] or "attention_engine",
            "priority": item["priority"],
            "title": item["title"],
            "summary": item["summary"],
        }
        for item in safe_items[:12]
    ]
    return redact_sensitive_data({
        "source": "attention_engine",
        "status": "OK",
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "item_count": len(safe_items),
        "items": safe_items,
        "reports": reports,
        "counts": summary_counts,
        "system_health": system_health or {},
        "security_attention": list(security_attention or []),
        "needs_user_attention": [item["attention_id"] for item in safe_items if item.get("requires_user_attention")],
        "highest_priority": next((item["priority"] for item in safe_items if item["priority"] in {"CRITICAL", "HIGH", "MEDIUM"}), "INFORMATIONAL"),
        "bounded": {"item_limit": MAX_ATTENTION_ITEMS},
        "provenance": dict(provenance or {"origin": "attention_engine", "read_only": True}),
    })


__all__ = [
    "ATTENTION_CATEGORIES",
    "ATTENTION_CONFIDENCES",
    "ATTENTION_PRIORITIES",
    "ATTENTION_SOURCES",
    "ATTENTION_URGENCIES",
    "MAX_ATTENTION_ITEMS",
    "attention_snapshot",
    "build_attention_item",
    "validate_attention_item",
]
