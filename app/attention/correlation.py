from __future__ import annotations

import re
from typing import Any

from app.agent.task_commitments import parse_deadline
from app.attention.models import build_attention_item
from app.attention.rules import deadline_attention_state

MAX_CORRELATION_GROUPS = 50
MAX_GROUP_EVIDENCE_REFS = 12
MAX_CROSS_SOURCE_INPUT = 200

_DEDUPE_KEY_FIELDS = {
    "task_ledger": ("id",),
    "calendar_observer": ("calendar_event_id", "event_id", "id"),
    "email_observer": ("message_id", "email_id", "id"),
    "comms_observer": ("message_id", "conversation_id", "id"),
    "approval_authority": ("approval_id", "request_id", "id"),
    "approval_pending": ("approval_id", "request_id", "id"),
}

_CROSS_SOURCE_NOISE_WORDS = {
    "action",
    "approval",
    "calendar",
    "comms",
    "commitment",
    "deadline",
    "email",
    "git",
    "overdue",
    "request",
    "requested",
    "required",
    "security",
    "workspace",
}

_CROSS_SOURCE_STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "by",
    "for",
    "from",
    "has",
    "in",
    "is",
    "of",
    "on",
    "the",
    "their",
    "to",
    "with",
}

_RISK_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _dedupe_key(item: dict[str, Any]) -> str:
    source = item.get("source") or item.get("source_type") or item.get("category") or "item"
    identity = ""
    for field in _DEDUPE_KEY_FIELDS.get(source, ("id", "attention_id")):
        value = item.get(field) or item.get("reference") or ""
        if value:
            identity = str(value)
            break
    if not identity:
        identity = str(item.get("attention_id") or item.get("title") or item.get("subject") or "")
    return f"{source}:{identity}"


def _bounded_refs(refs: list[Any] | None, limit: int = MAX_GROUP_EVIDENCE_REFS) -> list[dict[str, Any]]:
    safe: list[dict[str, Any]] = []
    for ref in (refs or []):
        if isinstance(ref, dict):
            safe.append({str(k): str(v) for k, v in ref.items()})
        else:
            safe.append({"source": str(ref)})
        if len(safe) >= limit:
            break
    return safe


def _merge_items(group: list[dict[str, Any]]) -> dict[str, Any]:
    priorities = {item.get("priority") for item in group}
    urgencies = {item.get("urgency") for item in group}
    _ORDER_P = ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    _ORDER_U = ("NONE", "LATER", "SOON", "TODAY", "IMMEDIATE")
    priority = max(priorities, key=lambda p: _ORDER_P.index(p) if p in _ORDER_P else 0)
    urgency = max(urgencies, key=lambda u: _ORDER_U.index(u) if u in _ORDER_U else 0)

    first = group[0]
    sources = sorted({str(item.get("source") or item.get("source_type") or "") for item in group if item.get("source") or item.get("source_type")})
    merged = dict(first)
    merged.update(
        {
            "attention_id": first.get("attention_id") or first.get("id") or f"attn-group-{len(group)}",
            "priority": priority,
            "urgency": urgency,
            "sources": sources,
            "source": ",".join(sources) or first.get("source", ""),
            "source_count": len(group),
            "evidence_refs": _bounded_refs(
                [item.get("evidence_ref") or item.get("evidence_refs") for item in group if item.get("evidence_ref") or item.get("evidence_refs")]
            ),
            "related_ids": sorted({str(item.get("id") or item.get("message_id") or item.get("attention_id") or "") for item in group if item.get("id") or item.get("message_id") or item.get("attention_id")})[
                :12
            ],
        }
    )
    if "conflicts" not in merged:
        merged["conflicts"] = []
    return merged


def correlate_attention_items(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Group attention items that refer to the same underlying event or message.

    Only identity is deduplicated: two records with the same source and the same
    stable reference (message id, event id, task id) are collapsed into one group.
    Conflicting evidence is preserved rather than reconciled.
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    for item in (items or []):
        key = _dedupe_key(item)
        groups.setdefault(key, []).append(item)

    correlated: list[dict[str, Any]] = []
    for key, members in groups.items():
        if not members:
            continue
        if len(members) == 1:
            correlated.append(members[0])
            continue
        correlated.append(_merge_items(members))
        if len(correlated) >= MAX_CORRELATION_GROUPS:
            break

    return {
        "correlated_items": correlated,
        "group_count": len(correlated),
        "total_items_seen": len(items or []),
        "bounded": {"group_limit": MAX_CORRELATION_GROUPS},
    }


def _deadline_key(value: Any) -> str:
    try:
        parsed = parse_deadline(str(value or ""))
    except ValueError:
        return ""
    return parsed.isoformat() if parsed else ""


def _subject_key(*values: Any) -> str:
    tokens: list[str] = []
    for value in values:
        for token in re.findall(r"[a-z0-9]+", str(value or "").lower()):
            if token in _CROSS_SOURCE_STOPWORDS or token in _CROSS_SOURCE_NOISE_WORDS or len(token) < 3:
                continue
            if token not in tokens:
                tokens.append(token)
    if len(tokens) < 2:
        return ""
    return "|".join(tokens[:8])


def _cross_source_keys(item: dict[str, Any]) -> set[str]:
    deadline = _deadline_key(item.get("deadline") or item.get("meeting_time") or item.get("start_time") or "")
    keys: set[str] = set()
    if deadline:
        keys.add("d:" + deadline)
    subject = _subject_key(item.get("title"), item.get("summary"), item.get("subject"))
    if subject:
        keys.add("s:" + subject)
    referenced = list(item.get("related_ids") or []) + [item.get("source_reference")]
    for ref in referenced:
        ref_text = str(ref or "").strip()
        if ref_text:
            keys.add("r:" + ref_text[:200])
    return keys


def _highest_member(members: list[dict[str, Any]]) -> dict[str, Any]:
    _ORDER_P = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    _ORDER_U = {"NONE": 0, "LATER": 1, "SOON": 2, "TODAY": 3, "IMMEDIATE": 4}
    best = members[0]
    for member in members[1:]:
        if (_ORDER_P.get(member.get("priority"), 0), _ORDER_U.get(member.get("urgency"), 0)) > (
            _ORDER_P.get(best.get("priority"), 0),
            _ORDER_U.get(best.get("urgency"), 0),
        ):
            best = member
    return best


def _merge_cross_source(members: list[dict[str, Any]], *, now: Any = None) -> dict[str, Any]:
    """Merge records that describe the same deadline, subject, or identity."""

    best = _highest_member(members)
    best_priority = str(best.get("priority") or "LOW").upper()

    sources = sorted({str(item.get("source") or "") for item in members if str(item.get("source") or "")})
    related: list[str] = []
    for member in members:
        for ref in member.get("related_ids") or []:
            ref_text = str(ref or "").strip()
            if ref_text and ref_text not in related:
                related.append(ref_text)

    evidence: list[Any] = []
    for member in members:
        refs = member.get("evidence_refs") or member.get("evidence_ref") or []
        if isinstance(refs, dict):
            refs = [refs]
        for ref in list(refs)[:MAX_GROUP_EVIDENCE_REFS]:
            if ref not in evidence:
                evidence.append(ref)
        if len(evidence) >= MAX_GROUP_EVIDENCE_REFS:
            break

    deadlines = [str(item.get("deadline") or item.get("meeting_time") or item.get("start_time") or "").strip() for item in members]
    distinct_deadlines: list[str] = []
    for value in deadlines:
        if value and value not in distinct_deadlines:
            distinct_deadlines.append(value)

    deadline = ""
    deadline_state = ""
    if distinct_deadlines:
        overdue = [value for value in distinct_deadlines if deadline_attention_state(value, "MEDIUM", now=now)[0] == "OVERDUE"]
        if overdue:
            deadline = overdue[0]
        else:
            def _sort_time(value: str) -> tuple[int, str]:
                key = _deadline_key(value)
                return (0, key) if key else (1, value)
            deadline = sorted(distinct_deadlines, key=_sort_time)[0]
        deadline_state, _ = deadline_attention_state(deadline, "MEDIUM", now=now)

    deadline_confidence = "HIGH" if any(str(item.get("deadline_confidence") or item.get("confidence") or "").upper() == "HIGH" for item in members) else "MEDIUM"

    untrusted = any(bool(item.get("untrusted_content") or item.get("untrusted")) for item in members)
    approval_required = any(bool(item.get("approval_required")) for item in members)
    blocked = any(bool(item.get("blocked")) for item in members)
    risk_level = max(
        (str(item.get("risk_level") or "NONE").upper() for item in members),
        key=lambda value: _RISK_ORDER.get(value, 0),
    )

    conflicts: list[dict[str, Any]] = []
    for member in members:
        for conflict in member.get("conflicts") or []:
            if conflict not in conflicts:
                conflicts.append(conflict)
    if len(distinct_deadlines) > 1:
        conflicts.append({
            "type": "deadline_discrepancy",
            "sources": sources,
            "values": distinct_deadlines[:6],
        })

    summaries: list[str] = []
    for member in members:
        text = str(member.get("summary") or "").strip()
        if text and text not in summaries:
            summaries.append(text)

    category = str(best.get("category") or "task").lower()
    if deadline_state and category in {
        "deadline",
        "due_soon",
        "overdue",
        "meeting",
        "calendar",
        "email_action",
        "comms_action",
        "commitment",
        "task",
    }:
        category = deadline_state.lower() if deadline_state in {"OVERDUE", "DUE_SOON"} else ("deadline" if deadline_state == "UPCOMING" else category)

    return build_attention_item(
        **{
            "attention_id": str(best.get("attention_id") or best.get("id") or f"attn-group-{len(members)}"),
            "category": category,
            "title": str(best.get("title") or "Cross-application attention item"),
            "summary": (" | ".join(summaries[:4])) or str(best.get("summary") or ""),
            "priority": best_priority,
            "urgency": str(best.get("urgency") or "NONE").upper(),
            "confidence": str(best.get("confidence") or "MEDIUM"),
            "status": str(best.get("status") or "OPEN"),
            "source": ",".join(sources) or str(best.get("source") or ""),
            "source_reference": str(best.get("source_reference") or ""),
            "source_refs": sources,
            "sources": sources,
            "source_count": len(members),
            "related_ids": related[:24],
            "deadline": deadline,
            "deadline_state": deadline_state,
            "deadline_confidence": deadline_confidence,
            "reason": str(best.get("reason") or "correlated across attention sources"),
            "explanation": str(best.get("explanation") or ""),
            "recommended_next_step": str(best.get("recommended_next_step") or ""),
            "blocked": blocked,
            "blocked_reason": str(best.get("blocked_reason") or ""),
            "requires_user_attention": any(bool(item.get("requires_user_attention")) for item in members) or best_priority in {"CRITICAL", "HIGH", "MEDIUM"},
            "consequential_action_possible": any(bool(item.get("consequential_action_possible")) for item in members),
            "approval_required": approval_required,
            "risk_level": risk_level or "NONE",
            "untrusted_content": untrusted,
            "evidence_refs": [ref if isinstance(ref, str) else str(ref) for ref in evidence],
            "conflicts": conflicts,
            "observed_at": min((str(item.get("observed_at") or "") for item in members if item.get("observed_at")), default=""),
        }
    )


def cross_source_correlate_items(items: list[dict[str, Any]], *, now: Any = None) -> dict[str, Any]:
    """Group attention records that refer to the same deadline, subject, or related identity.

    Grouping is fully deterministic: two records share a key when they resolve to
    the same normalized deadline timestamp, to the same normalized subject tokens,
    or to the same referenced identity. Conflicting deadlines are preserved inside
    each merged group as structured conflicts rather than reconciled away.
    """
    ordered = list(items or [])[:MAX_CROSS_SOURCE_INPUT]
    count = len(ordered)
    parent = list(range(count))

    def _find(node: int) -> int:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def _union(left: int, right: int) -> None:
        root_left, root_right = _find(left), _find(right)
        if root_left != root_right:
            if root_left < root_right:
                parent[root_right] = root_left
            else:
                parent[root_left] = root_right

    keys = [_cross_source_keys(item) for item in ordered]
    for left in range(count):
        for right in range(left + 1, count):
            if keys[left] & keys[right]:
                _union(left, right)

    components: dict[int, list[dict[str, Any]]] = {}
    for index in range(count):
        components.setdefault(_find(index), []).append(ordered[index])

    grouped: list[dict[str, Any]] = []
    for root in sorted(components):
        members = components[root]
        if len(members) == 1:
            grouped.append(members[0])
            continue
        grouped.append(_merge_cross_source(members, now=now))
        if len(grouped) >= MAX_CORRELATION_GROUPS:
            break

    return {
        "correlated_items": grouped,
        "group_count": len(grouped),
        "total_items_seen": count,
        "bounded": {"group_limit": MAX_CORRELATION_GROUPS, "correlation": "cross_source"},
    }


__all__ = [
    "MAX_CORRELATION_GROUPS",
    "correlate_attention_items",
    "cross_source_correlate_items",
]