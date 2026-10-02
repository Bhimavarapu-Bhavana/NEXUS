from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from app.agent.approval_authority import list_pending_approvals
from app.attention.correlation import correlate_attention_items, cross_source_correlate_items
from app.attention.models import (
    MAX_ATTENTION_ITEMS,
    attention_snapshot,
    build_attention_item,
    validate_attention_item,
)
from app.attention.rules import (
    approval_attention_state,
    calendar_event_attention_state,
    deadline_attention_state,
    informational_density_state,
    max_priority,
    security_attention_state,
    task_attention_state,
)

_PRIORITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}
_URGENCY_ORDER = {"IMMEDIATE": 4, "TODAY": 3, "SOON": 2, "LATER": 1, "NONE": 0}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _deadline_of(item: dict[str, Any]) -> str:
    return str(item.get("deadline") or item.get("meeting_time") or item.get("start_time") or "").strip()


def _hash_id(*parts: str) -> str:
    return "attn-" + str(hash("|".join(parts)))[-10:] if any(parts) else ""


def _task_items(tasks: list[dict[str, Any]], *, now: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for task in (tasks or []):
        key = str(task.get("id") or task.get("task_id") or task.get("title") or "")
        if not key:
            continue
        deadline = _deadline_of(task)
        deadline_state = ""
        deadline_confidence = str(task.get("deadline_confidence") or task.get("confidence") or "MEDIUM")
        if deadline:
            deadline_state, _ = deadline_attention_state(deadline, deadline_confidence, now=now)
        blocked = bool(task.get("blocked") or task.get("is_blocked") or task.get("blocked_by"))
        blocked_reason = str(task.get("blocked_reason") or "")
        if blocked and not blocked_reason and (task.get("dependencies") or task.get("blocked_by")):
            blocked_reason = "Task is blocked by one or more unfinished dependencies."
        approval_pending = str(task.get("status") or "").upper() == "WAITING_APPROVAL"
        priority, urgency, _, _, requires_user = task_attention_state(
            priority=task.get("priority"),
            status=task.get("status"),
            deadline=deadline,
            deadline_state=deadline_state,
            confidence=deadline_confidence,
            blocked=blocked,
            needs_user_attention=bool(task.get("needs_user_attention") or task.get("requires_user_attention")),
            consequential=bool(task.get("consequential_action_possible") or task.get("consequential")),
            now=now,
        )
        if deadline_state == "OVERDUE":
            category = "overdue"
        elif deadline_state == "DUE_SOON":
            category = "due_soon"
        elif blocked:
            category = "blocked"
        else:
            category = "task"
        summary = str(task.get("summary") or task.get("description") or "").strip()
        if blocked and not summary:
            summary = blocked_reason
        next_step = ""
        if blocked:
            next_step = "Resolve the blocking dependency or update the task plan."
        elif deadline_state in {"OVERDUE", "DUE_SOON"}:
            next_step = f"Address the {deadline_state.lower()} deadline with current evidence."
        items.append(
            build_attention_item(
                category=category,
                title=str(task.get("title") or task.get("summary") or key),
                summary=summary or str(task.get("title") or key),
                priority=priority,
                urgency=urgency,
                confidence=deadline_confidence,
                status=str(task.get("status") or "OPEN"),
                source="task_ledger",
                source_reference=str(key),
                source_refs=[str(key)],
                related_ids=[str(key)],
                deadline=deadline,
                deadline_state=deadline_state,
                deadline_confidence=deadline_confidence,
                reason=f"task status {task.get('status')} maps to {(priority, urgency)}",
                recommended_next_step=next_step,
                blocked=blocked,
                blocked_reason=blocked_reason,
                approval_required=approval_pending,
                risk_level="MEDIUM" if approval_pending else "NONE",
                requires_user_attention=requires_user,
                observed_at=_now_iso(),
            )
        )
    return items


def _calendar_items(calendar_observatory: dict[str, Any], *, now: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    events = list((calendar_observatory or {}).get("events") or [])
    for event in events:
        if not isinstance(event, dict):
            continue
        event_id = str(event.get("event_id") or event.get("id") or event.get("title") or "")
        if not event_id:
            continue
        deadline = _deadline_of(event)
        deadline_confidence = str(event.get("deadline_confidence") or event.get("confidence") or "MEDIUM")
        deadline_state, _ = deadline_attention_state(deadline, deadline_confidence, now=now)
        priority, urgency = calendar_event_attention_state(event, now=now)
        if event.get("is_deadline") and deadline_state in {"OVERDUE", "DUE_SOON", "UPCOMING"}:
            priority = priority or "MEDIUM"
            urgency = urgency or "SOON"
        next_step = ""
        if event.get("is_deadline") and deadline_state in {"OVERDUE", "DUE_SOON", "UPCOMING"}:
            next_step = f"Prepare for the {deadline_state.lower()} calendar deadline: {event.get('title')}."
        items.append(
            build_attention_item(
                category="deadline" if event.get("is_deadline") else "meeting",
                title=str(event.get("title") or "Calendar event"),
                summary=str(event.get("summary") or event.get("description") or event.get("title") or ""),
                priority=priority,
                urgency=urgency,
                confidence=deadline_confidence,
                status=str(event.get("status") or "CONFIRMED"),
                source="calendar_observer",
                source_reference=str(event_id),
                source_refs=[str(event_id)],
                related_ids=[str(event_id)],
                deadline=deadline,
                deadline_state=deadline_state,
                deadline_confidence=deadline_confidence,
                untrusted_content=bool(event.get("untrusted")),
                reason="calendar event is a tracked deadline" if event.get("is_deadline") else "scheduled calendar event",
                recommended_next_step=next_step,
                requires_user_attention=priority in {"CRITICAL", "HIGH", "MEDIUM"},
                observed_at=_now_iso(),
            )
        )
    return items


def _email_items(email_observatory: dict[str, Any], *, now: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    action_required = list((email_observatory or {}).get("action_required") or [])
    deadlines = list((email_observatory or {}).get("deadlines") or [])
    for record in action_required:
        if not isinstance(record, dict):
            continue
        message_id = str(record.get("message_id") or record.get("id") or record.get("thread_id") or record.get("subject") or "")
        if not message_id:
            continue
        deadline = _deadline_of(record)
        deadline_confidence = str(record.get("deadline_confidence") or record.get("confidence") or "MEDIUM")
        deadline_state = ""
        if deadline:
            deadline_state, _ = deadline_attention_state(deadline, deadline_confidence, now=now)
        priority = "HIGH" if deadline_state in {"OVERDUE", "DUE_SOON"} else ("MEDIUM" if record.get("action_required") else "LOW")
        urgency = "TODAY" if deadline_state == "OVERDUE" else ("SOON" if deadline_state == "DUE_SOON" else "NONE")
        items.append(
            build_attention_item(
                category="email_action",
                title=f"Action required: {record.get('subject') or record.get('summary') or message_id}",
                summary=str(record.get("summary") or record.get("subject") or message_id),
                priority=priority,
                urgency=urgency,
                confidence=deadline_confidence,
                status="ACTION_REQUIRED",
                source="email_observer",
                source_reference=str(message_id),
                source_refs=[str(message_id)],
                related_ids=[str(record.get("thread_id") or message_id)],
                deadline=deadline,
                deadline_state=deadline_state,
                deadline_confidence=deadline_confidence,
                untrusted_content=bool(record.get("untrusted")),
                reason="email requests a reply or action",
                recommended_next_step="Reply to the email or complete the requested action with current evidence.",
                requires_user_attention=True,
                observed_at=_now_iso(),
            )
        )
    for record in deadlines:
        if not isinstance(record, dict):
            continue
        message_id = str(record.get("message_id") or record.get("id") or record.get("thread_id") or record.get("sender") or "")
        deadline = _deadline_of(record)
        deadline_confidence = str(record.get("deadline_confidence") or record.get("confidence") or "MEDIUM")
        deadline_state = ""
        if deadline:
            deadline_state, _ = deadline_attention_state(deadline, deadline_confidence, now=now)
        if deadline_state not in {"OVERDUE", "DUE_SOON", "UPCOMING"}:
            continue
        items.append(
            build_attention_item(
                category="deadline",
                title=f"Deadline from email: {record.get('summary') or record.get('subject') or 'email deadline'}",
                summary=str(record.get("summary") or record.get("subject") or "email deadline"),
                priority=("CRITICAL" if deadline_state in {"OVERDUE", "DUE_SOON"} else "MEDIUM"),
                urgency="TODAY" if deadline_state == "OVERDUE" else ("SOON" if deadline_state in {"DUE_SOON", "UPCOMING"} else "NONE"),
                confidence=deadline_confidence,
                status="ACTION_REQUIRED",
                source="email_observer",
                source_reference=f"deadline:{message_id}",
                source_refs=[f"deadline:{message_id}"],
                related_ids=[str(record.get("thread_id") or message_id)],
                deadline=deadline,
                deadline_state=deadline_state,
                deadline_confidence=deadline_confidence,
                untrusted_content=bool(record.get("untrusted")),
                reason="email contains a tracked deadline",
                recommended_next_step=f"Prepare for the {deadline_state.lower()} email deadline before it lapses.",
                requires_user_attention=True,
                observed_at=_now_iso(),
            )
        )
    for record in list((email_observatory or {}).get("commitments") or []):
        item = _record_item(record, category="commitment", label="Committed in email", source="email_observer", now=now, reason="email contains an explicit commitment")
        if item:
            items.append(item)
    for record in list((email_observatory or {}).get("follow_ups") or []):
        item = _record_item(record, category="follow_up", label="Email follow-up", source="email_observer", now=now, reason="email requires a follow-up")
        if item:
            items.append(item)
    for record in list((email_observatory or {}).get("unanswered") or []):
        item = _record_item(record, category="unanswered", label="Unanswered email", source="email_observer", now=now, reason="email contains an unanswered question")
        if item:
            items.append(item)
    return items


def _record_item(record: dict[str, Any], *, category: str, label: str, source: str, now: Any, reason: str) -> dict[str, Any]:
    if not isinstance(record, dict):
        return {}
    message_id = str(record.get("message_id") or record.get("conversation_id") or record.get("id") or record.get("thread_id") or record.get("subject") or "")
    if not message_id:
        return {}
    deadline = _deadline_of(record)
    deadline_confidence = str(record.get("deadline_confidence") or record.get("confidence") or "MEDIUM")
    deadline_state = ""
    if deadline:
        deadline_state, _ = deadline_attention_state(deadline, deadline_confidence, now=now)
    priority = "HIGH" if deadline_state in {"OVERDUE", "DUE_SOON"} else ("MEDIUM")
    urgency = "TODAY" if deadline_state == "OVERDUE" else ("SOON" if deadline_state in {"DUE_SOON", "UPCOMING"} else ("LATER" if category == "follow_up" else "SOON"))
    return build_attention_item(
        category=category,
        title=f"{label}: {record.get('summary') or record.get('subject') or message_id}",
        summary=str(record.get("summary") or record.get("subject") or message_id),
        priority=priority,
        urgency=urgency,
        confidence=deadline_confidence,
        status="ACTION_REQUIRED",
        source=source,
        source_reference=str(message_id),
        source_refs=[str(message_id)],
        related_ids=[str(record.get("thread_id") or message_id)],
        deadline=deadline,
        deadline_state=deadline_state,
        deadline_confidence=deadline_confidence,
        untrusted_content=bool(record.get("untrusted")),
        reason=reason,
        recommended_next_step=f"Review the {category.replace('_', ' ')} and respond with current evidence.",
        requires_user_attention=True,
        observed_at=_now_iso(),
    )


def _comms_items(comms_observatory: dict[str, Any], *, now: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for record in (list((comms_observatory or {}).get("action_required") or []) + list((comms_observatory or {}).get("requests") or [])):
        if not isinstance(record, dict):
            continue
        message_id = str(record.get("message_id") or record.get("conversation_id") or record.get("id") or record.get("summary") or "")
        deadline = _deadline_of(record)
        deadline_confidence = str(record.get("deadline_confidence") or record.get("confidence") or "MEDIUM")
        deadline_state = ""
        if deadline:
            deadline_state, _ = deadline_attention_state(deadline, deadline_confidence, now=now)
        priority = "HIGH" if deadline_state in {"OVERDUE", "DUE_SOON"} else ("MEDIUM" if record.get("action_required") or record.get("request") else "LOW")
        urgency = "TODAY" if deadline_state == "OVERDUE" else ("SOON" if deadline_state == "DUE_SOON" else "NONE")
        items.append(
            build_attention_item(
                category="comms_action",
                title=f"Comms request: {record.get('summary') or record.get('subject') or message_id}",
                summary=str(record.get("summary") or record.get("subject") or message_id),
                priority=priority,
                urgency=urgency,
                confidence=deadline_confidence,
                status="ACTION_REQUIRED",
                source="comms_observer",
                source_reference=str(message_id),
                source_refs=[str(message_id)],
                related_ids=[str(record.get("thread_id") or message_id)],
                deadline=deadline,
                deadline_state=deadline_state,
                deadline_confidence=deadline_confidence,
                untrusted_content=bool(record.get("untrusted")),
                reason="communication requests a reply or action",
                recommended_next_step="Reply to the communication request with current evidence.",
                requires_user_attention=True,
                observed_at=_now_iso(),
            )
        )
    for record in list((comms_observatory or {}).get("deadlines") or []):
        if not isinstance(record, dict):
            continue
        message_id = str(record.get("message_id") or record.get("conversation_id") or record.get("id") or record.get("summary") or "")
        deadline = _deadline_of(record)
        deadline_confidence = str(record.get("deadline_confidence") or record.get("confidence") or "MEDIUM")
        deadline_state = ""
        if deadline:
            deadline_state, _ = deadline_attention_state(deadline, deadline_confidence, now=now)
        if deadline_state not in {"OVERDUE", "DUE_SOON", "UPCOMING"}:
            continue
        items.append(
            build_attention_item(
                category="deadline",
                title=f"Deadline from comms: {record.get('summary') or record.get('subject') or 'comms deadline'}",
                summary=str(record.get("summary") or record.get("subject") or "comms deadline"),
                priority="CRITICAL" if deadline_state in {"OVERDUE", "DUE_SOON"} else "MEDIUM",
                urgency="TODAY" if deadline_state == "OVERDUE" else ("SOON" if deadline_state in {"DUE_SOON", "UPCOMING"} else "NONE"),
                confidence=deadline_confidence,
                status="ACTION_REQUIRED",
                source="comms_observer",
                source_reference=f"deadline:{message_id}",
                source_refs=[f"deadline:{message_id}"],
                related_ids=[str(record.get("thread_id") or message_id)],
                deadline=deadline,
                deadline_state=deadline_state,
                deadline_confidence=deadline_confidence,
                untrusted_content=bool(record.get("untrusted")),
                reason="communication contains a tracked deadline",
                recommended_next_step=f"Prepare for the {deadline_state.lower()} comms deadline before it lapses.",
                requires_user_attention=True,
                observed_at=_now_iso(),
            )
        )
    for record in list((comms_observatory or {}).get("commitments") or []):
        item = _record_item(record, category="commitment", label="Committed in comms", source="comms_observer", now=now, reason="communication contains an explicit commitment")
        if item:
            items.append(item)
    for record in list((comms_observatory or {}).get("meetings") or []):
        item = _record_item(record, category="meeting", label="Meeting from comms", source="comms_observer", now=now, reason="communication schedules a meeting")
        if item:
            items.append(item)
    for record in list((comms_observatory or {}).get("follow_ups") or []):
        item = _record_item(record, category="follow_up", label="Comms follow-up", source="comms_observer", now=now, reason="communication requires a follow-up")
        if item:
            items.append(item)
    for record in list((comms_observatory or {}).get("unanswered_questions") or []):
        item = _record_item(record, category="unanswered", label="Unanswered comms question", source="comms_observer", now=now, reason="communication contains an unanswered question")
        if item:
            items.append(item)
    return items


def _approval_items(approvals: list[dict[str, Any]], *, now: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for approval in (approvals or []):
        if not isinstance(approval, dict):
            continue
        approval_id = str(approval.get("approval_id") or approval.get("request_id") or approval.get("id") or approval.get("action") or "")
        if not approval_id:
            continue
        priority, urgency = approval_attention_state(approval.get("risk_level"))
        risk_level = str(approval.get("risk_level") or "MEDIUM_RISK").upper()
        expires_at = str(approval.get("expires_at") or approval.get("expiry") or "")
        deadline_state = ""
        if expires_at:
            deadline_state, _ = deadline_attention_state(expires_at, "MEDIUM", now=now)
        items.append(
            build_attention_item(
                category="approval",
                title=f"Approval requested: {approval.get('action') or approval.get('summary') or approval_id}",
                summary=str(approval.get("reason") or approval.get("summary") or approval.get("action") or ""),
                priority=priority,
                urgency=urgency,
                confidence="HIGH",
                status="PENDING_APPROVAL",
                source="approval_authority",
                source_reference=str(approval_id),
                source_refs=[str(approval_id)],
                related_ids=[str(approval_id)],
                deadline=expires_at,
                deadline_state=deadline_state,
                deadline_confidence="MEDIUM",
                approval_required=True,
                risk_level=risk_level,
                reason="human approval is pending",
                recommended_next_step="Review the pending approval and decide with current evidence.",
                requires_user_attention=True,
                consequential_action_possible=True,
                observed_at=_now_iso(),
            )
        )
    return items


def _security_items(security_events: list[dict[str, Any]], *, now: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for event in (security_events or []):
        if not isinstance(event, dict):
            continue
        severity = str(event.get("severity") or event.get("level") or "")
        if not severity:
            continue
        event_id = str(event.get("event_id") or event.get("id") or event.get("event_type") or severity)
        priority, urgency = security_attention_state(severity)
        risk_level = {
            "CRITICAL": "CRITICAL",
            "BLOCKED": "HIGH",
            "DATA_BREACH": "CRITICAL",
            "THREAT_DETECTED": "CRITICAL",
            "HIGH": "HIGH",
            "SECURITY": "HIGH",
            "MEDIUM": "MEDIUM",
            "WARNING": "MEDIUM",
        }.get(severity.upper(), "LOW")
        items.append(
            build_attention_item(
                category="security",
                title=f"Security: {event.get('event_type') or event.get('summary') or severity}",
                summary=str(event.get("summary") or event.get("detail") or event.get("event_type") or ""),
                priority=priority,
                urgency=urgency,
                confidence=str(event.get("confidence") or "HIGH"),
                status=str(event.get("status") or "DETECTED"),
                source="security_events",
                source_reference=str(event_id),
                source_refs=[str(event_id)],
                related_ids=[str(event_id)],
                risk_level=risk_level,
                reason=f"security event severity {severity}",
                recommended_next_step="Investigate the security event with current evidence.",
                requires_user_attention=priority in {"CRITICAL", "HIGH", "MEDIUM"},
                observed_at=_now_iso(),
            )
        )
    return items


def _git_items(git_status: dict[str, Any], *, now: Any) -> list[dict[str, Any]]:
    if not isinstance(git_status, dict):
        return []
    status = str(git_status.get("status") or "UNAVAILABLE")
    if status not in {"CHANGED"}:
        return []
    branch = str(git_status.get("branch") or "")
    changed_files = [str(name) for name in (git_status.get("changed_files") or []) if str(name).strip()]
    changed_count = len(changed_files)
    priority, urgency = informational_density_state(changed_count, threshold=25, soft_threshold=10)
    if changed_count >= 10:
        priority = max_priority(priority, "MEDIUM")
    title = f"Git working tree is not clean on branch {branch}." if branch else "Git working tree is not clean."
    summary = "; ".join(changed_files[:5]) if changed_files else "uncommitted changes present"
    return [
        build_attention_item(
            category="git",
            title=title,
            summary=summary,
            priority=priority,
            urgency=urgency,
            confidence="HIGH",
            status="CHANGED",
            source="git_inspector",
            source_reference=branch or "git:working_tree",
            source_refs=[branch or "git:working_tree"] + changed_files[:10],
            related_ids=[branch or "git:working_tree"],
            reason=f"git working tree contains {changed_count} uncommitted change(s)",
            recommended_next_step="Review and commit the bounded Git changes with current evidence.",
            requires_user_attention=priority in {"CRITICAL", "HIGH", "MEDIUM"},
            observed_at=_now_iso(),
        )
    ]


def _workspace_items(workspace_events: list[dict[str, Any]], *, now: Any) -> list[dict[str, Any]]:
    events = [event for event in (workspace_events or []) if isinstance(event, dict)]
    if not events:
        return []
    by_type: dict[str, int] = {}
    paths_by_type: dict[str, list[str]] = {}
    for event in events:
        event_type = str(event.get("event_type") or "FILE_MODIFIED")
        by_type[event_type] = by_type.get(event_type, 0) + 1
        path = str(event.get("path") or "")
        bucket = paths_by_type.setdefault(event_type, [])
        if path and path not in bucket and len(bucket) < 5:
            bucket.append(path)
    items: list[dict[str, Any]] = []
    for event_type in sorted(by_type):
        count = by_type[event_type]
        paths = "; ".join(paths_by_type.get(event_type, [])[:5])
        priority, urgency = informational_density_state(count, threshold=25, soft_threshold=10)
        items.append(
            build_attention_item(
                category="workspace",
                title=f"{event_type}: {count} file(s) changed in the workspace",
                summary=paths or f"{count} file(s) affected",
                priority=priority,
                urgency=urgency,
                confidence="HIGH",
                status=str(event_type),
                source="workspace_observer",
                source_reference=f"workspace:{event_type}",
                source_refs=[f"workspace:{event_type}:{path}" for path in paths_by_type.get(event_type, [])[:10]],
                reason=f"workspace monitor detected {count} {event_type.lower().replace('_', ' ')} event(s)",
                recommended_next_step="Review the changed workspace files with the workspace inspector.",
                requires_user_attention=priority in {"CRITICAL", "HIGH", "MEDIUM"},
                observed_at=_now_iso(),
            )
        )
    return items


def _document_items(document_observations: list[dict[str, Any]] | dict[str, Any] | None, *, now: Any) -> list[dict[str, Any]]:
    if isinstance(document_observations, dict):
        observations = [document_observations]
    else:
        observations = list(document_observations or [])
    items: list[dict[str, Any]] = []
    for observation in observations[:10]:
        if not isinstance(observation, dict) or observation.get("status") != "OK":
            continue
        target = str(observation.get("target") or observation.get("source_document") or "document")
        facts = observation.get("facts") or {}
        if not isinstance(facts, dict):
            continue
        for entry in (facts.get("deadlines") or [])[:3]:
            text = str(entry.get("text") if isinstance(entry, dict) else entry or "")
            match = re.search(r"\b(20\d\d[-/]\d\d[-/]\d\d)\b", text)
            if not match:
                continue
            deadline = match.group(1).replace("/", "-") + "T23:59:59+00:00"
            deadline_state, _ = deadline_attention_state(deadline, "MEDIUM", now=now)
            if deadline_state not in {"OVERDUE", "DUE_SOON", "UPCOMING"}:
                continue
            items.append(
                build_attention_item(
                    category="deadline",
                    title=f"Deadline in document: {text[:120]}",
                    summary=text,
                    priority=("CRITICAL" if deadline_state in {"OVERDUE", "DUE_SOON"} else "MEDIUM"),
                    urgency="TODAY" if deadline_state == "OVERDUE" else ("SOON" if deadline_state in {"DUE_SOON", "UPCOMING"} else "NONE"),
                    confidence="MEDIUM",
                    status="ACTION_REQUIRED",
                    source="document_observer",
                    source_reference=f"document:{target}",
                    source_refs=[f"document:{target}"],
                    related_ids=[f"document:{target}"],
                    deadline=deadline,
                    deadline_state=deadline_state,
                    deadline_confidence="MEDIUM",
                    untrusted_content=True,
                    reason="document text contains a tracked deadline",
                    recommended_next_step=f"Verify the {deadline_state.lower()} deadline in the source document with current evidence.",
                    requires_user_attention=True,
                    observed_at=_now_iso(),
                )
            )
        commitments = facts.get("commitments") or []
        action_items = facts.get("action_items") or []
        if commitments or action_items:
            proof = (commitments or action_items)[0]
            text = str(proof.get("text") if isinstance(proof, dict) else proof or "")
            items.append(
                build_attention_item(
                    category="commitment",
                    title=f"Document commitment: {target}",
                    summary=text or f"Commitments and action items exist in {target}",
                    priority="MEDIUM",
                    urgency="SOON",
                    confidence="MEDIUM",
                    status="ACTION_REQUIRED",
                    source="document_observer",
                    source_reference=f"document:{target}",
                    source_refs=[f"document:{target}"],
                    related_ids=[f"document:{target}"],
                    untrusted_content=True,
                    reason="document text contains commitments or action items",
                    recommended_next_step=f"Verify the commitment against {target} with current evidence.",
                    requires_user_attention=True,
                    observed_at=_now_iso(),
                )
            )
    return items


def _review_aggregated(aggregated: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for item in (aggregated or {}).get("correlated_items") or []:
        if isinstance(item, dict):
            merged[item.get("attention_id") or str(item)] = item
    return {"correlated_items": list(merged.values()), "group_count": len(merged), "total_items_seen": len(merged)}


def build_attention_snapshot(
    *,
    tasks: list[dict[str, Any]] | None = None,
    approvals: list[dict[str, Any]] | None = None,
    calendar_observatory: dict[str, Any] | None = None,
    email_observatory: dict[str, Any] | None = None,
    comms_observatory: dict[str, Any] | None = None,
    security_events: list[dict[str, Any]] | None = None,
    system_health: dict[str, Any] | None = None,
    git_status: dict[str, Any] | None = None,
    workspace_events: list[dict[str, Any]] | None = None,
    document_observations: list[dict[str, Any]] | dict[str, Any] | None = None,
    generated_at: str = "",
    max_items: int = MAX_ATTENTION_ITEMS,
    now: Any = None,
) -> dict[str, Any]:
    raw: list[dict[str, Any]] = []
    raw += _task_items(tasks or [], now=now)
    raw += _calendar_items(calendar_observatory or {}, now=now)
    raw += _email_items(email_observatory or {}, now=now)
    raw += _comms_items(comms_observatory or {}, now=now)
    raw += _document_items(document_observations, now=now)
    raw += _approval_items(approvals or [], now=now)
    raw += _git_items(git_status or {}, now=now)
    raw += _workspace_items(workspace_events or [], now=now)
    security_attention: list[dict[str, Any]] = []
    if security_events:
        raw += _security_items(security_events, now=now)
        security_attention = sorted(
            [item for item in raw if item.get("source") == "security_events"],
            key=lambda i: (_PRIORITY_ORDER.get(i.get("priority"), 0), _URGENCY_ORDER.get(i.get("urgency"), 0), i.get("attention_id", "")),
            reverse=True,
        )[:12]

    raw.sort(
        key=lambda i: (
            -_PRIORITY_ORDER.get(i.get("priority"), 0),
            -_URGENCY_ORDER.get(i.get("urgency"), 0),
            str(i.get("attention_id") or ""),
        )
    )
    identity_correlated = correlate_attention_items(raw)
    cross_correlated = cross_source_correlate_items(identity_correlated.get("correlated_items", []), now=now)
    merged = [validate_attention_item(item) for item in cross_correlated.get("correlated_items", [])]
    merged.sort(
        key=lambda i: (
            -_PRIORITY_ORDER.get(i.get("priority"), 0),
            -_URGENCY_ORDER.get(i.get("urgency"), 0),
            str(i.get("attention_id") or ""),
        )
    )
    merged = merged[:max_items]

    over_due = [i for i in merged if i.get("deadline_state") == "OVERDUE"]
    due_soon = [i for i in merged if i.get("deadline_state") == "DUE_SOON"]
    counts = {
        "item_count": len(merged),
        "by_priority": {p: sum(1 for i in merged if i.get("priority") == p) for p in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")},
        "by_category": {},
        "overdue": len(over_due),
        "due_soon": len(due_soon),
        "blocked": sum(1 for i in merged if i.get("blocked")),
        "requiring_user_attention": sum(1 for i in merged if i.get("requires_user_attention")),
        "pending_approvals": sum(1 for i in merged if i.get("category") == "approval"),
        "security_events": len(security_attention),
        "conflicts": sum(1 for i in merged if i.get("conflicts")),
        "cross_source_groups": int(cross_correlated.get("group_count", 0)),
        "untrusted_content": sum(1 for i in merged if i.get("untrusted_content")),
    }
    for i in merged:
        counts["by_category"][i.get("category", "")] = counts["by_category"].get(i.get("category", ""), 0) + 1

    return attention_snapshot(
        items=merged,
        counts=counts,
        system_health=system_health or {},
        security_attention=security_attention,
        generated_at=generated_at,
        provenance={"origin": "attention_engine", "read_only": True, "sources": ["task_ledger", "calendar_observer", "email_observer", "comms_observer", "document_observer", "approval_authority", "security_events", "git_inspector", "workspace_observer"], "correlation": "identity_dedupe_then_cross_source"},
    )


def summarize_attention_snapshot(snapshot: dict[str, Any], *, max_lines: int = 8) -> str:
    """Render a bounded, deterministic human-readable summary of an attention snapshot."""
    if not isinstance(snapshot, dict):
        return ""
    items = snapshot.get("items") or []
    counts = snapshot.get("counts") or {}
    if not isinstance(items, list):
        return ""
    overdue = int(counts.get("overdue", 0) or 0)
    due_soon = int(counts.get("due_soon", 0) or 0)
    pending = int(counts.get("pending_approvals", 0) or 0)
    lines = [f"NEXUS attention summary: {overdue} overdue, {due_soon} due soon, {pending} pending approval(s), {len(items)} attention item(s)."]
    for item in items[:max(1, min(int(max_lines), 12))]:
        if len(lines) - 1 >= int(max_lines):
            break
        deadline_label = f" ({item.get('deadline_state')})" if item.get("deadline_state") and item.get("deadline_state") != "NONE" else ""
        sources = ", ".join(item.get("sources") or [item.get("source") or ""])
        lines.append(f"- {item.get('priority')}{deadline_label}: {item.get('title')} [{sources}]")
    return "\n".join(lines)


__all__ = ["build_attention_snapshot", "summarize_attention_snapshot"]