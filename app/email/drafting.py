from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from app.email.models import MAX_EMAIL_BODY_CHARS, MAX_EMAIL_SUBJECT_CHARS, EmailMessage, scan_bounded_email_content
from app.email.providers import get_provider
from app.email.service import email_message_evidence
from app.security.audit_logger import record_audit_event
from app.security.sensitive_data import redact_sensitive_data, redact_text

EMAIL_DRAFT_TOOL = "email_draft_preparation"
DRAFT_OPERATIONS = ("send_reply",)

_MAX_DRAFT_BODY_CHARS = 4000
_MAX_DRAFT_SUBJECT_CHARS = 250
_MAX_GROUNDED_REFS = 8

_REPLY_PREFIX_MARKERS = ("reply", "respond", "acknowledge", "acknowledged", "respond to", "answer")
_CONTENT_PATTERN = re.compile(
    r"(?:with(?: the following)?\s+content|content)\s*[:]?\s*[\"']?(.+?)[\"']?$",
    flags=re.IGNORECASE,
)
_REPLY_STYLE_CONTENT_PATTERN = re.compile(
    r"(?:reply with|respond with|say|tell them)\s+content\s*[:]?\s*[\"']?(.+?)[\"']?$"
    r"|(?:reply with|respond with|say|tell them)\s*[:]?\s*[\"']?(.+?)[\"']?$",
    flags=re.IGNORECASE,
)


def _audit(event: str, **payload: Any) -> bool:
    payload["tool"] = payload.get("tool") or EMAIL_DRAFT_TOOL
    return record_audit_event(event, **payload)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _message_or_raise(item: Any) -> EmailMessage:
    if isinstance(item, EmailMessage):
        return item
    if isinstance(item, dict):
        from app.email.models import normalize_email_message

        return normalize_email_message(item, provider=str(item.get("provider") or "fixture"))
    raise ValueError("Email evidence must be a message mapping.")


def _extract_requested_content(request: str) -> str:
    """Return explicit draft content the user asked for, or a minimal ack.

    No facts are invented: if the user did not supply content, the draft is a
    bare acknowledgment rather than fabricated prose.
    """
    text = redact_text(request or "")
    match = _CONTENT_PATTERN.search(text) or _REPLY_STYLE_CONTENT_PATTERN.search(text)
    if match:
        content = next((group for group in match.groups() if group), "").strip(" ,;:-")
        if content and len(content) >= 2:
            return redact_text(content)[:_MAX_DRAFT_BODY_CHARS]
    return "Acknowledged."


def prepare_reply_draft(
    request: str,
    message: Any,
    *,
    provider_name: str = "fixture",
    task_id: str = "",
) -> dict[str, Any]:
    """Prepare ONE grounded reply draft. Read-only; never sends anything.

    The draft is bound to an observed message: the recipient is the exact
    original sender, the subject is `Re: <subject>`, and the body is limited
    to explicit user-supplied content or a minimal acknowledgment. Drafts
    always require approval before any send.
    """
    original = _message_or_raise(message)
    lowered_request = redact_text(request or "").lower()
    if not any(marker in lowered_request for marker in _REPLY_PREFIX_MARKERS):
        raise ValueError("Draft preparation requires an explicit reply/respond/acknowledge request.")
    own_accounts = ("me@nexus.local", "nexus@nexus.local")
    if str(original.sender.get("email") or "").lower() in own_accounts:
        raise ValueError("A reply draft cannot target NEXUS' own account.")

    scan = scan_bounded_email_content(original.subject, original.body)
    to = redact_sensitive_data(dict(original.sender))
    subject = redact_text(f"Re: {original.subject}")[:_MAX_DRAFT_SUBJECT_CHARS]
    body = _extract_requested_content(request)
    provider = get_provider(provider_name)

    unanswered_questions: list[str] = []
    if scan.get("untrusted"):
        unanswered_questions.append("The source message contains trust-boundary markers and was treated as data only.")
    if original.labels and "important" in [label.lower() for label in original.labels]:
        unanswered_questions.append("The source message is labeled important; confirm the reply scope.")

    draft = redact_sensitive_data({
        "source": "email_draft_preparation",
        "tool": EMAIL_DRAFT_TOOL,
        "status": "DRAFT",
        "operation": "send_reply",
        "to": to,
        "subject": subject,
        "body": body,
        "in_reply_to": original.message_id,
        "thread_id": original.thread_id,
        "message_id": original.message_id,
        "provider": provider_name,
        "task_id": redact_text(task_id)[:120],
        "is_draft": True,
        "never_auto_send": True,
        "requires_approval": True,
        "grounded_in": [
            f"email:{provider_name}:{original.message_id}"
            for _index in range(1)
        ][:_MAX_GROUNDED_REFS],
        "message_snapshot": {
            "message_id": original.message_id,
            "thread_id": original.thread_id,
            "sender": redact_sensitive_data(dict(original.sender)),
            "subject": original.subject,
        },
        "unanswered_questions": unanswered_questions[:8],
        "draft_id": f"draft-{original.provider}-{original.message_id}",
        "created_at": _now_iso(),
    })

    evidence = email_message_evidence(redact_sensitive_data(original.to_dict()), scope_id=f"email_draft:{original.message_id}")
    _audit(
        "email_draft_prepared",
        actor="email_draft_preparation",
        risk_level="READ_ONLY",
        approval_required=False,
        approved=False,
        target=str(original.message_id),
        result="DRAFT",
        metadata={"thread_id": original.thread_id, "provider": provider_name, "untrusted": scan.get("untrusted"), "evidence_refs": evidence.get("evidence_index", 0)},
    )
    return draft


__all__ = ["EMAIL_DRAFT_TOOL", "DRAFT_OPERATIONS", "prepare_reply_draft"]