from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from app.comms.models import CommunicationMessage
from app.comms.providers import get_provider
from app.security.sensitive_data import redact_sensitive_data, redact_text

MAX_DRAFT_CHARS = 4000
MAX_UNRESOLVED_QUESTIONS = 10

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


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _extract_requested_content(request: str) -> str:
    """Return explicit draft content the user asked for, or a minimal ack.

    No facts are invented: if the user did not supply content, the draft is a
    bare acknowledgment rather than fabricated reply content.
    """
    text = redact_text(request or "")
    match = _CONTENT_PATTERN.search(text) or _REPLY_STYLE_CONTENT_PATTERN.search(text)
    if match:
        content = next((group for group in match.groups() if group), "").strip(" ,;:-")
        if content and len(content) >= 2:
            return redact_text(content)[:MAX_DRAFT_CHARS]
    return "Acknowledged."


def draft_reply_to_message(
    provider_name: str,
    message_id: str,
    *,
    draft_body: str,
    requested_by: str = "operator",
) -> dict[str, Any]:
    """Prepare a grounded reply draft bound to one observed message.

    The draft is preparation only: it preserves the observed recipient and
    conversation binding, never fabricates facts, lists unresolved questions,
    and is explicitly marked as never auto-sending. It requires approval
    before any send path can consume it.
    """
    provider = get_provider(provider_name)
    message = provider.get_message(str(message_id or ""))
    if message is None:
        raise ValueError(f"Message {message_id} was not observed by provider {provider_name}.")
    lowered_request = redact_text(draft_body or "").lower()
    if not any(marker in lowered_request for marker in _REPLY_PREFIX_MARKERS):
        raise ValueError("Draft preparation requires an explicit reply/respond/acknowledge request.")
    own = {str(identifier).lower() for identifier in getattr(provider, "own_participants", ("nexus@nexus.local", "nexus"))}
    sender_id = str(message.sender.get("id") or "").lower()
    if sender_id in own:
        raise ValueError("Cannot draft a reply to an own-account message; the observed sender is this account.")

    body = redact_text(draft_body or "")
    body = _extract_requested_content(body)
    if not body.strip():
        raise ValueError("A reply draft requires explicit content or a minimal acknowledgment.")
    if len(body) > MAX_DRAFT_CHARS:
        raise ValueError("Reply draft content exceeds the bounded length limit.")

    unresolved = _unresolved_questions(message)
    recipient = redact_sensitive_data(dict(message.sender))
    draft_id = f"draft-{message.message_id}"
    return redact_sensitive_data({
        "source": "comms_draft_preparation",
        "tool": "comms_draft_preparation",
        "status": "DRAFT",
        "operation": "send_reply",
        "draft_id": draft_id,
        "message_id": message.message_id,
        "is_draft": True,
        "never_auto_send": True,
        "requires_approval": True,
        "provider": provider_name,
        "requested_by": redact_text(requested_by)[:200],
        "conversation_id": message.conversation_id,
        "channel": message.channel,
        "recipient": recipient,
        "in_reply_to": message.message_id,
        "subject": f"Re: {message.content[:200]}" if message.content else "",
        "content": body[:MAX_DRAFT_CHARS],
        "unresolved_questions": unresolved,
        "created_at": _now_iso(),
        "confidence": "MEDIUM",
        "grounding": {
            "grounded_on_message_id": message.message_id,
            "grounded_on_timestamp": message.timestamp.isoformat(),
            "evidence_source": "comms_observer",
            "fabricated_facts": False,
            "redacted": True,
        },
        "provenance": {
            "origin": "comms_draft",
            "message_id": message.message_id,
            "conversation_id": message.conversation_id,
            "channel": message.channel,
            "provider": provider_name,
            "observed_at": (message.provenance or {}).get("observed_at", _now_iso()),
        },
    })


def draft_reply_from_context(
    context: dict[str, Any],
    *,
    draft_body: str,
    requested_by: str = "operator",
) -> dict[str, Any]:
    """Draft a reply from one bounded conversation context window.

    The most recent externally-sent message in the window is the recipient
    binding; the window itself supplies grounding evidence.
    """
    if not isinstance(context, dict) or not context.get("conversation_id"):
        raise ValueError("A reply draft requires one observed conversation context.")
    messages = [entry for entry in (context.get("messages") or []) if isinstance(entry, dict)]
    if not messages:
        raise ValueError("A reply draft requires at least one observed message in context.")
    own = {str(identifier).lower() for identifier in (context.get("own_participants") or ("nexus@nexus.local", "nexus"))}
    target: dict[str, Any] | None = None
    for entry in reversed(messages):
        sender_id = str((entry.get("sender") or {}).get("id") or "").lower()
        if sender_id and sender_id not in own:
            target = entry
            break
    if target is None:
        raise ValueError("No external recipient found in the conversation context.")
    provider_name = str(context.get("provider") or "comms")
    provider = get_provider(provider_name)
    message_id = str(target.get("message_id") or "")
    if provider.get_message(message_id) is None:
        raise ValueError("Context recipient message was not observed by the provider.")
    return draft_reply_to_message(provider_name, message_id, draft_body=draft_body, requested_by=requested_by)


def _unresolved_questions(message: CommunicationMessage) -> list[str]:
    questions: list[str] = []
    if message.untrusted:
        questions.append("The source message contains trust-boundary markers and was treated as data only.")
    for line in message.content.splitlines():
        stripped = line.strip()
        if stripped.endswith("?") and len(stripped) > 4:
            questions.append(redact_text(stripped)[:500])
        if len(questions) >= MAX_UNRESOLVED_QUESTIONS:
            break
    return questions


def prepare_draft(provider_name: str, message_id: str, *, draft_body: str, requested_by: str = "operator") -> dict[str, Any]:
    return draft_reply_to_message(provider_name, message_id, draft_body=draft_body, requested_by=requested_by)


__all__ = [
    "MAX_DRAFT_CHARS",
    "draft_reply_from_context",
    "draft_reply_to_message",
    "prepare_draft",
]