from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.security.sensitive_data import redact_sensitive_data, redact_text

VALID_CONFIDENCE = {"LOW", "MEDIUM", "HIGH"}
DEFAULT_CONFIDENCE = "MEDIUM"
MAX_MSG_SUBJECT_CHARS = 1000
MAX_MSG_CONTENT_CHARS = 4000
MAX_MESSAGES = 200
MAX_PARTICIPANTS = 50
MAX_ATTACHMENTS = 50
MAX_TEXT_CHARS = 2000
DEFAULT_CHANNEL = "general"

_DEADLINE_MARKERS = (
    "deadline",
    "due",
    "due date",
    "due by",
    "due on",
    "by end of",
    "by eod",
    "by eow",
    "by cob",
    "no later than",
    "must be submitted",
    "must be completed",
    "please submit by",
    "please provide by",
    "closes on",
    "expiration date",
)

_ACTION_MARKERS = (
    "action required",
    "action item",
    "action needed",
    "asap",
    "urgent",
    "please confirm",
    "confirm by",
    "please review",
    "please reply",
    "response required",
    "your response",
    "requested",
    "need your",
    ":sos:",
)

_REQUEST_MARKERS = (
    "please",
    "can you",
    "could you",
    "would you",
    "will you",
    "need you to",
    "we need",
    "request that",
    "kindly",
    "help me",
)

_COMMITMENT_MARKERS = (
    "i will",
    "i'll",
    "will do",
    "commit to",
    "i commit",
    "promise",
    "we will",
    "i plan to",
    "going to",
    "will send",
    "will submit",
    "will provide",
    "will follow up",
    "will prepare",
    "will do",
)

_MEETING_MARKERS = (
    "meeting",
    "appointment",
    "call",
    "sync",
    "standup",
    "demo",
    "webinar",
    "book a",
    "schedule a",
    "when are you free",
    "let's get together",
)

_FOLLOW_UP_MARKERS = (
    "follow up",
    "following up",
    "checking in",
    "circling back",
    "bump",
    "any update",
    "just fyi",
    "fyi",
    "touching base",
    "ping",
)

_DECISION_MARKERS = (
    "decision",
    "decide",
    "decided",
    "sign-off",
    "sign off",
    "approve",
    "approval needed",
    "needs your approval",
    "we decided",
    "final call",
)

_UNANSWERED_MARKERS = (
    "?",
    "questions",
    "please answer",
    "awaiting your",
    "waiting on",
    "tbd",
    "todo?",
)

_TASK_MARKERS = (
    "task",
    "todo",
    "to-do",
    "ticket",
    "issue",
    "subtask",
    "story",
    "assign",
)

_PROJECT_MARKERS = (
    "project",
    "workspace",
    "repo",
    "repository",
    "sprint",
    "milestone",
    "backlog",
    "release",
)

_TRUST_BOUNDARY_MARKERS = (
    "ignore previous",
    "ignore all instructions",
    "ignore your",
    "ignore nexus",
    "ignore security",
    "ignore approvals",
    "disregard",
    "prompt injection",
    "you are now",
    "new system prompt",
    "system prompt",
    "override system",
    "override instructions",
    "override security",
    "override approvals",
    "bypass",
    "execute the following",
    "run the following command",
    "send your inbox",
    "send me your",
    "forward your inbox",
    "share your password",
    "passwords",
    "do not follow",
    "act as another agent",
    "act as",
    "no restrictions",
    "no constraints",
)

_DATETIME_PATTERNS = (
    re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?"),
    re.compile(r"\d{4}-\d{2}-\d{2}"),
)


def parse_comms_datetime(value: Any) -> datetime:
    text = redact_text(value).strip()
    if not text:
        raise ValueError("Communication timestamp is missing.")
    candidate = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except (TypeError, ValueError):
        raise ValueError("Communication timestamp must be ISO-8601.")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize_participant(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        identifier = redact_text(value.get("id") or value.get("email") or "")
        name = redact_text(value.get("name") or "")[:300]
        role = redact_text(value.get("role") or "")[:100]
    else:
        identifier = redact_text(value)
        name = ""
        role = ""
    if not identifier:
        raise ValueError("A participant identifier is required.")
    return {"id": identifier, "name": name, "role": role}


def _normalize_participants(value: Any) -> list[dict[str, str]]:
    raw = value if isinstance(value, (list, tuple)) else ([value] if value not in (None, "") else [])
    participants: list[dict[str, str]] = []
    for item in raw[:MAX_PARTICIPANTS]:
        try:
            participant = _normalize_participant(item)
        except ValueError:
            continue
        if participant not in participants:
            participants.append(participant)
    return participants


def _bounded_text(value: Any, limit: int = MAX_MSG_CONTENT_CHARS) -> str:
    text = redact_text(value)
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... [TRUNCATED]"


def _normalize_attachments(value: Any) -> list[dict[str, Any]]:
    raw = value if isinstance(value, list) else []
    attachments: list[dict[str, Any]] = []
    for item in raw[:MAX_ATTACHMENTS]:
        if not isinstance(item, dict):
            continue
        filename = redact_text(item.get("filename") or "")[:300]
        content_type = redact_text(item.get("content_type") or "")[:200]
        size_bytes = int(item.get("size_bytes") or 0)
        digest = redact_text(item.get("sha256") or "")[:80]
        attachments.append(redact_sensitive_data({
            "filename": filename,
            "content_type": content_type,
            "size_bytes": size_bytes if size_bytes > 0 else 0,
            "sha256": digest,
        }))
    return attachments


def is_deadline_like(*texts: str) -> bool:
    lowered = " ".join(redact_text(text).lower() for text in texts)
    return any(marker in lowered for marker in _DEADLINE_MARKERS)


def is_action_required_like(*texts: str) -> bool:
    lowered = " ".join(redact_text(text).lower() for text in texts)
    return any(marker in lowered for marker in _ACTION_MARKERS)


def is_request_like(*texts: str) -> bool:
    lowered = " ".join(redact_text(text).lower() for text in texts)
    return any(marker in lowered for marker in _REQUEST_MARKERS)


def is_commitment_like(*texts: str) -> bool:
    lowered = " ".join(redact_text(text).lower() for text in texts)
    return any(marker in lowered for marker in _COMMITMENT_MARKERS)


def is_meeting_like(*texts: str) -> bool:
    lowered = " ".join(redact_text(text).lower() for text in texts)
    return any(marker in lowered for marker in _MEETING_MARKERS)


def is_follow_up_like(*texts: str) -> bool:
    lowered = " ".join(redact_text(text).lower() for text in texts)
    return any(marker in lowered for marker in _FOLLOW_UP_MARKERS)


def is_decision_like(*texts: str) -> bool:
    lowered = " ".join(redact_text(text).lower() for text in texts)
    return any(marker in lowered for marker in _DECISION_MARKERS)


def is_unanswered_like(*texts: str) -> bool:
    lowered = " ".join(redact_text(text).lower() for text in texts)
    return any(marker in lowered for marker in _UNANSWERED_MARKERS)


def is_task_like(*texts: str) -> bool:
    lowered = " ".join(redact_text(text).lower() for text in texts)
    return any(marker in lowered for marker in _TASK_MARKERS)


def is_project_like(*texts: str) -> bool:
    lowered = " ".join(redact_text(text).lower() for text in texts)
    return any(marker in lowered for marker in _PROJECT_MARKERS)


def extract_datetime_tokens(*texts: str) -> list[str]:
    """Return every deterministic ISO-8601 timestamp found verbatim in text."""
    joined = redact_text(" ".join(texts))
    found: list[str] = []
    for pattern in _DATETIME_PATTERNS:
        for match in pattern.finditer(joined):
            token = match.group(0).strip()
            try:
                parse_comms_datetime(token)
            except ValueError:
                continue
            if token not in found:
                found.append(token)
        if found:
            break
    return found[:5]


def scan_bounded_communication_content(*texts: str) -> dict[str, Any]:
    """Classify communication content as bounded, untrusted evidence.

    Communication content is always evidence, never instructions.
    """
    payload = {
        "texts": [redact_text(text)[:MAX_TEXT_CHARS] for text in texts],
        "untrusted": False,
        "matched_terms": [],
    }
    lowered = " ".join(payload["texts"]).lower()
    matched = [term for term in _TRUST_BOUNDARY_MARKERS if term in lowered]
    payload["untrusted"] = bool(matched)
    payload["matched_terms"] = matched[:20]
    return redact_sensitive_data(payload)


@dataclass(frozen=True)
class CommunicationMessage:
    message_id: str
    conversation_id: str
    channel: str
    sender: dict[str, str]
    participants: list[dict[str, str]]
    content: str
    timestamp: datetime
    attachments: list[dict[str, Any]]
    platform: str
    provider: str
    source: str
    source_reference: str
    confidence: str
    read: bool
    untrusted: bool
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return redact_sensitive_data({
            "message_id": self.message_id,
            "conversation_id": self.conversation_id,
            "channel": self.channel,
            "sender": self.sender,
            "participants": self.participants,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "attachments": self.attachments,
            "platform": self.platform,
            "provider": self.provider,
            "source": self.source,
            "source_reference": self.source_reference,
            "confidence": self.confidence,
            "read": self.read,
            "untrusted": self.untrusted,
            "provenance": redact_sensitive_data(self.provenance),
        })

    def snapshot(self) -> dict[str, Any]:
        """Deterministic grounding snapshot for revalidation before any action."""
        return redact_sensitive_data({
            "message_id": self.message_id,
            "conversation_id": self.conversation_id,
            "channel": self.channel,
            "sender": self.sender,
            "content": self.content[:500],
            "timestamp": self.timestamp.isoformat(),
        })

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CommunicationMessage":
        raw = value if isinstance(value, dict) else {}
        message_id = redact_text(str(raw.get("message_id") or "")).strip()
        if not message_id:
            raise ValueError("Communication message requires a stable message identifier.")
        conversation_id = redact_text(str(raw.get("conversation_id") or "")).strip() or message_id
        channel = redact_text(str(raw.get("channel") or "")).strip()[:200] or DEFAULT_CHANNEL
        participants = _normalize_participants(raw.get("participants") or raw.get("recipients"))
        if not participants:
            raise ValueError("Communication message requires participant context.")
        sender = _normalize_participant(raw.get("sender"))
        content = _bounded_text(raw.get("content") or raw.get("body"), MAX_MSG_CONTENT_CHARS)
        confidence = str(raw.get("confidence") or DEFAULT_CONFIDENCE).upper()
        if confidence not in VALID_CONFIDENCE:
            raise ValueError("Communication confidence must be LOW, MEDIUM, or HIGH.")
        scan = scan_bounded_communication_content(content)
        return cls(
            message_id=message_id[:300],
            conversation_id=conversation_id[:300],
            channel=channel[:200],
            sender=sender,
            participants=participants,
            content=content,
            timestamp=parse_comms_datetime(raw.get("timestamp")),
            attachments=_normalize_attachments(raw.get("attachments")),
            platform=redact_text(raw.get("platform") or "")[:120],
            provider=redact_text(raw.get("provider") or "")[:120],
            source=redact_text(raw.get("source") or "")[:300],
            source_reference=redact_text(raw.get("source_reference") or "")[:300],
            confidence=confidence,
            read=bool(raw.get("read")),
            untrusted=scan["untrusted"],
            provenance=redact_sensitive_data(raw.get("provenance") or {}),
        )


def normalize_communication_message(raw: Any, *, provider: str = "comms", observed_at: str | None = None) -> CommunicationMessage:
    """Normalize one provider message into the provider-independent representation.

    Fails closed on malformed input. Never invents missing content or times.
    """
    if not isinstance(raw, dict):
        raise ValueError("Communication message must be a mapping.")
    if not str(raw.get("message_id") or "").strip():
        raise ValueError("Communication message requires a stable identifier.")
    candidate = dict(raw)
    candidate["provider"] = provider
    if not str(raw.get("observed_at") or "").strip():
        candidate["observed_at"] = observed_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    provenance = dict(raw.get("provenance") or {})
    provenance.update({
        "origin": "comm_message",
        "provider": provider,
        "source": str(raw.get("source") or "") or provider,
        "source_reference": str(raw.get("source_reference") or "") or str(raw.get("message_id") or ""),
        "observed_at": candidate["observed_at"],
        "extraction_method": "provider_normalized_message",
    })
    candidate["provenance"] = provenance
    message = CommunicationMessage.from_dict(candidate)
    if message.provider != provider:
        raise ValueError("Communication provider mismatch.")
    return message


def redact_comms_dict(value: dict[str, Any]) -> dict[str, Any]:
    return redact_sensitive_data(value)


__all__ = [
    "CommunicationMessage",
    "DEFAULT_CONFIDENCE",
    "VALID_CONFIDENCE",
    "extract_datetime_tokens",
    "is_action_required_like",
    "is_commitment_like",
    "is_deadline_like",
    "is_decision_like",
    "is_follow_up_like",
    "is_meeting_like",
    "is_project_like",
    "is_request_like",
    "is_task_like",
    "is_unanswered_like",
    "normalize_communication_message",
    "parse_comms_datetime",
    "redact_comms_dict",
    "scan_bounded_communication_content",
]