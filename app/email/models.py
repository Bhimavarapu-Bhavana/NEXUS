from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.security.sensitive_data import redact_sensitive_data, redact_text

VALID_CONFIDENCE = {"LOW", "MEDIUM", "HIGH"}
MAX_EMAIL_SUBJECT_CHARS = 1000
MAX_EMAIL_BODY_CHARS = 4000
MAX_EMAIL_MESSAGES = 200
MAX_RECIPIENTS = 50
MAX_ATTACHMENTS = 50
MAX_EMAIL_TEXT_CHARS = 2000
DEFAULT_CONFIDENCE = "MEDIUM"

_DEADLINE_MARKERS = (
    "deadline",
    "due",
    "due date",
    "due by",
    "due on",
    "submission date",
    "submission deadline",
    "closes on",
    "expiration date",
    "by end of",
    "by eod",
    "by eow",
    "by cob",
    "by friday",
    "by monday",
    "no later than",
    "must be submitted",
    "must be completed",
    "please submit by",
    "please provide by",
    "roger by",
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
    "required by",
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
)

_MEETING_MARKERS = (
    "meeting",
    "appointment",
    "calendar invite",
    "invitation",
    "rsvp",
    "rsvp by",
    "call at",
    "sync call",
    "standup",
    "get together",
    "schedule a",
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

_IMPORTANCE_MARKERS = (
    "important",
    "high priority",
    "priority",
    "attention",
    "decision needed",
    "blocking",
    "blocked on",
    "needs your sign-off",
    "sign-off",
    "approve",
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
    "override approval",
    "override authorization",
    "tool authorization",
    "bypass",
    "disregard the rules",
    "execute the following",
    "run the following command",
    "send your inbox",
    "send me your",
    "forward your inbox",
    "share your password",
    "give me your password",
    "send me your password",
    "passwords",
    "do not follow",
    "act as",
    "no restrictions",
    "no constraints",
)

_DATETIME_PATTERNS = (
    re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?"),
    re.compile(r"\d{4}-\d{2}-\d{2}"),
)


def parse_email_datetime(value: Any) -> datetime:
    """Parse one email timestamp deterministically into canonical UTC.

    A bare date is interpreted as midnight UTC. Unparseable timestamps are
    rejected; NEXUS never invents email times.
    """
    text = redact_text(value).strip()
    if not text:
        raise ValueError("Email timestamp is missing.")
    candidate = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except (TypeError, ValueError):
        if not any(pattern.match(text) for pattern in _DATETIME_PATTERNS):
            raise ValueError("Email timestamp must be ISO-8601.")
        raise ValueError("Email timestamp must be ISO-8601.")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize_address(value: Any) -> dict[str, str]:
    """Normalize one address into {name, email} with email required."""
    if isinstance(value, dict):
        email = redact_text(value.get("email") or "")
        name = redact_text(value.get("name") or "")[:300]
    else:
        email = redact_text(value)
        name = ""
    if not email or "@" not in email:
        raise ValueError("An email address is required.")
    return {"name": name, "email": email}


def _normalize_address_list(value: Any) -> list[dict[str, str]]:
    raw = value if isinstance(value, (list, tuple)) else ([value] if value not in (None, "") else [])
    addresses: list[dict[str, str]] = []
    for item in raw[:MAX_RECIPIENTS]:
        try:
            addresses.append(_normalize_address(item))
        except ValueError:
            continue
    return addresses


def _bounded_text(value: Any, limit: int = MAX_EMAIL_BODY_CHARS) -> str:
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


def is_commitment_like(*texts: str) -> bool:
    lowered = " ".join(redact_text(text).lower() for text in texts)
    return any(marker in lowered for marker in _COMMITMENT_MARKERS)


def is_meeting_like(*texts: str) -> bool:
    lowered = " ".join(redact_text(text).lower() for text in texts)
    return any(marker in lowered for marker in _MEETING_MARKERS)


def is_follow_up_like(*texts: str) -> bool:
    lowered = " ".join(redact_text(text).lower() for text in texts)
    return any(marker in lowered for marker in _FOLLOW_UP_MARKERS)


def is_request_like(*texts: str) -> bool:
    lowered = " ".join(redact_text(text).lower() for text in texts)
    return any(marker in lowered for marker in _REQUEST_MARKERS)


def extract_datetime_tokens(*texts: str) -> list[str]:
    """Return every deterministic ISO-8601 timestamp found verbatim in text.

    No dates are computed or inferred; only explicit tokens are returned.
    """
    joined = redact_text(" ".join(texts))
    found: list[str] = []
    for pattern in _DATETIME_PATTERNS:
        for match in pattern.finditer(joined):
            token = match.group(0).strip()
            try:
                parse_email_datetime(token)
            except ValueError:
                continue
            if token not in found:
                found.append(token)
        if found:
            break
    return found[:5]


def scan_bounded_email_content(*texts: str) -> dict[str, Any]:
    """Classify email text as bounded, untrusted evidence.

    Email content is always evidence, never instructions. Hostile markers are
    reported but never obeyed.
    """
    payload = {
        "texts": [redact_text(text)[:MAX_EMAIL_TEXT_CHARS] for text in texts],
        "untrusted": False,
        "matched_terms": [],
    }
    lowered = " ".join(payload["texts"]).lower()
    matched = [term for term in _TRUST_BOUNDARY_MARKERS if term in lowered]
    payload["untrusted"] = bool(matched)
    payload["matched_terms"] = matched[:20]
    return redact_sensitive_data(payload)


@dataclass(frozen=True)
class EmailMessage:
    message_id: str
    thread_id: str
    sender: dict[str, str]
    recipients: list[dict[str, str]]
    subject: str
    body: str
    timestamp: datetime
    labels: list[str]
    attachments: list[dict[str, Any]]
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
            "thread_id": self.thread_id,
            "sender": self.sender,
            "recipients": self.recipients,
            "subject": self.subject,
            "body": self.body,
            "timestamp": self.timestamp.isoformat(),
            "labels": self.labels,
            "attachments": self.attachments,
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
            "thread_id": self.thread_id,
            "sender": self.sender,
            "subject": self.subject,
            "timestamp": self.timestamp.isoformat(),
        })

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "EmailMessage":
        raw = value if isinstance(value, dict) else {}
        message_id = redact_text(str(raw.get("message_id") or "")).strip()
        if not message_id:
            raise ValueError("Email message requires a stable message identifier.")
        thread_id = redact_text(str(raw.get("thread_id") or "")).strip() or message_id
        subject = redact_text(raw.get("subject") or "")[:MAX_EMAIL_SUBJECT_CHARS]
        body_text = _bounded_text(raw.get("body"), MAX_EMAIL_BODY_CHARS)
        timestamp = parse_email_datetime(raw.get("timestamp"))
        sender = _normalize_address(raw.get("sender"))
        recipients = _normalize_address_list(raw.get("recipients"))
        if not recipients:
            if _normalize_address(raw.get("to")):
                recipients = [_normalize_address(raw.get("to"))]
        if not recipients:
            raise ValueError("Email message requires at least one recipient address.")
        confidence = str(raw.get("confidence") or DEFAULT_CONFIDENCE).upper()
        if confidence not in VALID_CONFIDENCE:
            raise ValueError("Email confidence must be LOW, MEDIUM, or HIGH.")
        scan = scan_bounded_email_content(subject, body_text)
        return cls(
            message_id=message_id[:300],
            thread_id=thread_id[:300],
            sender=sender,
            recipients=recipients,
            subject=subject,
            body=body_text,
            timestamp=timestamp,
            labels=[redact_text(item)[:200] for item in (raw.get("labels") or [])[:30]],
            attachments=_normalize_attachments(raw.get("attachments")),
            provider=redact_text(raw.get("provider") or "")[:120],
            source=redact_text(raw.get("source") or "")[:300],
            source_reference=redact_text(raw.get("source_reference") or "")[:300],
            confidence=confidence,
            read=bool(raw.get("read")),
            untrusted=scan["untrusted"],
            provenance=redact_sensitive_data(raw.get("provenance") or {}),
        )


def normalize_email_message(raw: Any, *, provider: str = "fixture", observed_at: str | None = None) -> EmailMessage:
    """Normalize one provider message into the provider-independent representation.

    Fails closed on malformed input. Never invents missing content or times.
    """
    if not isinstance(raw, dict):
        raise ValueError("Email message must be a mapping.")
    if not str(raw.get("message_id") or "").strip():
        raise ValueError("Email message requires a stable identifier.")
    candidate = dict(raw)
    candidate["provider"] = provider
    if not str(raw.get("observed_at") or "").strip():
        candidate["observed_at"] = observed_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    provenance = dict(raw.get("provenance") or {})
    provenance.update({
        "origin": "email_message",
        "provider": provider,
        "source": str(raw.get("source") or "") or provider,
        "source_reference": str(raw.get("source_reference") or "") or str(raw.get("message_id") or ""),
        "observed_at": candidate["observed_at"],
        "extraction_method": "provider_normalized_message",
    })
    candidate["provenance"] = provenance
    message = EmailMessage.from_dict(candidate)
    if message.provider != provider:
        raise ValueError("Email message provider mismatch.")
    return message


def redact_email_dict(value: dict[str, Any]) -> dict[str, Any]:
    return redact_sensitive_data(value)


__all__ = [
    "DEFAULT_CONFIDENCE",
    "EmailMessage",
    "MAX_EMAIL_MESSAGES",
    "VALID_CONFIDENCE",
    "extract_datetime_tokens",
    "is_action_required_like",
    "is_commitment_like",
    "is_deadline_like",
    "is_follow_up_like",
    "is_meeting_like",
    "is_request_like",
    "normalize_email_message",
    "parse_email_datetime",
    "redact_email_dict",
    "scan_bounded_email_content",
]