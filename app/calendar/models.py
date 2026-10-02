from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.security.sensitive_data import redact_sensitive_data, redact_text

VALID_CONFIDENCE = {"LOW", "MEDIUM", "HIGH"}
VALID_EVENT_STATUS = {"CONFIRMED", "TENTATIVE", "CANCELLED", "FREE", "BUSY"}
MAX_EVENT_TEXT_CHARS = 2000
MAX_EVENT_DESCRIPTION_CHARS = 4000
MAX_CALENDAR_EVENTS = 200
DEFAULT_CONFIDENCE = "MEDIUM"
DEFAULT_EVENT_STATUS = "CONFIRMED"

_DEADLINE_MARKERS = (
    "deadline",
    "due",
    "due date",
    "due by",
    "submission date",
    "submission deadline",
    "closes on",
    "expiration date",
)

_TRUST_BOUNDARY_MARKERS = (
    "ignore previous",
    "ignore all instructions",
    "ignore your",
    "ignore nexus",
    "ignore security",
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
    "disregard all rules",
    "execute the following",
    "run the following command",
    "do not follow",
    "act as",
    "no restrictions",
    "no constraints",
)

_DATETIME_PARSE_PATTERNS = (
    re.compile(r"^\d{4}-\d{2}-\d{2}$"),
    re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$"),
)


def parse_calendar_datetime(value: Any) -> datetime:
    """Parse one calendar timestamp deterministically.

    Missing time-of-day on a bare date is interpreted as midnight UTC. A value
    that cannot be parsed is rejected; NEXUS never invents calendar times.
    """
    text = redact_text(value).strip()
    if not text:
        raise ValueError("Calendar event time is missing.")
    candidate = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except (TypeError, ValueError):
        if not any(pattern.match(text) for pattern in _DATETIME_PARSE_PATTERNS):
            raise ValueError("Calendar event time must be an ISO-8601 timestamp.")
        raise ValueError("Calendar event time must be an ISO-8601 timestamp.")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def is_deadline_like(*texts: str) -> bool:
    lowered = " ".join(redact_text(text).lower() for text in texts)
    return any(marker in lowered for marker in _DEADLINE_MARKERS)


def scan_bounded_calendar_content(*texts: str) -> dict[str, Any]:
    """Classify calendar text as bounded, potentially untrusted evidence.

    Returns redacted, bounded text plus a flag describing whether the content
    attempts to override NEXUS instructions or security boundaries. Calendar
    content is always treated as evidence, never as instructions.
    """
    payload = {
        "texts": [redact_text(text)[:MAX_EVENT_TEXT_CHARS] for text in texts],
        "untrusted": False,
        "matched_terms": [],
    }
    lowered = " ".join(payload["texts"]).lower()
    matched = [term for term in _TRUST_BOUNDARY_MARKERS if term in lowered]
    payload["untrusted"] = bool(matched)
    payload["matched_terms"] = matched[:20]
    return redact_sensitive_data(payload)


def _bounded_text(value: Any, limit: int = MAX_EVENT_DESCRIPTION_CHARS) -> str:
    text = redact_text(value)
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... [TRUNCATED]"


@dataclass(frozen=True)
class CalendarEvent:
    event_id: str
    title: str
    start_time: datetime
    end_time: datetime | None
    timezone: str
    summary: str
    description: str
    provider: str
    source: str
    source_reference: str
    confidence: str
    status: str
    observed_at: str
    is_deadline: bool
    untrusted: bool
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return redact_sensitive_data({
            "event_id": self.event_id,
            "title": self.title,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time is not None else "",
            "timezone": self.timezone,
            "summary": self.summary,
            "description": self.description,
            "provider": self.provider,
            "source": self.source,
            "source_reference": self.source_reference,
            "confidence": self.confidence,
            "status": self.status,
            "observed_at": self.observed_at,
            "is_deadline": self.is_deadline,
            "untrusted": self.untrusted,
            "provenance": redact_sensitive_data(self.provenance),
        })

    def snapshot(self) -> dict[str, Any]:
        """Deterministic grounding snapshot for revalidation before mutation."""
        return redact_sensitive_data({
            "event_id": self.event_id,
            "title": self.title,
            "start_time": self.start_time.isoformat() if self.start_time else "",
            "end_time": self.end_time.isoformat() if self.end_time else "",
            "status": self.status,
        })

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CalendarEvent":
        raw = value if isinstance(value, dict) else {}
        event_id = str(raw.get("event_id") or "")
        title = redact_text(raw.get("title"))
        start_text = raw.get("start_time")
        end_text = raw.get("end_time")
        if not event_id or not title:
            raise ValueError("Calendar event requires a stable identifier and a title.")
        start_time = parse_calendar_datetime(start_text)
        end_time = parse_calendar_datetime(end_text) if end_text else None
        if end_time is not None and end_time <= start_time:
            raise ValueError("Calendar event end time must be after its start time.")
        timezone_value = str(raw.get("timezone") or "").strip() or (start_time.tzinfo.tzname(start_time) if start_time.tzinfo and not isinstance(start_time.tzinfo, timezone) else "UTC")
        confidence = str(raw.get("confidence") or DEFAULT_CONFIDENCE).upper()
        if confidence not in VALID_CONFIDENCE:
            raise ValueError("Calendar event confidence must be LOW, MEDIUM, or HIGH.")
        status = str(raw.get("status") or DEFAULT_EVENT_STATUS).upper()
        if status not in VALID_EVENT_STATUS:
            raise ValueError("Calendar event status is not recognized.")
        scan = scan_bounded_calendar_content(title, str(raw.get("summary") or ""), str(raw.get("description") or ""))
        return cls(
            event_id=redact_text(event_id)[:300],
            title=title[:MAX_EVENT_TEXT_CHARS],
            start_time=start_time,
            end_time=end_time,
            timezone=timezone_value[:64],
            summary=_bounded_text(raw.get("summary"), MAX_EVENT_TEXT_CHARS),
            description=_bounded_text(raw.get("description"), MAX_EVENT_DESCRIPTION_CHARS),
            provider=redact_text(raw.get("provider") or "")[:120],
            source=redact_text(raw.get("source") or "")[:300],
            source_reference=redact_text(raw.get("source_reference") or "")[:300],
            confidence=confidence,
            status=status,
            observed_at=redact_text(raw.get("observed_at") or datetime.now(timezone.utc).isoformat(timespec="seconds"))[:80],
            is_deadline=is_deadline_like(title, str(raw.get("summary") or ""), str(raw.get("description") or "")),
            untrusted=scan["untrusted"],
            provenance=redact_sensitive_data(raw.get("provenance") or {}),
        )


def normalize_calendar_event(raw: Any, *, provider: str = "fixture", observed_at: str | None = None) -> CalendarEvent:
    """Normalize one provider event into the provider-independent representation.

    Fails closed on malformed data. Never invents start/end times or other
    missing fields. Calendar text is redacted and marked as untrusted evidence.
    """
    if not isinstance(raw, dict):
        raise ValueError("Calendar event must be a mapping.")
    if not str(raw.get("event_id") or "").strip():
        raise ValueError("Calendar event requires a stable identifier.")
    if not redact_text(raw.get("title") or "").strip():
        raise ValueError("Calendar event requires a title.")
    candidate = dict(raw)
    candidate["provider"] = provider
    candidate["timezone"] = str(raw.get("timezone") or "").strip() or "UTC"
    if not str(raw.get("observed_at") or "").strip():
        candidate["observed_at"] = observed_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    provenance = dict(raw.get("provenance") or {})
    provenance.update({
        "origin": "calendar_event",
        "provider": provider,
        "source": str(raw.get("source") or "") or provider,
        "source_reference": str(raw.get("source_reference") or "") or str(raw.get("event_id") or ""),
        "observed_at": candidate["observed_at"],
        "extraction_method": "provider_normalized_event",
    })
    candidate["provenance"] = provenance
    event = CalendarEvent.from_dict(candidate)
    if event.provider != provider:
        raise ValueError("Calendar event provider mismatch.")
    return event


def redact_event_dict(value: dict[str, Any]) -> dict[str, Any]:
    return redact_sensitive_data(value)


__all__ = [
    "CalendarEvent",
    "DEFAULT_CONFIDENCE",
    "MAX_CALENDAR_EVENTS",
    "VALID_CONFIDENCE",
    "VALID_EVENT_STATUS",
    "is_deadline_like",
    "normalize_calendar_event",
    "parse_calendar_datetime",
    "redact_event_dict",
    "scan_bounded_calendar_content",
]