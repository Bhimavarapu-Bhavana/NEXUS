from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Protocol

from app.calendar.fixtures import DEFAULT_PROVIDER, DISPLAY_NAME, build_default_fixture_events
from app.calendar.models import CalendarEvent, MAX_CALENDAR_EVENTS, normalize_calendar_event
from app.security.sensitive_data import redact_sensitive_data, redact_text

MUTATION_OPERATIONS = {"create", "update", "delete", "cancel"}


class CalendarProvider(Protocol):
    """Provider-independent calendar abstraction.

    Concrete providers expose read operations only through the Provider API;
    mutations are implemented only by providers that declare support and are
    invoked strictly through the bounded, approval-gated action layer.
    """

    name: str

    def list_events(self) -> list[CalendarEvent]: ...

    def get_event(self, event_id: str) -> CalendarEvent | None: ...

    def supports_mutation(self) -> bool: ...

    def requires_credentials(self) -> bool: ...


class ProviderRegistry:
    """Deterministic, ordered registry of calendar providers."""

    def __init__(self) -> None:
        self._providers: dict[str, CalendarProvider] = {}

    def register(self, provider: CalendarProvider) -> None:
        name = str(getattr(provider, "name", "") or "").strip()
        if not name:
            raise ValueError("A calendar provider requires a name.")
        self._providers[name] = provider

    def get(self, name: str | None = None) -> CalendarProvider:
        key = str(name or "").strip() or DEFAULT_PROVIDER
        provider = self._providers.get(key)
        if provider is None:
            raise ValueError(f"Calendar provider {key} is not registered.")
        return provider

    def names(self) -> list[str]:
        return sorted(self._providers)

    def exists(self, name: str | None = None) -> bool:
        key = str(name or "").strip() or DEFAULT_PROVIDER
        return key in self._providers


class FixtureCalendarProvider:
    """Deterministic local calendar provider for tests and offline runs.

    No network access, no credentials, no secrets. Mutation support is declared
    but every mutation still requires the shared approval/executor path.
    """

    def __init__(self, events: list[dict[str, Any]] | list[CalendarEvent] | None = None, *, now: datetime | None = None) -> None:
        self.name = DEFAULT_PROVIDER
        self.display_name = DISPLAY_NAME
        raw_events = events if events is not None else build_default_fixture_events(now=now)
        self._events: dict[str, CalendarEvent] = {}
        self._errors: list[str] = []
        self._observed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._ingest(raw_events)

    def _ingest(self, events: list[dict[str, Any]] | list[CalendarEvent]) -> None:
        validated: list[CalendarEvent] = []
        for index, item in enumerate(events[:MAX_CALENDAR_EVENTS]):
            try:
                event = item if isinstance(item, CalendarEvent) else normalize_calendar_event(item, provider=self.name, observed_at=self._observed_at)
            except (TypeError, ValueError) as exc:
                self._errors.append(f"fixture[{index}]: {redact_text(exc)}")
                continue
            validated.append(event)
        self._events = {}
        for event in validated:
            self._events[event.event_id] = event

    def list_events(self) -> list[CalendarEvent]:
        ordered = sorted(self._events.values(), key=lambda event: (event.start_time, event.event_id))
        return [event for event in ordered if event.status != "CANCELLED"]

    def get_event(self, event_id: str) -> CalendarEvent | None:
        return self._events.get(str(event_id or ""))

    def supports_mutation(self) -> bool:
        return True

    def requires_credentials(self) -> bool:
        return False

    def credentials_info(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "requires_credentials": False,
            "stores_credentials": False,
            "oauth": False,
            "external_connection": False,
        }

    def errors(self) -> list[str]:
        return list(self._errors)

    # ------------------------------------------------------------------
    # Bounded mutation primitives. These are never called directly by
    # read paths; the approved action layer is the only caller.
    # ------------------------------------------------------------------

    def _next_event_id(self, title: str, start_time: datetime) -> str:
        digest = hashlib.sha256(f"{title}|{start_time.isoformat()}".encode("utf-8")).hexdigest()[:12]
        return f"fixture-{digest}"

    def create_event(
        self,
        *,
        title: str,
        start_time: datetime,
        end_time: datetime | None = None,
        summary: str = "",
        description: str = "",
        timezone: str = "UTC",
        status: str = "CONFIRMED",
        confidence: str = "MEDIUM",
        source: str = "fixture",
    ) -> CalendarEvent:
        raw = {
            "event_id": self._next_event_id(redact_text(title), start_time),
            "title": redact_text(title),
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat() if end_time is not None else "",
            "timezone": timezone,
            "summary": summary,
            "description": description,
            "status": status,
            "confidence": confidence,
            "source": source,
            "source_reference": DEFAULT_PROVIDER,
        }
        event = normalize_calendar_event(raw, provider=self.name, observed_at=self._observed_at)
        self._events[event.event_id] = event
        return event

    def update_event(self, event_id: str, *, title: str | None = None, start_time: datetime | None = None, end_time: datetime | None = None, summary: str | None = None, description: str | None = None, status: str | None = None, confidence: str | None = None) -> CalendarEvent:
        existing = self.get_event(event_id)
        if existing is None:
            raise ValueError("Calendar event was not found.")
        raw = existing.to_dict()
        if title is not None:
            raw["title"] = redact_text(title)
        if start_time is not None:
            raw["start_time"] = start_time.isoformat()
            if end_time is None and existing.end_time is not None:
                duration = existing.end_time - existing.start_time
                raw["end_time"] = (start_time + duration).isoformat()
        if end_time is not None:
            raw["end_time"] = end_time.isoformat()
        if summary is not None:
            raw["summary"] = redact_text(summary)
        if description is not None:
            raw["description"] = redact_text(description)
        if status is not None:
            raw["status"] = redact_text(status)
        if confidence is not None:
            raw["confidence"] = redact_text(confidence)
        event = normalize_calendar_event(raw, provider=self.name, observed_at=self._observed_at)
        if event.event_id != existing.event_id:
            raise ValueError("Calendar event identifier drift is blocked.")
        self._events[event.event_id] = event
        return event

    def delete_event(self, event_id: str) -> None:
        if self.get_event(event_id) is None:
            raise ValueError("Calendar event was not found.")
        self._events.pop(event_id, None)

    def cancel_event(self, event_id: str) -> CalendarEvent:
        existing = self.get_event(event_id)
        if existing is None:
            raise ValueError("Calendar event was not found.")
        event = normalize_calendar_event({**existing.to_dict(), "status": "CANCELLED"}, provider=self.name, observed_at=self._observed_at)
        self._events[event.event_id] = event
        return event


PROVIDER_REGISTRY: ProviderRegistry = ProviderRegistry()
PROVIDER_REGISTRY.register(FixtureCalendarProvider())


def get_provider(name: str | None = None) -> CalendarProvider:
    return PROVIDER_REGISTRY.get(name)


def get_provider_names() -> list[str]:
    return PROVIDER_REGISTRY.names()


def provider_credentials_required(name: str | None = None) -> bool:
    return bool(PROVIDER_REGISTRY.get(name).requires_credentials())


def registered_actions() -> tuple[str, ...]:
    return ("read", "list", "get")


__all__ = [
    "FixtureCalendarProvider",
    "MUTATION_OPERATIONS",
    "PROVIDER_REGISTRY",
    "ProviderRegistry",
    "get_provider",
    "get_provider_names",
    "provider_credentials_required",
    "registered_actions",
]