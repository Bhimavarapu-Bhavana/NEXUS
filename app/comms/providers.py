from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Protocol

from app.comms.fixtures import DEFAULT_PROVIDER, DISPLAY_NAME, build_default_fixture_messages
from app.comms.models import MAX_MESSAGES, CommunicationMessage, normalize_communication_message
from app.security.sensitive_data import redact_sensitive_data, redact_text


class CommsProvider(Protocol):
    """Provider-independent communication abstraction.

    Read operations are the only interface a provider must expose. Sending is
    an explicitly declared capability invoked only through the bounded,
    approval-gated action layer.
    """

    name: str

    def list_conversations(self) -> list[dict[str, Any]]: ...

    def list_messages(self) -> list[CommunicationMessage]: ...

    def get_message(self, message_id: str) -> CommunicationMessage | None: ...

    def get_conversation(self, conversation_id: str) -> list[CommunicationMessage]: ...

    def supports_send(self) -> bool: ...

    def requires_credentials(self) -> bool: ...


class ProviderRegistry:
    """Deterministic, ordered registry of communication providers."""

    def __init__(self) -> None:
        self._providers: dict[str, CommsProvider] = {}

    def register(self, provider: CommsProvider) -> None:
        name = str(getattr(provider, "name", "") or "").strip()
        if not name:
            raise ValueError("A communication provider requires a name.")
        self._providers[name] = provider

    def get(self, name: str | None = None) -> CommsProvider:
        key = str(name or "").strip() or DEFAULT_PROVIDER
        provider = self._providers.get(key)
        if provider is None:
            raise ValueError(f"Communication provider {key} is not registered.")
        return provider

    def names(self) -> list[str]:
        return sorted(self._providers)

    def exists(self, name: str | None = None) -> bool:
        key = str(name or "").strip() or DEFAULT_PROVIDER
        return key in self._providers


class FixtureCommsProvider:
    """Deterministic local communication provider for tests and offline runs.

    No real account, no credentials, no network. Sending is mocked strictly
    for exercising the security/approval pipeline and is never a real send.
    """

    def __init__(self, messages: list[dict[str, Any]] | list[CommunicationMessage] | None = None) -> None:
        self.name = DEFAULT_PROVIDER
        self.display_name = DISPLAY_NAME
        self.own_participants = ("nexus@nexus.local", "nexus")
        raw_messages = messages if messages is not None else build_default_fixture_messages()
        self._messages: dict[str, CommunicationMessage] = {}
        self._errors: list[str] = []
        self._observed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._ingest(raw_messages)
        self._sent: dict[str, dict[str, Any]] = {}

    def _ingest(self, messages: list[dict[str, Any]] | list[CommunicationMessage]) -> None:
        validated: list[CommunicationMessage] = []
        for index, item in enumerate(messages[:MAX_MESSAGES]):
            try:
                message = item if isinstance(item, CommunicationMessage) else normalize_communication_message(item, provider=self.name, observed_at=self._observed_at)
            except (TypeError, ValueError) as exc:
                self._errors.append(f"fixture[{index}]: {redact_text(exc)}")
                continue
            validated.append(message)
        self._messages = {}
        for message in validated:
            self._messages[message.message_id] = message

    # ------------------------------------------------------------------
    # Read-only observation interface
    # ------------------------------------------------------------------

    def list_conversations(self) -> list[dict[str, Any]]:
        conversations: dict[str, dict[str, Any]] = {}
        for message in self._messages.values():
            entry = conversations.setdefault(message.conversation_id, {
                "conversation_id": message.conversation_id,
                "channel": message.channel,
                "platform": message.platform,
                "message_count": 0,
                "participants": [],
            })
            entry["message_count"] += 1
            for participant in [message.sender, *message.participants]:
                if participant and participant not in entry["participants"]:
                    entry["participants"].append(participant)
        return [conversations[key] for key in sorted(conversations)]

    def list_messages(self) -> list[CommunicationMessage]:
        ordered = sorted(self._messages.values(), key=lambda message: (message.timestamp, message.message_id))
        return list(ordered)

    def get_message(self, message_id: str) -> CommunicationMessage | None:
        return self._messages.get(str(message_id or ""))

    def get_conversation(self, conversation_id: str) -> list[CommunicationMessage]:
        matches = [message for message in self._messages.values() if message.conversation_id == str(conversation_id or "")]
        return sorted(matches, key=lambda message: (message.timestamp, message.message_id))

    def supports_send(self) -> bool:
        return True

    def requires_credentials(self) -> bool:
        return False

    def credentials_info(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "requires_credentials": False,
            "stores_credentials": False,
            "oauth": False,
            "cookies": False,
            "real_account": False,
            "external_connection": False,
            "send_is_mocked": True,
        }

    def errors(self) -> list[str]:
        return list(self._errors)

    # ------------------------------------------------------------------
    # Mocked send primitives. These are never called by read paths; the
    # approved, audited action layer is the only caller, and they never
    # reach a real communication account.
    # ------------------------------------------------------------------

    def send_message(
        self,
        *,
        conversation_id: str,
        channel: str,
        to: dict[str, str],
        content: str,
        in_reply_to: str = "",
    ) -> dict[str, Any]:
        recipient = redact_sensitive_data(to) if isinstance(to, dict) else {"id": redact_text(to)}
        if not str(recipient.get("id") or "").strip():
            raise ValueError("A send requires an exact recipient or participant identifier.")
        body = redact_text(content)
        if not body.strip():
            raise ValueError("A send requires message content.")
        sent_id = f"sent-{hashlib.sha256(f'{conversation_id}|{channel}|{recipient.get('id', '')}|{body}'.encode('utf-8')).hexdigest()[:16]}"
        binding = redact_sensitive_data({
            "sent_id": sent_id,
            "conversation_id": redact_text(conversation_id)[:300],
            "channel": redact_text(channel)[:200],
            "to": recipient,
            "content": body[:4000],
            "in_reply_to": redact_text(in_reply_to)[:300],
            "sent_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "provider": self.name,
        })
        self._sent[sent_id] = binding
        return dict(binding)

    def verify_send_binding(
        self,
        sent_id: str,
        *,
        conversation_id: str,
        channel: str,
        to: dict[str, str],
        content: str,
    ) -> bool:
        binding = self._sent.get(str(sent_id or ""))
        if not binding:
            return False
        stored_to = dict(binding.get("to") or {})
        expected_to = dict(to or {})
        return (
            str(stored_to.get("id") or "") == str(expected_to.get("id") or "")
            and str(binding.get("conversation_id") or "") == redact_text(conversation_id)
            and str(binding.get("channel") or "") == redact_text(channel)
            and str(binding.get("content") or "") == redact_text(content)
        )

    def get_sent(self, sent_id: str) -> dict[str, Any] | None:
        binding = self._sent.get(str(sent_id or ""))
        return dict(binding) if binding is not None else None


PROVIDER_REGISTRY: ProviderRegistry = ProviderRegistry()
PROVIDER_REGISTRY.register(FixtureCommsProvider())


def get_provider(name: str | None = None) -> CommsProvider:
    return PROVIDER_REGISTRY.get(name)


def get_provider_names() -> list[str]:
    return PROVIDER_REGISTRY.names()


def provider_credentials_required(name: str | None = None) -> bool:
    return bool(PROVIDER_REGISTRY.get(name).requires_credentials())


def registered_actions() -> tuple[str, ...]:
    return ("read", "list", "get_conversation", "prepare_draft")


__all__ = [
    "CommsProvider",
    "FixtureCommsProvider",
    "PROVIDER_REGISTRY",
    "ProviderRegistry",
    "get_provider",
    "get_provider_names",
    "provider_credentials_required",
    "registered_actions",
]