from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Protocol

from app.email.fixtures import DEFAULT_PROVIDER, DISPLAY_NAME, OWN_ACCOUNTS, build_default_fixture_messages
from app.email.models import MAX_EMAIL_MESSAGES, EmailMessage, normalize_email_message
from app.security.sensitive_data import redact_sensitive_data, redact_text


class EmailProvider(Protocol):
    """Provider-independent email abstraction.

    Read operations are the only interface a provider must expose. Sending is
    an explicitly declared capability invoked only through the bounded,
    approval-gated action layer.
    """

    name: str

    def list_messages(self) -> list[EmailMessage]: ...

    def get_message(self, message_id: str) -> EmailMessage | None: ...

    def get_thread(self, thread_id: str) -> list[EmailMessage]: ...

    def supports_send(self) -> bool: ...

    def requires_credentials(self) -> bool: ...


class ProviderRegistry:
    """Deterministic, ordered registry of email providers."""

    def __init__(self) -> None:
        self._providers: dict[str, EmailProvider] = {}

    def register(self, provider: EmailProvider) -> None:
        name = str(getattr(provider, "name", "") or "").strip()
        if not name:
            raise ValueError("An email provider requires a name.")
        self._providers[name] = provider

    def get(self, name: str | None = None) -> EmailProvider:
        key = str(name or "").strip() or DEFAULT_PROVIDER
        provider = self._providers.get(key)
        if provider is None:
            raise ValueError(f"Email provider {key} is not registered.")
        return provider

    def names(self) -> list[str]:
        return sorted(self._providers)

    def exists(self, name: str | None = None) -> bool:
        key = str(name or "").strip() or DEFAULT_PROVIDER
        return key in self._providers


class FixtureEmailProvider:
    """Deterministic local email provider for tests and offline runs.

    No real account, no credentials, no network. Sending is mocked strictly
    for exercising the security/approval pipeline and is never a real send.
    """

    def __init__(self, messages: list[dict[str, Any]] | list[EmailMessage] | None = None) -> None:
        self.name = DEFAULT_PROVIDER
        self.display_name = DISPLAY_NAME
        self.own_accounts = OWN_ACCOUNTS
        raw_messages = messages if messages is not None else build_default_fixture_messages()
        self._messages: dict[str, EmailMessage] = {}
        self._errors: list[str] = []
        self._observed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._ingest(raw_messages)
        self._sent: dict[str, dict[str, Any]] = {}

    def _ingest(self, messages: list[dict[str, Any]] | list[EmailMessage]) -> None:
        validated: list[EmailMessage] = []
        for index, item in enumerate(messages[:MAX_EMAIL_MESSAGES]):
            try:
                message = item if isinstance(item, EmailMessage) else normalize_email_message(item, provider=self.name, observed_at=self._observed_at)
            except (TypeError, ValueError) as exc:
                self._errors.append(f"fixture[{index}]: {redact_text(exc)}")
                continue
            validated.append(message)
        self._messages = {}
        for message in validated:
            self._messages[message.message_id] = message

    def list_messages(self) -> list[EmailMessage]:
        ordered = sorted(self._messages.values(), key=lambda message: (message.timestamp, message.message_id))
        return [message for message in ordered]

    def get_message(self, message_id: str) -> EmailMessage | None:
        return self._messages.get(str(message_id or ""))

    def get_thread(self, thread_id: str) -> list[EmailMessage]:
        matches = [message for message in self._messages.values() if message.thread_id == str(thread_id or "")]
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
            "real_account": False,
            "external_connection": False,
            "send_is_mocked": True,
        }

    def errors(self) -> list[str]:
        return list(self._errors)

    # ------------------------------------------------------------------
    # Mocked send primitives. These are never called by read paths; the
    # approved, audited action layer is the only caller, and they never
    # reach a real email account.
    # ------------------------------------------------------------------

    def send_message(
        self,
        *,
        to: dict[str, str],
        subject: str,
        body: str,
        in_reply_to: str = "",
        thread_id: str = "",
    ) -> dict[str, Any]:
        recipient = redact_sensitive_data(to) if isinstance(to, dict) else {"email": redact_text(to)}
        if not str(recipient.get("email") or "").strip():
            raise ValueError("A send requires an exact recipient address.")
        if not redact_text(subject).strip():
            raise ValueError("A send requires a subject.")
        message_body = redact_text(body)
        if not message_body.strip():
            raise ValueError("A send requires message content.")
        sent_id = f"sent-{hashlib.sha256(f'{recipient.get('email', '')}|{redact_text(subject)}|{message_body}'.encode('utf-8')).hexdigest()[:16]}"
        binding = redact_sensitive_data({
            "sent_id": sent_id,
            "to": recipient,
            "subject": redact_text(subject)[:1000],
            "body": message_body[:4000],
            "in_reply_to": redact_text(in_reply_to)[:300],
            "thread_id": redact_text(thread_id)[:300],
            "sent_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "provider": self.name,
        })
        self._sent[sent_id] = binding
        return dict(binding)

    def verify_send_binding(self, sent_id: str, *, to: dict[str, str], subject: str, body: str) -> bool:
        binding = self._sent.get(str(sent_id or ""))
        if not binding:
            return False
        stored_to = dict(binding.get("to") or {})
        expected_to = dict(to or {})
        return (
            str(stored_to.get("email") or "") == str(expected_to.get("email") or "")
            and str(stored_to.get("name") or "") == str(expected_to.get("name") or "")
            and str(binding.get("subject") or "") == redact_text(subject)
            and str(binding.get("body") or "") == redact_text(body)
        )

    def get_sent(self, sent_id: str) -> dict[str, Any] | None:
        binding = self._sent.get(str(sent_id or ""))
        return dict(binding) if binding is not None else None


PROVIDER_REGISTRY: ProviderRegistry = ProviderRegistry()
PROVIDER_REGISTRY.register(FixtureEmailProvider())


def get_provider(name: str | None = None) -> EmailProvider:
    return PROVIDER_REGISTRY.get(name)


def get_provider_names() -> list[str]:
    return PROVIDER_REGISTRY.names()


def provider_credentials_required(name: str | None = None) -> bool:
    return bool(PROVIDER_REGISTRY.get(name).requires_credentials())


def registered_actions() -> tuple[str, ...]:
    return ("read", "list", "get_thread", "prepare_draft")


__all__ = [
    "EmailProvider",
    "FixtureEmailProvider",
    "PROVIDER_REGISTRY",
    "ProviderRegistry",
    "get_provider",
    "get_provider_names",
    "provider_credentials_required",
    "registered_actions",
]