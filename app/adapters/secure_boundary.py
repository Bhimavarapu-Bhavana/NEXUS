from __future__ import annotations

import hashlib
import re
from typing import Any

from app.adapters.model import ProviderDescriptor, ProviderKind
from app.security.sensitive_data import redact_text

_SECRET_PATTERNS = re.compile(r"(?i)(password|passwd|pwd|token|secret|api[_-]?key|client[_-]?secret|bearer|authorization|private[_-]?key|otp|one[_-]?time[_-]?code|cookie)\s*[=:]\s*\S+")

MAX_HANDLE_LENGTH = 80
MAX_SECRET_CHARS = 4000


def _redact_secret_markers(text: str) -> str:
    return _SECRET_PATTERNS.sub(r"\g<1>=***REDACTED***", redact_text(text))


class SecureCredentialBoundary:
    """Secure boundary for provider credentials.

    Requirements enforced here:
    * Credentials are never persisted (no plaintext credential database).
    * Credentials never enter prompts, task state, logs, evidence, or audit.
    * Deterministic mock authorization is used for fixture and mock providers.
    * Real providers remain unauthenticated unless an opaque in-memory handle is
      injected through this boundary; otherwise they fail closed.
    """

    def __init__(self) -> None:
        self._secrets: dict[str, str] = {}
        self._handles: dict[str, str] = {}
        self._mock_authorized: dict[str, bool] = {}

    def inject_credential(self, provider_id: str, secret: str) -> str:
        """Inject one credential in memory only and return an opaque handle."""
        cleaned = str(secret or "")
        if not cleaned or len(cleaned) > MAX_SECRET_CHARS:
            raise ValueError("A credential handle requires bounded non-empty secret material.")
        key = str(provider_id or "").strip()
        handle = "cred-handle-" + hashlib.sha256(f"{key}|{cleaned}".encode("utf-8")).hexdigest()[:24]
        self._secrets[key] = cleaned
        self._handles[handle] = key
        return handle

    def mock_authenticate(self, provider_id: str, *, kind: ProviderKind) -> bool:
        """Deterministic mock authorization for fixture/mock providers.

        No secret material exists; the result is derived purely from the provider
        id and a local fixed namespace, so it is deterministic and never a real
        secret."""
        if kind not in {ProviderKind.FIXTURE_PROVIDER, ProviderKind.MOCK_PROVIDER}:
            self._mock_authorized[str(provider_id or "").strip()] = False
            return False
        key = str(provider_id or "").strip()
        self._mock_authorized[key] = True
        return True

    def is_authenticated(self, provider_id: str) -> bool:
        return bool(self._mock_authorized.get(str(provider_id or "").strip(), False))

    def authorize_descriptor(self, descriptor: ProviderDescriptor) -> ProviderDescriptor:
        """Return a descriptor whose authentication reflects deterministic mock
        authorization (fixture/mock) or explicit in-memory credential injection
        (real providers only when a handle was injected)."""
        if descriptor.kind in {ProviderKind.FIXTURE_PROVIDER, ProviderKind.MOCK_PROVIDER}:
            self.mock_authenticate(descriptor.provider_id, kind=descriptor.kind)
            authenticated = self.is_authenticated(descriptor.provider_id)
        elif descriptor.kind == ProviderKind.REAL_PROVIDER:
            authenticated = bool(
                descriptor.authenticated
                and descriptor.configured
                and descriptor.provider_id in self._secrets
                and self._secrets.get(descriptor.provider_id)
            )
        else:
            authenticated = False
        return ProviderDescriptor(
            provider_id=descriptor.provider_id,
            application_id=descriptor.application_id,
            display_name=descriptor.display_name,
            kind=descriptor.kind,
            capabilities=descriptor.capabilities,
            capability_grants=descriptor.capability_grants,
            credential_requirement=descriptor.credential_requirement,
            stores_credentials=False,
            oauth=descriptor.oauth,
            real_account=descriptor.real_account,
            external_connection=descriptor.external_connection,
            send_is_mocked=descriptor.send_is_mocked,
            mutation_is_mocked=descriptor.mutation_is_mocked,
            configured=descriptor.configured,
            authenticated=authenticated,
            description=descriptor.description,
        )

    def reveal(self, handle: str) -> str:
        """Return the in-memory secret material for an injected handle.

        This is deliberately restricted to the secure boundary; it never feeds
        prompts, task state, logs, evidence, or audit records."""
        provider_id = self._handles.get(str(handle or ""), "")
        return self._secrets.get(provider_id, "")

    def scrub(self, text: str) -> str:
        """Redact any credential-like markers before content enters evidence."""
        return _redact_secret_markers(text)

    def has_credentials(self, provider_id: str) -> bool:
        return bool(self._secrets.get(str(provider_id or "").strip()))


SECURE_BOUNDARY = SecureCredentialBoundary()


__all__ = ["SECURE_BOUNDARY", "SecureCredentialBoundary"]