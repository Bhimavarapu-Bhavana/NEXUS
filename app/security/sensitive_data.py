from __future__ import annotations

import re
from typing import Any

REDACTION_MARKER = "[REDACTED]"

_PLACEHOLDERS = {
    "",
    "changeme",
    "example",
    "example.com",
    "hello",
    "none",
    "null",
    "password",
    "secret",
    "test",
    "token",
    "your_token",
    "your-password",
}

_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_BEARER_PATTERN = re.compile(r"(?i)(\bbearer\s+)[^\s,;]+")
_AUTH_PATTERN = re.compile(r"(?i)(\bauthorization\s*:\s*(?:bearer\s+)?)[^\s,;]+")
_CONNECTION_PASSWORD_PATTERN = re.compile(
    r"(?i)(\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:/]+:)[^\s@]+(@)"
)
_CLOUD_KEY_PATTERN = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9][A-Za-z0-9_-]{15,})\b"
)
_SENSITIVE_PHRASE_PATTERN = re.compile(r"(?i)\b(?:secret\s+token|private\s+key)\b")
_NAMED_SECRET_PATTERN = re.compile(
    r"(?i)\b[A-Za-z0-9]+[_-](?:secret|token|password|api[_-]?key)[_-][A-Za-z0-9_-]+\b"
)
_SECRET_WORD_VALUE_PATTERN = re.compile(
    r"(?i)\b[A-Za-z0-9_-]*(?:secret|token|password)(?:[_-][A-Za-z0-9]+)+\b"
)
_KEY_VALUE_PATTERN = re.compile(
    r"(?i)([\"']?(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|secret|token|aws_secret_access_key|private[_-]?key)[\"']?\s*[:=]\s*)([\"']?)([^\s,;\"']+)(\2)"
)
_QUOTED_KEY_VALUE_PATTERN = re.compile(
    r"(?i)(['\"](?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|secret|token|aws_secret_access_key|private[_-]?key)['\"]\s*:\s*['\"]?)([^'\"\s,;]+)(['\"]?)"
)


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().lower()
    return (
        normalized in _PLACEHOLDERS
        or normalized.startswith("<")
        or normalized.startswith("${")
        or normalized.startswith("your_")
        or normalized.startswith("your-")
    )


def _replace_key_value(match: re.Match[str]) -> str:
    value = match.group(3)
    if _is_placeholder(value):
        return match.group(0)
    return f"{match.group(1)}{match.group(2)}{REDACTION_MARKER}{match.group(4)}"


def redact_sensitive_data(value: Any) -> Any:
    """Return a protected copy of strings and nested containers.

    Detection is heuristic and bounded to common credential-shaped patterns;
    it cannot guarantee discovery of every sensitive value.
    """

    if isinstance(value, str):
        protected = _PRIVATE_KEY_PATTERN.sub(REDACTION_MARKER, value)
        protected = _AUTH_PATTERN.sub(rf"\1{REDACTION_MARKER}", protected)
        protected = _BEARER_PATTERN.sub(rf"\1{REDACTION_MARKER}", protected)
        protected = _CONNECTION_PASSWORD_PATTERN.sub(rf"\1{REDACTION_MARKER}\2", protected)
        protected = _QUOTED_KEY_VALUE_PATTERN.sub(rf"\1{REDACTION_MARKER}\3", protected)
        protected = _KEY_VALUE_PATTERN.sub(_replace_key_value, protected)
        protected = _SENSITIVE_PHRASE_PATTERN.sub(REDACTION_MARKER, protected)
        protected = _NAMED_SECRET_PATTERN.sub(REDACTION_MARKER, protected)
        protected = _SECRET_WORD_VALUE_PATTERN.sub(REDACTION_MARKER, protected)
        return _CLOUD_KEY_PATTERN.sub(REDACTION_MARKER, protected)

    if isinstance(value, dict):
        return {
            key: (
                REDACTION_MARKER
                if isinstance(key, str)
                and any(marker in key.lower() for marker in ("password", "secret", "token", "api_key", "private_key"))
                and isinstance(item, str)
                and not _is_placeholder(item)
                else redact_sensitive_data(item)
            )
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [redact_sensitive_data(item) for item in value]

    if isinstance(value, tuple):
        return tuple(redact_sensitive_data(item) for item in value)

    return value


def contains_sensitive_data(value: Any) -> bool:
    """Return whether heuristic redaction would change the supplied value."""

    protected = redact_sensitive_data(value)
    return protected != value


def redact_mapping(value: dict[Any, Any]) -> dict[Any, Any]:
    """Return a recursively protected copy of a mapping."""

    result = redact_sensitive_data(value)
    return result if isinstance(result, dict) else {}


def redact_sequence(value: list[Any] | tuple[Any, ...]) -> list[Any] | tuple[Any, ...]:
    """Return a recursively protected copy of a sequence."""

    result = redact_sensitive_data(value)
    return result


def redact_text(value: Any) -> str:
    """Protect a value for legacy text-only evidence and memory fields."""

    protected = redact_sensitive_data("" if value is None else str(value))
    return protected if isinstance(protected, str) else str(protected)
