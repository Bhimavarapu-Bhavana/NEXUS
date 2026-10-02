"""Durable local-first User DNA layer.

User DNA distinguishes three record kinds with different authority:

- PREFERENCE: personalization hints (e.g. preferred editor, verbosity).
  May influence selection and presentation. NEVER authorizes actions.
- CONTEXT: durable background facts (e.g. timezone, project root).
  Informational only. NEVER authorizes actions.
- AUTHORIZATION: explicit user grants (e.g. access to sensitive data).
  The ONLY kind consulted by authorization checks. Explicit and revocable.

Security rules enforced here, not by convention:

- No passwords, API keys, tokens, private keys, or secrets are stored.
  Values tripping the sensitive-data heuristics are rejected outright.
- Authorization is never inferred from a preference or context record.
  Only AUTHORIZATION-kind records satisfy authorization checks.
- Nothing is silently invented: records require explicit provenance, and
  merely OBSERVED (unconfirmed) records are excluded from effective output.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.security.audit_logger import record_audit_event
from app.security.sensitive_data import (
    contains_sensitive_data,
    redact_sensitive_data,
    redact_text,
)

DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "nexus_dna.db"

DNA_KINDS = {"PREFERENCE", "CONTEXT", "AUTHORIZATION"}

DNA_CONFIDENCES = {"STATED", "OBSERVED", "CONFIRMED"}

# Only these confidences are ever surfaced as effective user DNA.
# OBSERVED records stay quarantined until the user states or confirms them,
# so NEXUS can never silently invent preferences.
EFFECTIVE_CONFIDENCES = {"STATED", "CONFIRMED"}

DNA_STATUSES = {"ACTIVE", "REVOKED", "EXPIRED"}

DNA_PROVENANCE_SOURCES = {"user-stated", "user-confirmed", "observed"}

DEFAULT_SUBJECT = "local-user"

MAX_KEY_CHARS = 120
MAX_VALUE_CHARS = 2000
MAX_SUBJECT_CHARS = 200
MAX_PROVENANCE_CHARS = 120
MAX_EXPIRY_CHARS = 80
MAX_METADATA_CHARS = 8000


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return (value or _now()).isoformat(timespec="seconds")


def _canonical_kind(value: Any) -> str:
    text = str(value or "").strip().upper()
    if text not in DNA_KINDS:
        raise ValueError(f"Unknown User DNA kind: {value}")
    return text


def _canonical_confidence(value: Any) -> str:
    text = str(value or "").strip().upper()
    if text not in DNA_CONFIDENCES:
        raise ValueError(f"Unknown User DNA confidence: {value}")
    return text


def _bounded_text(value: Any, limit: int, field: str) -> str:
    text = redact_text(value).strip()
    if not text:
        raise ValueError(f"User DNA {field} is required.")
    if len(text) > limit:
        raise ValueError(f"User DNA {field} exceeds the bounded length of {limit}.")
    return text


def _parse_expiry(value: str | None) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    if len(text) > MAX_EXPIRY_CHARS:
        raise ValueError("User DNA expires_at exceeds the bounded length.")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("User DNA expires_at must be a valid ISO timestamp.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.isoformat(timespec="seconds")


def _reject_secrets(key: str, value: str) -> None:
    if contains_sensitive_data(key) or contains_sensitive_data(value):
        raise ValueError(
            "User DNA must never store passwords, API keys, tokens, private keys, or secrets."
        )


def _audit(
    event_type: str,
    *,
    audit_db_path: str | Path | None = None,
    **payload: Any,
) -> None:
    try:
        record_audit_event(event_type, db_path=audit_db_path, mirror_central=True, **payload)
    except Exception:
        pass


def _db_path(db_path: str | Path | None = None) -> Path:
    path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    connection = sqlite3.connect(str(_db_path(db_path)))
    connection.row_factory = sqlite3.Row
    return connection


def initialize_dna_store(db_path: str | Path | None = None) -> Path:
    path = _db_path(db_path)
    connection = _connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS dna_records (
                dna_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                record_key TEXT NOT NULL,
                record_value TEXT NOT NULL DEFAULT '',
                confidence TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                subject TEXT NOT NULL DEFAULT 'local-user',
                provenance_source TEXT NOT NULL,
                provenance_actor TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                expires_at TEXT NOT NULL DEFAULT '',
                revoked_at TEXT NOT NULL DEFAULT '',
                revoked_reason TEXT NOT NULL DEFAULT '',
                metadata TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_dna_kind ON dna_records(kind)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_dna_key ON dna_records(record_key)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_dna_status ON dna_records(status)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_dna_subject ON dna_records(subject)")
        connection.commit()
    finally:
        connection.close()
    return path


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return redact_sensitive_data(dict(row))


def _expire_locked(connection: sqlite3.Connection) -> None:
    connection.execute(
        "UPDATE dna_records SET status = 'EXPIRED', revoked_at = ?, revoked_reason = 'User DNA record expired.' WHERE status = 'ACTIVE' AND expires_at != '' AND expires_at <= ?",
        (_iso(), _iso()),
    )


def create_dna_record(
    *,
    kind: str,
    key: str,
    value: str = "",
    confidence: str = "STATED",
    subject: str = DEFAULT_SUBJECT,
    provenance_source: str = "user-stated",
    provenance_actor: str = "",
    expires_at: str | None = None,
    metadata: dict[str, Any] | None = None,
    db_path: str | Path | None = None,
    audit_db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Create one User DNA record with explicit provenance.

    Provenance is mandatory: callers must state where the record came from.
    Secrets are rejected before storage, never redacted-after-the-fact.
    """
    canon_kind = _canonical_kind(kind)
    canon_confidence = _canonical_confidence(confidence)
    # Screen the raw inputs BEFORE any redaction: redaction would otherwise
    # mask the very secret it is meant to catch.
    raw_key = str(key or "").strip()
    raw_value = str(value or "")
    if not raw_key:
        raise ValueError("User DNA key is required.")
    if len(raw_key) > MAX_KEY_CHARS:
        raise ValueError(f"User DNA key exceeds the bounded length of {MAX_KEY_CHARS}.")
    if len(raw_value) > MAX_VALUE_CHARS:
        raise ValueError(f"User DNA value exceeds the bounded length of {MAX_VALUE_CHARS}.")
    _reject_secrets(raw_key, raw_value)
    canon_key = redact_text(raw_key)
    safe_value = redact_text(raw_value).strip()
    canon_subject = _bounded_text(subject or DEFAULT_SUBJECT, MAX_SUBJECT_CHARS, "subject")
    provenance = str(provenance_source or "").strip().lower()
    if provenance not in DNA_PROVENANCE_SOURCES:
        raise ValueError(f"User DNA requires explicit provenance: {provenance_source}")
    expiry = _parse_expiry(expires_at)
    _reject_secrets(canon_key, safe_value)
    packed_metadata = json.dumps(
        redact_sensitive_data(metadata or {}), sort_keys=True, ensure_ascii=True
    )
    if len(packed_metadata) > MAX_METADATA_CHARS:
        raise ValueError("User DNA metadata exceeds the bounded size.")
    initialize_dna_store(db_path)
    connection = _connect(db_path)
    try:
        _expire_locked(connection)
        dna_id = f"dna-{uuid.uuid4().hex[:16]}"
        connection.execute(
            "INSERT INTO dna_records (dna_id, kind, record_key, record_value, confidence, status, subject, provenance_source, provenance_actor, created_at, updated_at, expires_at, metadata) VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?, ?, ?)",
            (
                dna_id,
                canon_kind,
                canon_key,
                safe_value,
                canon_confidence,
                canon_subject,
                provenance,
                redact_text(provenance_actor)[:MAX_PROVENANCE_CHARS],
                _iso(),
                _iso(),
                expiry,
                packed_metadata,
            ),
        )
        connection.commit()
        record = _row(connection.execute("SELECT * FROM dna_records WHERE dna_id = ?", (dna_id,)).fetchone())
    finally:
        connection.close()
    _audit(
        "dna_created",
        audit_db_path=audit_db_path,
        actor="user_dna",
        tool="user_dna",
        target=canon_key,
        result="ACTIVE",
        reason=f"User DNA {canon_kind} record created with {canon_confidence} confidence.",
        metadata={"dna_id": dna_id, "kind": canon_kind, "key": canon_key, "subject": canon_subject},
    )
    return record or {}


def get_dna_record(dna_id: str, *, db_path: str | Path | None = None) -> dict[str, Any] | None:
    if not dna_id:
        return None
    initialize_dna_store(db_path)
    connection = _connect(db_path)
    try:
        _expire_locked(connection)
        connection.commit()
        return _row(connection.execute("SELECT * FROM dna_records WHERE dna_id = ?", (dna_id,)).fetchone())
    finally:
        connection.close()


def list_dna_records(
    *,
    kind: str | None = None,
    status: str | None = None,
    subject: str | None = None,
    limit: int = 50,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    initialize_dna_store(db_path)
    connection = _connect(db_path)
    try:
        _expire_locked(connection)
        connection.commit()
        query = "SELECT * FROM dna_records WHERE 1=1"
        params: list[Any] = []
        if kind:
            query += " AND kind = ?"
            params.append(_canonical_kind(kind))
        if status:
            normalized = str(status or "").strip().upper()
            if normalized not in DNA_STATUSES:
                raise ValueError(f"Invalid User DNA status: {status}")
            query += " AND status = ?"
            params.append(normalized)
        if subject:
            query += " AND subject = ?"
            params.append(_bounded_text(subject, MAX_SUBJECT_CHARS, "subject"))
        query += " ORDER BY created_at DESC LIMIT ?"
        try:
            bounded = max(1, min(int(limit), 100))
        except (TypeError, ValueError):
            bounded = 50
        params.append(bounded)
        return [_row(row) for row in connection.execute(query, params).fetchall()]
    finally:
        connection.close()


def revoke_dna_record(
    dna_id: str,
    reason: str,
    *,
    db_path: str | Path | None = None,
    audit_db_path: str | Path | None = None,
) -> dict[str, Any] | None:
    if not reason or not str(reason).strip():
        raise ValueError("Revocation reason is required.")
    initialize_dna_store(db_path)
    connection = _connect(db_path)
    try:
        cursor = connection.execute(
            "UPDATE dna_records SET status = 'REVOKED', revoked_at = ?, revoked_reason = ? WHERE dna_id = ? AND status = 'ACTIVE'",
            (_iso(), redact_text(reason)[:500], dna_id),
        )
        revoked_now = cursor.rowcount == 1
        connection.commit()
        record = _row(connection.execute("SELECT * FROM dna_records WHERE dna_id = ?", (dna_id,)).fetchone())
    finally:
        connection.close()
    if record is None:
        _audit(
            "dna_revoke_rejected",
            audit_db_path=audit_db_path,
            actor="user_dna",
            tool="user_dna",
            target=str(dna_id or ""),
            result="NOT_FOUND",
            reason="Revocation target does not exist.",
            metadata={"dna_id": str(dna_id or "")},
        )
        return None
    _audit(
        "dna_revoked" if revoked_now else "dna_revoke_rejected",
        audit_db_path=audit_db_path,
        actor="user_dna",
        tool="user_dna",
        target=str(record.get("record_key") or ""),
        result=str(record.get("status") or ""),
        reason=redact_text(reason)[:500],
        metadata={"dna_id": str(record.get("dna_id") or ""), "kind": str(record.get("kind") or "")},
    )
    return record


def get_effective_preferences(
    *,
    subject: str = DEFAULT_SUBJECT,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Return ACTIVE PREFERENCE records with STATED or CONFIRMED confidence.

    OBSERVED records are quarantined here: personalization may only act on
    what the user stated or confirmed, never on what NEXUS guessed.
    """
    records = list_dna_records(kind="PREFERENCE", status="ACTIVE", subject=subject, db_path=db_path)
    return [record for record in records if str(record.get("confidence") or "").upper() in EFFECTIVE_CONFIDENCES]


def check_authorization(
    key: str,
    *,
    subject: str = DEFAULT_SUBJECT,
    db_path: str | Path | None = None,
) -> bool:
    """Return True only for an ACTIVE, non-expired AUTHORIZATION record.

    Preferences and context records can never satisfy this check, no matter
    their key or value: authorization is never inferred.
    """
    canon_key = str(key or "").strip()
    if not canon_key:
        return False
    initialize_dna_store(db_path)
    connection = _connect(db_path)
    try:
        _expire_locked(connection)
        connection.commit()
        row = connection.execute(
            "SELECT dna_id FROM dna_records WHERE kind = 'AUTHORIZATION' AND record_key = ? AND subject = ? AND status = 'ACTIVE' ORDER BY created_at DESC LIMIT 1",
            (canon_key, str(subject or DEFAULT_SUBJECT).strip()),
        ).fetchone()
        return row is not None
    finally:
        connection.close()


__all__ = [
    "DEFAULT_DB_PATH",
    "DEFAULT_SUBJECT",
    "DNA_CONFIDENCES",
    "DNA_KINDS",
    "DNA_PROVENANCE_SOURCES",
    "DNA_STATUSES",
    "EFFECTIVE_CONFIDENCES",
    "check_authorization",
    "create_dna_record",
    "get_dna_record",
    "get_effective_preferences",
    "initialize_dna_store",
    "list_dna_records",
    "revoke_dna_record",
]
