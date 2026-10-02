from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.memory.sqlite_memory import DEFAULT_DB_PATH
from app.security.sensitive_data import redact_sensitive_data, redact_text

MAX_AUDIT_FIELD_CHARS = 4000
MAX_AUDIT_METADATA_CHARS = 8000
MAX_AUDIT_QUERY_LIMIT = 100


def initialize_audit(db_path: str | Path | None = None) -> Path:
    """Create the append-oriented audit table and its history protections."""

    resolved_path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    resolved_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(str(resolved_path))
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                tool TEXT,
                risk_level TEXT,
                approval_required INTEGER NOT NULL DEFAULT 0,
                approved INTEGER NOT NULL DEFAULT 0,
                target TEXT,
                result TEXT,
                reason TEXT,
                metadata TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS audit_events_no_update
            BEFORE UPDATE ON audit_events
            BEGIN
                SELECT RAISE(ABORT, 'audit events are append-only');
            END
            """
        )
        connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
            BEFORE DELETE ON audit_events
            BEGIN
                SELECT RAISE(ABORT, 'audit events are append-only');
            END
            """
        )
        connection.commit()
    finally:
        connection.close()

    return resolved_path


def _bounded_text(value: Any, limit: int = MAX_AUDIT_FIELD_CHARS) -> str:
    text = redact_text(value)
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... [TRUNCATED]"


def _safe_metadata(metadata: dict[str, Any] | None) -> str:
    protected = redact_sensitive_data(metadata or {})
    serialized = json.dumps(protected, sort_keys=True, separators=(",", ":"), default=str)
    if len(serialized) > MAX_AUDIT_METADATA_CHARS:
        serialized = serialized[:MAX_AUDIT_METADATA_CHARS] + "... [TRUNCATED]"
    return serialized


def _insert_event(target_path: Path, fields: tuple[Any, ...]) -> bool:
    connection = sqlite3.connect(str(target_path))
    try:
        connection.execute(
            """
            INSERT INTO audit_events (
                timestamp, event_type, actor, tool, risk_level,
                approval_required, approved, target, result, reason, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            fields,
        )
        connection.commit()
        return True
    finally:
        connection.close()


def record_audit_event(
    event_type: str,
    *,
    actor: str = "nexus",
    tool: str = "",
    risk_level: str = "",
    approval_required: bool = False,
    approved: bool = False,
    target: str = "",
    result: str = "",
    reason: str = "",
    metadata: dict[str, Any] | None = None,
    db_path: str | Path | None = None,
    mirror_central: bool = False,
) -> bool:
    """Append one redacted, bounded audit event using parameterized SQL.

    When ``mirror_central`` is set, the same security-decision event is also
    appended to the central audit database (best effort) so approval,
    permission, scope, privacy, execution, and recovery decisions remain
    discoverable through the central audit view even when the primary record
    lives in a per-store database. Per-store records are never removed.
    Ordinary events must not set this flag.
    """

    try:
        target_path = initialize_audit(db_path)
        fields = (
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            _bounded_text(event_type, 120),
            _bounded_text(actor, 120),
            _bounded_text(tool, 120),
            _bounded_text(risk_level, 40),
            1 if approval_required else 0,
            1 if approved else 0,
            _bounded_text(target),
            _bounded_text(result),
            _bounded_text(reason),
            _safe_metadata(metadata),
        )
        primary_ok = _insert_event(target_path, fields)
        if mirror_central:
            try:
                central_path = initialize_audit(None)
                if target_path.resolve() != central_path.resolve():
                    _insert_event(central_path, fields)
            except Exception:
                pass
        return primary_ok
    except (OSError, sqlite3.Error, TypeError, ValueError):
        return False


def get_recent_audit_events(
    limit: int = 20,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Return a bounded, deterministic, redacted audit history newest first."""

    try:
        bounded_limit = max(1, min(int(limit), MAX_AUDIT_QUERY_LIMIT))
    except (TypeError, ValueError):
        bounded_limit = 20
    try:
        target_path = initialize_audit(db_path)
        connection = sqlite3.connect(str(target_path))
        try:
            rows = connection.execute(
                """
                SELECT id, timestamp, event_type, actor, tool, risk_level,
                       approval_required, approved, target, result, reason, metadata
                FROM audit_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (bounded_limit,),
            ).fetchall()
        finally:
            connection.close()
    except (OSError, sqlite3.Error, TypeError, ValueError):
        return []

    events: list[dict[str, Any]] = []
    for row in rows:
        metadata: Any = {}
        try:
            metadata = json.loads(row[11] or "{}")
        except (TypeError, json.JSONDecodeError):
            metadata = {"parse_error": "invalid audit metadata"}
        events.append(redact_sensitive_data({
            "id": row[0],
            "timestamp": row[1],
            "event_type": row[2],
            "actor": row[3],
            "tool": row[4],
            "risk_level": row[5],
            "approval_required": bool(row[6]),
            "approved": bool(row[7]),
            "target": row[8],
            "result": row[9],
            "reason": row[10],
            "metadata": metadata,
        }))
    return events


# Explicit aliases for callers that prefer action-oriented names.
append_audit_event = record_audit_event
query_recent_audit_events = get_recent_audit_events
