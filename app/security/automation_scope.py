"""Durable automation-scope controls.

Automation scopes answer a different question than permissions:

- Permission Authority = whether NEXUS may PERFORM a specific action.
- Automation Scope = whether a capability AREA is enabled for automation
  at all, for which targets, and for which task.

Both must pass. A permission never overrides a scope denial, and a scope
grant never authorizes an action. There is exactly one scope store and one
scope vocabulary; no parallel permission system is introduced here.

Scope areas cover the existing NEXUS capability surface: workspace/files,
Git, browser, desktop, email, calendar, communications, and security
scanning. No arbitrary shell execution or unrestricted automation exists in
any area: scopes only ever gate the already-allowlisted tool set.

Fail-closed throughout: an area with no ACTIVE ALLOW grant is denied.
"""

from __future__ import annotations

import fnmatch
import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.security.audit_logger import record_audit_event
from app.security.sensitive_data import redact_sensitive_data, redact_text
from app.tools.tool_registry import TOOL_REGISTRY

DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "nexus_scopes.db"

SCOPE_AREAS = {"workspace", "git", "browser", "desktop", "email", "calendar", "comms", "security"}

SCOPE_DECISIONS = {"ALLOW", "DENY"}

SCOPE_OUTCOMES = {"ALLOWED", "DENIED", "EXPIRED", "REVOKED", "UNKNOWN_AREA"}

SCOPE_STATUSES = {"ACTIVE", "EXPIRED", "REVOKED"}

MAX_AREA_CHARS = 40
MAX_PATTERN_CHARS = 500
MAX_TASK_ID_CHARS = 200
MAX_EXPIRY_CHARS = 80
MAX_TARGET_CHARS = 2000
MAX_METADATA_CHARS = 8000


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return (value or _now()).isoformat(timespec="seconds")


def _canonical_area(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text not in SCOPE_AREAS:
        raise ValueError(f"Unknown automation scope area: {value}")
    return text


def _canonical_decision(value: Any) -> str:
    text = str(value or "").strip().upper()
    if text not in SCOPE_DECISIONS:
        raise ValueError(f"Unknown automation scope decision: {value}")
    return text


def _canonical_task_id(value: Any) -> str:
    text = redact_text(value).strip()
    if len(text) > MAX_TASK_ID_CHARS:
        raise ValueError(f"Automation scope task_id exceeds the bounded length of {MAX_TASK_ID_CHARS}.")
    return text


def _canonical_pattern(value: Any) -> str:
    text = redact_text(value).strip()
    if len(text) > MAX_PATTERN_CHARS:
        raise ValueError(f"Automation scope target_pattern exceeds the bounded length of {MAX_PATTERN_CHARS}.")
    return text


def _parse_expiry(value: str | None) -> str:
    if value is None:
        return _iso(_now() + timedelta(days=30))
    text = str(value).strip()
    if not text:
        raise ValueError("Automation scope expires_at must be a valid ISO timestamp.")
    if len(text) > MAX_EXPIRY_CHARS:
        raise ValueError("Automation scope expires_at exceeds the bounded length.")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Automation scope expires_at must be a valid ISO timestamp.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.isoformat(timespec="seconds")


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


def initialize_scope_store(db_path: str | Path | None = None) -> Path:
    path = _db_path(db_path)
    connection = _connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS automation_scopes (
                scope_id TEXT PRIMARY KEY,
                area TEXT NOT NULL,
                decision TEXT NOT NULL,
                target_pattern TEXT NOT NULL DEFAULT '',
                task_id TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL DEFAULT '',
                revoked_at TEXT NOT NULL DEFAULT '',
                revoked_reason TEXT NOT NULL DEFAULT '',
                metadata TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_scopes_area ON automation_scopes(area)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_scopes_task ON automation_scopes(task_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_scopes_status ON automation_scopes(status)")
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
        "UPDATE automation_scopes SET status = 'EXPIRED', revoked_at = ?, revoked_reason = 'Automation scope expired.' WHERE status = 'ACTIVE' AND expires_at != '' AND expires_at <= ?",
        (_iso(), _iso()),
    )


def _task_matches(scope_task_id: str, request_task_id: str, *, allow_global: bool) -> bool:
    stored = str(scope_task_id or "")
    requested = str(request_task_id or "")
    if not requested:
        return stored == ""
    if stored == requested:
        return True
    if stored == "" and allow_global:
        return True
    return False


def scope_area_for_tool(tool_name: str) -> str:
    """Map a registry tool to its automation-scope area, deterministically.

    Reads the Tool Registry's own ``application`` metadata and the same
    tool-name prefixes the executor already uses. Unknown tools raise
    ValueError so scope gates fail closed.
    """
    name = str(tool_name or "").strip()
    metadata = TOOL_REGISTRY.get(name)
    if not metadata or not metadata.get("allowed"):
        raise ValueError(f"Tool is not authorized by the Tool Registry: {tool_name}")
    if name.startswith("browser_"):
        return "browser"
    if name.startswith("desktop_"):
        return "desktop"
    if name.startswith("git_"):
        return "git"
    application = str(metadata.get("application") or "").strip().lower()
    if application in {"email", "calendar", "comms", "security"}:
        return application
    if "email" in name:
        return "email"
    if "calendar" in name:
        return "calendar"
    if "comms" in name:
        return "comms"
    if "security" in name or "scan" in name:
        return "security"
    return "workspace"


def grant_scope(
    *,
    area: str,
    decision: str = "ALLOW",
    target_pattern: str = "",
    task_id: str = "",
    expires_at: str | None = None,
    metadata: dict[str, Any] | None = None,
    db_path: str | Path | None = None,
    audit_db_path: str | Path | None = None,
) -> dict[str, Any]:
    canon_area = _canonical_area(area)
    canon_decision = _canonical_decision(decision)
    canon_pattern = _canonical_pattern(target_pattern)
    canon_task = _canonical_task_id(task_id)
    expiry = _parse_expiry(expires_at)
    packed_metadata = json.dumps(
        redact_sensitive_data(metadata or {}), sort_keys=True, ensure_ascii=True
    )
    if len(packed_metadata) > MAX_METADATA_CHARS:
        raise ValueError("Automation scope metadata exceeds the bounded size.")
    initialize_scope_store(db_path)
    connection = _connect(db_path)
    try:
        _expire_locked(connection)
        scope_id = f"scope-{uuid.uuid4().hex[:16]}"
        connection.execute(
            "INSERT INTO automation_scopes (scope_id, area, decision, target_pattern, task_id, status, created_at, expires_at, metadata) VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?)",
            (scope_id, canon_area, canon_decision, canon_pattern, canon_task, _iso(), expiry, packed_metadata),
        )
        connection.commit()
        record = _row(connection.execute("SELECT * FROM automation_scopes WHERE scope_id = ?", (scope_id,)).fetchone())
    finally:
        connection.close()
    _audit(
        "scope_granted",
        audit_db_path=audit_db_path,
        actor="automation_scope",
        tool="automation_scope",
        target=canon_pattern or canon_area,
        result=canon_decision,
        reason=f"Automation scope {canon_decision} granted for area {canon_area}.",
        metadata={"scope_id": scope_id, "area": canon_area, "task_id": canon_task},
    )
    return record or {}


def get_scope(scope_id: str, *, db_path: str | Path | None = None) -> dict[str, Any] | None:
    if not scope_id:
        return None
    initialize_scope_store(db_path)
    connection = _connect(db_path)
    try:
        _expire_locked(connection)
        connection.commit()
        return _row(connection.execute("SELECT * FROM automation_scopes WHERE scope_id = ?", (scope_id,)).fetchone())
    finally:
        connection.close()


def list_scopes(
    *,
    area: str | None = None,
    status: str | None = None,
    task_id: str | None = None,
    limit: int = 50,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    initialize_scope_store(db_path)
    connection = _connect(db_path)
    try:
        _expire_locked(connection)
        connection.commit()
        query = "SELECT * FROM automation_scopes WHERE 1=1"
        params: list[Any] = []
        if area:
            query += " AND area = ?"
            params.append(_canonical_area(area))
        if status:
            normalized = str(status or "").strip().upper()
            if normalized not in SCOPE_STATUSES:
                raise ValueError(f"Invalid automation scope status: {status}")
            query += " AND status = ?"
            params.append(normalized)
        if task_id:
            query += " AND task_id = ?"
            params.append(_canonical_task_id(task_id))
        query += " ORDER BY created_at DESC LIMIT ?"
        try:
            bounded = max(1, min(int(limit), 100))
        except (TypeError, ValueError):
            bounded = 50
        params.append(bounded)
        return [_row(row) for row in connection.execute(query, params).fetchall()]
    finally:
        connection.close()


def revoke_scope(
    scope_id: str,
    reason: str,
    *,
    db_path: str | Path | None = None,
    audit_db_path: str | Path | None = None,
) -> dict[str, Any] | None:
    if not reason or not str(reason).strip():
        raise ValueError("Revocation reason is required.")
    initialize_scope_store(db_path)
    connection = _connect(db_path)
    try:
        cursor = connection.execute(
            "UPDATE automation_scopes SET status = 'REVOKED', revoked_at = ?, revoked_reason = ? WHERE scope_id = ? AND status = 'ACTIVE'",
            (_iso(), redact_text(reason)[:500], scope_id),
        )
        revoked_now = cursor.rowcount == 1
        connection.commit()
        record = _row(connection.execute("SELECT * FROM automation_scopes WHERE scope_id = ?", (scope_id,)).fetchone())
    finally:
        connection.close()
    if record is None:
        _audit(
            "scope_revoke_rejected",
            audit_db_path=audit_db_path,
            actor="automation_scope",
            tool="automation_scope",
            target=str(scope_id or ""),
            result="NOT_FOUND",
            reason="Revocation target does not exist.",
            metadata={"scope_id": str(scope_id or "")},
        )
        return None
    _audit(
        "scope_revoked" if revoked_now else "scope_revoke_rejected",
        audit_db_path=audit_db_path,
        actor="automation_scope",
        tool="automation_scope",
        target=str(record.get("target_pattern") or record.get("area") or ""),
        result=str(record.get("status") or ""),
        reason=redact_text(reason)[:500],
        metadata={"scope_id": str(record.get("scope_id") or ""), "area": str(record.get("area") or "")},
    )
    return record


def _matches_pattern(target: str, pattern: str) -> bool:
    text = str(target or "")
    expression = str(pattern or "")
    if not expression:
        return True
    if len(text) > MAX_TARGET_CHARS or len(expression) > MAX_PATTERN_CHARS:
        return False
    return fnmatch.fnmatchcase(text, expression)


def check_scope(
    *,
    area: str,
    target: str,
    task_id: str = "",
    db_path: str | Path | None = None,
    audit_db_path: str | Path | None = None,
    allow_global: bool = False,
) -> dict[str, Any]:
    """Decide whether automation in the area may proceed for the target.

    Fail-closed: an area with no matching ACTIVE ALLOW grant is denied.
    An explicit DENY grant whose boundary matches the target wins over any
    ALLOW grant, regardless of creation order. Expired and revoked grants
    can never authorize; when they are the only match the outcome names them
    (EXPIRED / REVOKED) instead of a bare denial. Task-bound grants
    authorize only their exact task unless the caller explicitly passes
    allow_global=True for global grants.
    """
    canon_area = _canonical_area(area)
    request_task = _canonical_task_id(task_id)
    target_text = str(target or "")
    base = {"area": canon_area, "target": target_text, "task_id": request_task}
    initialize_scope_store(db_path)
    connection = _connect(db_path)
    try:
        _expire_locked(connection)
        connection.commit()
        rows = connection.execute(
            "SELECT * FROM automation_scopes WHERE area = ? ORDER BY created_at DESC",
            (canon_area,),
        ).fetchall()
        task_rows = [
            dict(row)
            for row in rows
            if _task_matches(str(dict(row).get("task_id") or ""), request_task, allow_global=allow_global)
        ]
        active_rows = [scope for scope in task_rows if scope.get("status") == "ACTIVE"]

        if not active_rows:
            if any(scope.get("status") == "REVOKED" for scope in task_rows):
                revoked = next(scope for scope in task_rows if scope.get("status") == "REVOKED")
                return _audited(
                    "REVOKED", False,
                    f"Automation scope {revoked.get('scope_id')} was revoked and cannot authorize {canon_area}.",
                    {**base, "scope_id": str(revoked.get("scope_id") or "")},
                    audit_db_path=audit_db_path,
                )
            if any(scope.get("status") == "EXPIRED" for scope in task_rows):
                expired = next(scope for scope in task_rows if scope.get("status") == "EXPIRED")
                return _audited(
                    "EXPIRED", False,
                    f"Automation scope {expired.get('scope_id')} has expired and cannot authorize {canon_area}.",
                    {**base, "scope_id": str(expired.get("scope_id") or "")},
                    audit_db_path=audit_db_path,
                )
            return _audited(
                "DENIED", False,
                f"No automation scope grants area {canon_area}; denied by default.",
                base,
                audit_db_path=audit_db_path,
            )

        matching = [
            scope for scope in active_rows
            if _matches_pattern(target_text, str(scope.get("target_pattern") or ""))
        ]
        for scope in matching:
            if str(scope.get("decision") or "") == "DENY":
                return _audited(
                    "DENIED", False,
                    f"Automation scope {scope.get('scope_id')} explicitly denies area {canon_area}.",
                    {**base, "scope_id": str(scope.get("scope_id") or "")},
                    audit_db_path=audit_db_path,
                )
        for scope in matching:
            if str(scope.get("decision") or "") == "ALLOW":
                return {
                    "outcome": "ALLOWED",
                    "allowed": True,
                    "reason": f"Automation scope {scope.get('scope_id')} allows area {canon_area}.",
                    "scope_id": str(scope.get("scope_id") or ""),
                    "metadata": redact_sensitive_data({**base, "scope_id": str(scope.get("scope_id") or "")}),
                }

        return _audited(
            "DENIED", False,
            f"No automation scope boundary matches target for area {canon_area}.",
            base,
            audit_db_path=audit_db_path,
        )
    finally:
        connection.close()


def _audited(
    outcome: str,
    allowed: bool,
    reason: str,
    metadata: dict[str, Any],
    *,
    audit_db_path: str | Path | None = None,
) -> dict[str, Any]:
    _audit(
        "scope_denied",
        audit_db_path=audit_db_path,
        actor="automation_scope",
        tool="automation_scope",
        target=str(metadata.get("target") or metadata.get("area") or ""),
        result=outcome,
        reason=reason,
        metadata=metadata,
    )
    return {
        "outcome": outcome,
        "allowed": allowed,
        "reason": reason,
        "scope_id": str(metadata.get("scope_id") or ""),
        "metadata": redact_sensitive_data(metadata),
    }


__all__ = [
    "DEFAULT_DB_PATH",
    "SCOPE_AREAS",
    "SCOPE_DECISIONS",
    "SCOPE_OUTCOMES",
    "SCOPE_STATUSES",
    "check_scope",
    "grant_scope",
    "get_scope",
    "initialize_scope_store",
    "list_scopes",
    "revoke_scope",
    "scope_area_for_tool",
]
