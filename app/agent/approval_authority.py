from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.security.audit_logger import record_audit_event
from app.security.sensitive_data import redact_sensitive_data, redact_text
from app.agent.capability_context import validate_capability_context, evidence_hash

DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "nexus_approvals.db"
APPROVAL_TTL_SECONDS = 300
VALID_STATUSES = {"PENDING", "APPROVED", "EXECUTING", "REJECTED", "EXPIRED", "INVALIDATED", "CONSUMED"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return (value or _now()).isoformat(timespec="seconds")


def _safe(value: Any, limit: int = 2000) -> str:
    return redact_text(value)[:limit]


def _db_path(db_path: str | Path | None = None) -> Path:
    path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    connection = sqlite3.connect(str(_db_path(db_path)))
    connection.row_factory = sqlite3.Row
    return connection


def initialize_approval_store(db_path: str | Path | None = None) -> Path:
    path = _db_path(db_path)
    connection = _connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS approvals (
                approval_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                checkpoint_id TEXT NOT NULL,
                proposal_hash TEXT NOT NULL,
                action_type TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                target TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                status TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                decided_at TEXT NOT NULL DEFAULT '',
                decision_actor TEXT NOT NULL DEFAULT '',
                decision_reason TEXT NOT NULL DEFAULT '',
                consumed_at TEXT NOT NULL DEFAULT '',
                target_hash TEXT NOT NULL DEFAULT '',
                evidence_hash TEXT NOT NULL DEFAULT ''
                ,capability_context TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_approvals_task ON approvals(task_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status)")
        columns = [row[1] for row in connection.execute("PRAGMA table_info(approvals)").fetchall()]
        if "capability_context" not in columns:
            connection.execute("ALTER TABLE approvals ADD COLUMN capability_context TEXT NOT NULL DEFAULT '{}'")
        if "target_hash" not in columns:
            connection.execute("ALTER TABLE approvals ADD COLUMN target_hash TEXT NOT NULL DEFAULT ''")
        if "evidence_hash" not in columns:
            connection.execute("ALTER TABLE approvals ADD COLUMN evidence_hash TEXT NOT NULL DEFAULT ''")
        connection.commit()
    finally:
        connection.close()
    return path


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    result = dict(row)
    return redact_sensitive_data(result)


def _expire_locked(connection: sqlite3.Connection) -> None:
    connection.execute(
        "UPDATE approvals SET status = 'EXPIRED', decided_at = ?, decision_actor = 'approval_authority', decision_reason = 'Approval expired.' WHERE status = 'PENDING' AND expires_at <= ?",
        (_iso(), _iso()),
    )


def create_approval(
    *,
    task_id: str,
    checkpoint_id: str,
    proposal_hash: str,
    action_type: str,
    tool_name: str,
    target: str,
    risk_level: str,
    reason: str = "",
    capability_context: dict[str, Any] | None = None,
    target_hash: str = "",
    evidence_hash_value: str = "",
    expires_at: str | None = None,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    if not task_id or not checkpoint_id or not proposal_hash or not action_type or not tool_name or not target:
        raise ValueError("Approval requires task, checkpoint, proposal, action, tool, and target bindings.")
    expiry = expires_at or _iso(_now() + timedelta(seconds=APPROVAL_TTL_SECONDS))
    approval_id = f"approval-{uuid.uuid4().hex[:16]}"
    initialize_approval_store(db_path)
    connection = _connect(db_path)
    try:
        _expire_locked(connection)
        connection.execute(
            "INSERT INTO approvals (approval_id, task_id, checkpoint_id, proposal_hash, action_type, tool_name, target, risk_level, status, reason, created_at, expires_at, capability_context, target_hash, evidence_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?, ?, ?, ?)",
            (approval_id, _safe(task_id, 200), _safe(checkpoint_id, 200), _safe(proposal_hash, 200), _safe(action_type, 200), _safe(tool_name, 200), _safe(target, 1000), _safe(risk_level, 50), _safe(reason), _iso(), _safe(expiry, 80), json.dumps(redact_sensitive_data(capability_context or {}), sort_keys=True, ensure_ascii=True), _safe(target_hash, 200), _safe(evidence_hash_value, 200)),
        )
        connection.commit()
        record = _row(connection.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone())
    finally:
        connection.close()
    record_audit_event("approval_created", actor="approval_authority", tool=tool_name, risk_level=risk_level, approval_required=True, approved=False, target=target, result="PENDING", reason=reason, metadata={"approval_id": approval_id, "task_id": task_id, "checkpoint_id": checkpoint_id, "proposal_hash": proposal_hash}, db_path=db_path, mirror_central=True)
    return record or {}


def get_approval(approval_id: str, *, db_path: str | Path | None = None) -> dict[str, Any] | None:
    if not approval_id:
        return None
    initialize_approval_store(db_path)
    connection = _connect(db_path)
    try:
        _expire_locked(connection)
        connection.commit()
        return _row(connection.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone())
    finally:
        connection.close()


def list_pending_approvals(*, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    initialize_approval_store(db_path)
    connection = _connect(db_path)
    try:
        _expire_locked(connection)
        connection.commit()
        return [_row(row) for row in connection.execute("SELECT * FROM approvals WHERE status = 'PENDING' ORDER BY created_at ASC").fetchall()]
    finally:
        connection.close()


def decide_approval(approval_id: str, decision: str, *, actor: str = "human", reason: str = "", db_path: str | Path | None = None) -> dict[str, Any]:
    normalized = str(decision or "").upper()
    if normalized not in {"APPROVED", "REJECTED"}:
        raise ValueError("Approval decision must be APPROVED or REJECTED.")
    initialize_approval_store(db_path)
    connection = _connect(db_path)
    try:
        _expire_locked(connection)
        row = connection.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone()
        if row is None:
            raise ValueError("Approval does not exist.")
        current = dict(row)
        if current["status"] != "PENDING":
            raise ValueError("Approval is no longer pending.")
        connection.execute("UPDATE approvals SET status = ?, decided_at = ?, decision_actor = ?, decision_reason = ? WHERE approval_id = ? AND status = 'PENDING'", (normalized, _iso(), _safe(actor, 120), _safe(reason), approval_id))
        connection.commit()
        result = _row(connection.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone())
    finally:
        connection.close()
    record_audit_event("approval_granted" if normalized == "APPROVED" else "approval_denied", actor=actor, tool=result.get("tool_name", "") if result else "", risk_level=result.get("risk_level", "") if result else "", approval_required=True, approved=normalized == "APPROVED", target=result.get("target", "") if result else "", result=normalized, reason=reason, metadata={"approval_id": approval_id, "task_id": result.get("task_id", "") if result else ""}, db_path=db_path, mirror_central=True)
    return result or {}


def invalidate_approval(approval_id: str, reason: str, *, db_path: str | Path | None = None) -> dict[str, Any] | None:
    """Terminally invalidate an approval that must never execute.

    Also covers EXECUTING records stranded by a failed dispatch so a failed
    execution can neither be replayed nor silently reused; retry requires a
    fresh approval. INVALIDATED is terminal everywhere it is read.
    """
    initialize_approval_store(db_path)
    connection = _connect(db_path)
    try:
        connection.execute("UPDATE approvals SET status = 'INVALIDATED', decided_at = ?, decision_actor = 'approval_authority', decision_reason = ? WHERE approval_id = ? AND status IN ('PENDING', 'APPROVED', 'EXECUTING')", (_iso(), _safe(reason), approval_id))
        connection.commit()
        return _row(connection.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone())
    finally:
        connection.close()


def consume_approval(approval_id: str, *, db_path: str | Path | None = None) -> dict[str, Any] | None:
    initialize_approval_store(db_path)
    connection = _connect(db_path)
    try:
        connection.execute("UPDATE approvals SET status = 'CONSUMED', consumed_at = ? WHERE approval_id = ? AND status = 'EXECUTING'", (_iso(), approval_id))
        connection.commit()
        return _row(connection.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone())
    finally:
        connection.close()


def _invalidate_locked(connection: sqlite3.Connection, approval_id: str, reason: str) -> None:
    """Mark an approval INVALIDATED inside the caller's transaction.

    Used where opening a second connection would contend with a held write
    lock (e.g. inside the atomic claim transaction below).
    """
    connection.execute(
        "UPDATE approvals SET status = 'INVALIDATED', decided_at = ?, decision_actor = 'approval_authority', decision_reason = ? WHERE approval_id = ? AND status IN ('PENDING', 'APPROVED', 'EXECUTING')",
        (_iso(), _safe(reason), approval_id),
    )


def _claim_bindings_match(stored: dict[str, Any], expected: dict[str, Any]) -> str:
    """Return the first mismatched binding key, or an empty string."""
    for key, value in expected.items():
        if value is None:
            continue
        if str(stored.get(key, "")) != str(value):
            return key
    return ""


def claim_approval(
    approval_id: str,
    *,
    task_id: str | None = None,
    checkpoint_id: str | None = None,
    proposal_hash: str | None = None,
    action_type: str | None = None,
    tool_name: str | None = None,
    target: str | None = None,
    risk_level: str | None = None,
    capability_context: dict[str, Any] | None = None,
    target_hash: str | None = None,
    evidence_hash_value: str | None = None,
    db_path: str | Path | None = None,
) -> dict[str, Any] | None:
    """Atomically reserve an approved approval for exactly one executor.

    Status, expiry, and every supplied binding are re-verified inside a
    single IMMEDIATE transaction before the APPROVED → EXECUTING transition,
    so the claim never relies solely on an earlier ``validate_approval``
    call. Bindings left as None are not checked, preserving the legacy
    claim-by-id behavior. Any failure fails closed; tampered or expired
    records are invalidated. Never raises for expected database states.
    """
    if not approval_id:
        return None
    initialize_approval_store(db_path)
    connection = _connect(db_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _expire_locked(connection)
        row = connection.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone()
        if row is None:
            connection.execute("ROLLBACK")
            return None
        # Compare raw stored values: redaction here could otherwise turn a
        # legitimate binding into a false mismatch. Output stays redacted
        # via _row on the way out.
        current = dict(row)
        if current.get("status") != "APPROVED":
            connection.commit()
            return None
        try:
            expiry = datetime.fromisoformat(str(current.get("expires_at", "")).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            _invalidate_locked(connection, approval_id, "Approval expiry is malformed; claim rejected.")
            connection.commit()
            return None
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= _now():
            _invalidate_locked(connection, approval_id, "Approval expired before execution claim.")
            connection.commit()
            return None
        mismatch = _claim_bindings_match(current, {
            "task_id": task_id,
            "checkpoint_id": checkpoint_id,
            "proposal_hash": proposal_hash,
            "action_type": action_type,
            "tool_name": tool_name,
            "target": target,
            "risk_level": risk_level,
        })
        if mismatch:
            _invalidate_locked(connection, approval_id, f"Approval binding mismatch for {mismatch} at claim time.")
            connection.commit()
            return None
        for key, value in (("target_hash", target_hash), ("evidence_hash", evidence_hash_value)):
            if value is None:
                continue
            if str(current.get(key) or "") and str(current.get(key) or "") != str(value or ""):
                _invalidate_locked(connection, approval_id, f"Approval binding mismatch for {key} at claim time.")
                connection.commit()
                return None
        if capability_context is not None:
            expected_context = redact_sensitive_data(capability_context)
            stored_context = current.get("capability_context") or {}
            if isinstance(stored_context, str):
                try:
                    stored_context = json.loads(stored_context)
                except json.JSONDecodeError:
                    stored_context = {}
            if evidence_hash(stored_context) != evidence_hash(expected_context):
                _invalidate_locked(connection, approval_id, "Approval capability context mismatch at claim time.")
                connection.commit()
                return None
        cursor = connection.execute(
            "UPDATE approvals SET status = 'EXECUTING', decided_at = ?, decision_actor = 'action_executor', decision_reason = 'Approval claimed for one execution.' WHERE approval_id = ? AND status = 'APPROVED'",
            (_iso(), approval_id),
        )
        connection.commit()
        if cursor.rowcount != 1:
            return None
        return _row(connection.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone())
    except (OSError, sqlite3.Error, TypeError, ValueError):
        try:
            connection.execute("ROLLBACK")
        except Exception:
            pass
        return None
    finally:
        connection.close()


def validate_approval(approval_id: str, *, task_id: str, checkpoint_id: str, proposal_hash: str, action_type: str, tool_name: str, target: str, risk_level: str, capability_context: dict[str, Any] | None = None, target_hash: str = "", evidence_hash_value: str = "", db_path: str | Path | None = None) -> dict[str, Any]:
    approval = get_approval(approval_id, db_path=db_path)
    if not approval:
        raise ValueError("Approval does not exist.")
    if approval.get("status") != "APPROVED":
        raise ValueError(f"Approval status is {approval.get('status')}, not APPROVED.")
    expiry = datetime.fromisoformat(str(approval.get("expires_at", "")).replace("Z", "+00:00"))
    if expiry <= _now():
        invalidate_approval(approval_id, "Approval expired before execution.", db_path=db_path)
        raise ValueError("Approval expired.")
    expected = {"task_id": task_id, "checkpoint_id": checkpoint_id, "proposal_hash": proposal_hash, "action_type": action_type, "tool_name": tool_name, "target": target, "risk_level": risk_level}
    for key, value in expected.items():
        if str(approval.get(key, "")) != str(value):
            invalidate_approval(approval_id, f"Approval binding mismatch for {key}.", db_path=db_path)
            raise ValueError(f"Approval binding mismatch for {key}.")
    for key, value in (("target_hash", target_hash), ("evidence_hash", evidence_hash_value)):
        stored = str(approval.get(key) or "")
        if stored and stored != str(value or ""):
            invalidate_approval(approval_id, f"Approval binding mismatch for {key}.", db_path=db_path)
            raise ValueError(f"Approval binding mismatch for {key}.")
    if capability_context is not None:
        expected_context = redact_sensitive_data(capability_context)
        stored_context = approval.get("capability_context") or {}
        if isinstance(stored_context, str):
            try:
                stored_context = json.loads(stored_context)
            except json.JSONDecodeError:
                stored_context = {}
        if evidence_hash(stored_context) != evidence_hash(expected_context):
            invalidate_approval(approval_id, "Approval capability context mismatch.", db_path=db_path)
            raise ValueError("Approval capability context mismatch.")
    return approval


__all__ = ["APPROVAL_TTL_SECONDS", "DEFAULT_DB_PATH", "claim_approval", "create_approval", "decide_approval", "get_approval", "initialize_approval_store", "invalidate_approval", "list_pending_approvals", "consume_approval", "validate_approval"]
