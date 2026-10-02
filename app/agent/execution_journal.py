from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.security.audit_logger import record_audit_event
from app.security.sensitive_data import redact_sensitive_data, redact_text

DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "nexus_execution_journal.db"

# Exact action payloads (code patch, action specs) needed for faithful
# resume-after-approval. Stored WITHOUT redaction because the executor
# requires byte-exact content and the proposal hash binds it; the journal
# database is local-only. Bounded to keep checkpoints small; oversized
# payloads are dropped (resume then fails closed at the executor guard).
MAX_ACTION_PAYLOAD_CHARS = 8000


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ensure_db(db_path: str | Path | None = None) -> Path:
    resolved = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    resolved.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(resolved))
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS execution_checkpoints (
                checkpoint_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                current_stage TEXT NOT NULL DEFAULT '',
                current_sub_goal TEXT NOT NULL DEFAULT '',
                selected_tools TEXT NOT NULL DEFAULT '[]',
                action_type TEXT NOT NULL DEFAULT '',
                action_target TEXT NOT NULL DEFAULT '',
                target_hash TEXT NOT NULL DEFAULT '',
                pre_action_snapshot_ref TEXT NOT NULL DEFAULT '',
                proposal_hash TEXT NOT NULL DEFAULT '',
                redacted_action_metadata TEXT NOT NULL DEFAULT '{}',
                risk_level TEXT NOT NULL DEFAULT '',
                approval_binding TEXT NOT NULL DEFAULT '{}',
                approval_status TEXT NOT NULL DEFAULT 'UNKNOWN',
                approval_expiry TEXT NOT NULL DEFAULT '',
                evidence_refs TEXT NOT NULL DEFAULT '[]',
                verification_snapshot TEXT NOT NULL DEFAULT '',
                retry_count INTEGER NOT NULL DEFAULT 0,
                retry_reason TEXT NOT NULL DEFAULT '',
                resume_required INTEGER NOT NULL DEFAULT 0,
                resume_reason TEXT NOT NULL DEFAULT '',
                environment_fingerprint TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_validated_at TEXT NOT NULL DEFAULT '',
                is_valid INTEGER NOT NULL DEFAULT 1,
                invalid_reason TEXT NOT NULL DEFAULT '',
                checkpoint_type TEXT NOT NULL DEFAULT 'execution'
            )
            """
        )
        columns = [row[1] for row in connection.execute("PRAGMA table_info(execution_checkpoints)").fetchall()]
        if "action_payload" not in columns:
            connection.execute("ALTER TABLE execution_checkpoints ADD COLUMN action_payload TEXT NOT NULL DEFAULT '{}'")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS recovery_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                checkpoint_id TEXT NOT NULL DEFAULT '',
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL DEFAULT '{}',
                timestamp TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT ''
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_execution_checkpoints_task_id ON execution_checkpoints(task_id)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_execution_checkpoints_validity ON execution_checkpoints(task_id, is_valid)"
        )
        connection.commit()
    finally:
        connection.close()
    return resolved


def _deserialize_json(value: Any, default: Any = None) -> Any:
    if value in (None, "", "null"):
        return default if default is not None else []
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default if default is not None else []


def _normalize_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    return [str(value)]


def _normalize_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return {str(key): val for key, val in value.items()}
    return {"value": str(value)}


def _serialize_json(value: Any) -> str:
    safe = redact_sensitive_data(value)
    return json.dumps(safe, ensure_ascii=True, default=str, separators=(",", ":"))


def _serialize_action_payload(value: Any) -> str:
    """Serialize exact resume payload without redaction (see module note)."""
    try:
        packed = json.dumps(value if isinstance(value, dict) else {}, ensure_ascii=True, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        return "{}"
    if len(packed) > MAX_ACTION_PAYLOAD_CHARS:
        return "{}"
    return packed


def _checkpoint_row_to_dict(row: sqlite3.Row | tuple[Any, ...] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    if isinstance(row, sqlite3.Row):
        values = dict(row)
    else:
        values = {"checkpoint_id": row[0]}
    checkpoint = {
        "checkpoint_id": values.get("checkpoint_id", ""),
        "task_id": values.get("task_id", ""),
        "current_stage": values.get("current_stage", ""),
        "current_sub_goal": values.get("current_sub_goal", ""),
        "selected_tools": _deserialize_json(values.get("selected_tools", "[]"), default=[]),
        "action_type": values.get("action_type", ""),
        "action_target": values.get("action_target", ""),
        "target_hash": values.get("target_hash", ""),
        "pre_action_snapshot_ref": values.get("pre_action_snapshot_ref", ""),
        "proposal_hash": values.get("proposal_hash", ""),
        "redacted_action_metadata": _deserialize_json(values.get("redacted_action_metadata", "{}"), default={}),
        "action_payload": _deserialize_json(values.get("action_payload", "{}"), default={}),
        "risk_level": values.get("risk_level", ""),
        "approval_binding": _deserialize_json(values.get("approval_binding", "{}"), default={}),
        "approval_status": values.get("approval_status", "UNKNOWN"),
        "approval_expiry": values.get("approval_expiry", ""),
        "evidence_refs": _deserialize_json(values.get("evidence_refs", "[]"), default=[]),
        "verification_snapshot": values.get("verification_snapshot", ""),
        "retry_count": int(values.get("retry_count", 0) or 0),
        "retry_reason": values.get("retry_reason", ""),
        "resume_required": bool(values.get("resume_required", 0)),
        "resume_reason": values.get("resume_reason", ""),
        "environment_fingerprint": values.get("environment_fingerprint", ""),
        "created_at": values.get("created_at", _now_iso()),
        "updated_at": values.get("updated_at", _now_iso()),
        "last_validated_at": values.get("last_validated_at", ""),
        "is_valid": int(values.get("is_valid", 1)),
        "invalid_reason": values.get("invalid_reason", ""),
        "checkpoint_type": values.get("checkpoint_type", "execution"),
    }
    checkpoint["selected_tools"] = [redact_text(item) for item in checkpoint["selected_tools"]]
    checkpoint["evidence_refs"] = [redact_text(item) for item in checkpoint["evidence_refs"]]
    checkpoint["redacted_action_metadata"] = redact_sensitive_data(checkpoint["redacted_action_metadata"])
    checkpoint["approval_binding"] = redact_sensitive_data(checkpoint["approval_binding"])
    checkpoint["action_target"] = redact_text(checkpoint["action_target"])
    checkpoint["current_stage"] = redact_text(checkpoint["current_stage"])
    checkpoint["current_sub_goal"] = redact_text(checkpoint["current_sub_goal"])
    checkpoint["action_type"] = redact_text(checkpoint["action_type"])
    checkpoint["proposal_hash"] = redact_text(checkpoint["proposal_hash"])
    checkpoint["target_hash"] = redact_text(checkpoint["target_hash"])
    checkpoint["risk_level"] = redact_text(checkpoint["risk_level"])
    checkpoint["approval_status"] = redact_text(checkpoint["approval_status"])
    checkpoint["approval_expiry"] = redact_text(checkpoint["approval_expiry"])
    checkpoint["invalid_reason"] = redact_text(checkpoint["invalid_reason"])
    return checkpoint


def create_checkpoint(
    task_id: str,
    *,
    current_stage: str = "",
    current_sub_goal: str = "",
    selected_tools: list[str] | tuple[str, ...] | None = None,
    action_type: str = "",
    action_target: str = "",
    target_hash: str = "",
    pre_action_snapshot_ref: str = "",
    proposal_hash: str = "",
    redacted_action_metadata: dict[str, Any] | None = None,
    action_payload: dict[str, Any] | None = None,
    risk_level: str = "",
    approval_binding: dict[str, Any] | None = None,
    approval_status: str = "UNKNOWN",
    approval_expiry: str = "",
    evidence_refs: list[str] | tuple[str, ...] | None = None,
    verification_snapshot: str = "",
    retry_count: int = 0,
    retry_reason: str = "",
    resume_required: bool = False,
    resume_reason: str = "",
    environment_fingerprint: str = "",
    checkpoint_type: str = "execution",
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    if not task_id:
        raise ValueError("task_id is required to create a checkpoint.")

    checkpoint_id = f"cp-{uuid.uuid4().hex[:12]}"
    now = _now_iso()
    safe_metadata = redact_sensitive_data(redacted_action_metadata or {})
    safe_binding = redact_sensitive_data(approval_binding or {})
    accepted_tools = [redact_text(item) for item in _normalize_list(selected_tools)]
    refs = [redact_text(item) for item in _normalize_list(evidence_refs)]

    row = {
        "checkpoint_id": checkpoint_id,
        "task_id": task_id,
        "current_stage": redact_text(current_stage),
        "current_sub_goal": redact_text(current_sub_goal),
        "selected_tools": accepted_tools,
        "action_type": redact_text(action_type),
        "action_target": redact_text(action_target),
        "target_hash": redact_text(target_hash),
        "pre_action_snapshot_ref": redact_text(pre_action_snapshot_ref),
        "proposal_hash": redact_text(proposal_hash),
        "redacted_action_metadata": safe_metadata,
        "action_payload": _serialize_action_payload(action_payload),
        "risk_level": redact_text(risk_level),
        "approval_binding": safe_binding,
        "approval_status": redact_text(approval_status),
        "approval_expiry": redact_text(approval_expiry),
        "evidence_refs": refs,
        "verification_snapshot": redact_text(verification_snapshot),
        "retry_count": int(retry_count or 0),
        "retry_reason": redact_text(retry_reason),
        "resume_required": 1 if resume_required else 0,
        "resume_reason": redact_text(resume_reason),
        "environment_fingerprint": redact_text(environment_fingerprint),
        "created_at": now,
        "updated_at": now,
        "last_validated_at": "",
        "is_valid": 1,
        "invalid_reason": "",
        "checkpoint_type": checkpoint_type,
    }

    resolved = _ensure_db(db_path)
    connection = sqlite3.connect(str(resolved))
    try:
        connection.execute(
            """
            INSERT INTO execution_checkpoints (
                checkpoint_id, task_id, current_stage, current_sub_goal, selected_tools,
                action_type, action_target, target_hash, pre_action_snapshot_ref, proposal_hash,
                redacted_action_metadata, action_payload, risk_level, approval_binding, approval_status,
                approval_expiry, evidence_refs, verification_snapshot, retry_count,
                retry_reason, resume_required, resume_reason, environment_fingerprint,
                created_at, updated_at, last_validated_at, is_valid, invalid_reason, checkpoint_type
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["checkpoint_id"],
                row["task_id"],
                row["current_stage"],
                row["current_sub_goal"],
                _serialize_json(row["selected_tools"]),
                row["action_type"],
                row["action_target"],
                row["target_hash"],
                row["pre_action_snapshot_ref"],
                row["proposal_hash"],
                _serialize_json(row["redacted_action_metadata"]),
                row["action_payload"],
                row["risk_level"],
                _serialize_json(row["approval_binding"]),
                row["approval_status"],
                row["approval_expiry"],
                _serialize_json(row["evidence_refs"]),
                row["verification_snapshot"],
                row["retry_count"],
                row["retry_reason"],
                row["resume_required"],
                row["resume_reason"],
                row["environment_fingerprint"],
                row["created_at"],
                row["updated_at"],
                row["last_validated_at"],
                row["is_valid"],
                row["invalid_reason"],
                row["checkpoint_type"],
            ),
        )
        connection.commit()
    finally:
        connection.close()

    event = record_recovery_event(
        task_id,
        "checkpoint_created",
        {
            "checkpoint_id": checkpoint_id,
            "current_stage": row["current_stage"],
            "action_type": row["action_type"],
            "risk_level": row["risk_level"],
        },
        checkpoint_id=checkpoint_id,
        db_path=db_path,
    )
    event["task_id"] = task_id
    return load_checkpoint(task_id, checkpoint_id=checkpoint_id, db_path=db_path)


def load_checkpoint(
    task_id: str,
    *,
    checkpoint_id: str | None = None,
    db_path: str | Path | None = None,
) -> dict[str, Any] | None:
    if not task_id and not checkpoint_id:
        return None

    resolved = _ensure_db(db_path)
    connection = sqlite3.connect(str(resolved))
    connection.row_factory = sqlite3.Row
    try:
        if checkpoint_id:
            row = connection.execute(
                "SELECT * FROM execution_checkpoints WHERE checkpoint_id = ?",
                (checkpoint_id,),
            ).fetchone()
        else:
            row = connection.execute(
                "SELECT * FROM execution_checkpoints WHERE task_id = ? ORDER BY created_at DESC, updated_at DESC LIMIT 1",
                (task_id,),
            ).fetchone()
    finally:
        connection.close()
    return _checkpoint_row_to_dict(row)


def update_checkpoint(
    checkpoint_id: str,
    **updates: Any,
) -> dict[str, Any]:
    db_path = updates.pop("db_path", None)
    if not checkpoint_id:
        raise ValueError("checkpoint_id is required.")

    existing = load_checkpoint("", checkpoint_id=checkpoint_id, db_path=db_path)
    if existing is None:
        raise ValueError(f"Checkpoint {checkpoint_id} was not found.")

    retry_count = existing["retry_count"]
    if "retry_count" in updates:
        retry_count = int(updates["retry_count"] or 0)

    resume_required = existing["resume_required"]
    if "resume_required" in updates:
        resume_required = bool(updates["resume_required"])

    is_valid = existing["is_valid"]
    if "is_valid" in updates:
        is_valid = int(updates["is_valid"])

    merged = {
        "current_stage": updates.get("current_stage", existing["current_stage"]),
        "current_sub_goal": updates.get("current_sub_goal", existing["current_sub_goal"]),
        "selected_tools": updates.get("selected_tools", existing["selected_tools"]),
        "action_type": updates.get("action_type", existing["action_type"]),
        "action_target": updates.get("action_target", existing["action_target"]),
        "target_hash": updates.get("target_hash", existing["target_hash"]),
        "pre_action_snapshot_ref": updates.get("pre_action_snapshot_ref", existing["pre_action_snapshot_ref"]),
        "proposal_hash": updates.get("proposal_hash", existing["proposal_hash"]),
        "redacted_action_metadata": updates.get("redacted_action_metadata", existing["redacted_action_metadata"]),
        "action_payload": updates.get("action_payload", existing.get("action_payload", {})),
        "risk_level": updates.get("risk_level", existing["risk_level"]),
        "approval_binding": updates.get("approval_binding", existing["approval_binding"]),
        "approval_status": updates.get("approval_status", existing["approval_status"]),
        "approval_expiry": updates.get("approval_expiry", existing["approval_expiry"]),
        "evidence_refs": updates.get("evidence_refs", existing["evidence_refs"]),
        "verification_snapshot": updates.get("verification_snapshot", existing["verification_snapshot"]),
        "retry_count": retry_count,
        "retry_reason": updates.get("retry_reason", existing["retry_reason"]),
        "resume_required": resume_required,
        "resume_reason": updates.get("resume_reason", existing["resume_reason"]),
        "environment_fingerprint": updates.get("environment_fingerprint", existing["environment_fingerprint"]),
        "checkpoint_type": updates.get("checkpoint_type", existing["checkpoint_type"]),
        "last_validated_at": updates.get("last_validated_at", existing["last_validated_at"]),
        "is_valid": is_valid,
        "invalid_reason": updates.get("invalid_reason", existing["invalid_reason"]),
    }
    merged["updated_at"] = _now_iso()
    if isinstance(merged.get("action_payload"), dict):
        merged["action_payload"] = _serialize_action_payload(merged["action_payload"])
    elif not isinstance(merged.get("action_payload"), str):
        merged["action_payload"] = "{}"
    merged["selected_tools"] = [redact_text(item) for item in _normalize_list(merged["selected_tools"])]
    merged["evidence_refs"] = [redact_text(item) for item in _normalize_list(merged["evidence_refs"])]
    merged["redacted_action_metadata"] = redact_sensitive_data(merged["redacted_action_metadata"])
    merged["approval_binding"] = redact_sensitive_data(merged["approval_binding"])
    if "is_valid" in updates:
        merged["is_valid"] = int(updates["is_valid"]) if updates["is_valid"] is not None else 1
    if "invalid_reason" in updates:
        merged["invalid_reason"] = str(updates["invalid_reason"] or "")

    resolved = _ensure_db(db_path)
    connection = sqlite3.connect(str(resolved))
    try:
        connection.execute(
            """
            UPDATE execution_checkpoints SET
                current_stage = ?, current_sub_goal = ?, selected_tools = ?, action_type = ?, action_target = ?,
                target_hash = ?, pre_action_snapshot_ref = ?, proposal_hash = ?, redacted_action_metadata = ?,
                action_payload = ?,
                risk_level = ?, approval_binding = ?, approval_status = ?, approval_expiry = ?, evidence_refs = ?,
                verification_snapshot = ?, retry_count = ?, retry_reason = ?, resume_required = ?, resume_reason = ?,
                environment_fingerprint = ?, updated_at = ?, last_validated_at = ?, is_valid = ?, invalid_reason = ?, checkpoint_type = ?
            WHERE checkpoint_id = ?
            """,
            (
                redact_text(merged["current_stage"]),
                redact_text(merged["current_sub_goal"]),
                _serialize_json(merged["selected_tools"]),
                redact_text(merged["action_type"]),
                redact_text(merged["action_target"]),
                redact_text(merged["target_hash"]),
                redact_text(merged["pre_action_snapshot_ref"]),
                redact_text(merged["proposal_hash"]),
                _serialize_json(merged["redacted_action_metadata"]),
                merged["action_payload"] if isinstance(merged.get("action_payload"), str) else _serialize_action_payload(merged.get("action_payload")),
                redact_text(merged["risk_level"]),
                _serialize_json(merged["approval_binding"]),
                redact_text(merged["approval_status"]),
                redact_text(merged["approval_expiry"]),
                _serialize_json(merged["evidence_refs"]),
                redact_text(merged["verification_snapshot"]),
                merged["retry_count"],
                redact_text(merged["retry_reason"]),
                1 if merged["resume_required"] else 0,
                redact_text(merged["resume_reason"]),
                redact_text(merged["environment_fingerprint"]),
                merged["updated_at"],
                redact_text(merged["last_validated_at"]),
                merged["is_valid"],
                redact_text(merged["invalid_reason"]),
                redact_text(merged["checkpoint_type"]),
                checkpoint_id,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    record_recovery_event(
        existing["task_id"],
        "checkpoint_updated",
        {"checkpoint_id": checkpoint_id, "current_stage": merged["current_stage"], "updated_at": merged["updated_at"]},
        checkpoint_id=checkpoint_id,
        db_path=db_path,
    )
    return load_checkpoint(existing["task_id"], checkpoint_id=checkpoint_id, db_path=db_path)


def list_checkpoints_for_task(task_id: str, *, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    if not task_id:
        return []

    resolved = _ensure_db(db_path)
    connection = sqlite3.connect(str(resolved))
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            "SELECT * FROM execution_checkpoints WHERE task_id = ? ORDER BY created_at DESC, updated_at DESC",
            (task_id,),
        ).fetchall()
    finally:
        connection.close()
    return [item for item in (_checkpoint_row_to_dict(row) for row in rows) if item is not None]


def mark_checkpoint_validated(checkpoint_id: str, *, db_path: str | Path | None = None) -> dict[str, Any]:
    existing = load_checkpoint("", checkpoint_id=checkpoint_id, db_path=db_path)
    if existing is None:
        raise ValueError(f"Checkpoint {checkpoint_id} was not found.")
    updated = update_checkpoint(
        checkpoint_id,
        is_valid=1,
        invalid_reason="",
        last_validated_at=_now_iso(),
        db_path=db_path,
    )
    record_recovery_event(
        existing["task_id"],
        "checkpoint_validated",
        {"checkpoint_id": checkpoint_id, "last_validated_at": updated["last_validated_at"]},
        checkpoint_id=checkpoint_id,
        db_path=db_path,
    )
    return updated


def invalidate_checkpoint(checkpoint_id: str, reason: str, *, db_path: str | Path | None = None) -> dict[str, Any]:
    existing = load_checkpoint("", checkpoint_id=checkpoint_id, db_path=db_path)
    if existing is None:
        raise ValueError(f"Checkpoint {checkpoint_id} was not found.")
    updated = update_checkpoint(
        checkpoint_id,
        is_valid=0,
        invalid_reason=reason,
        db_path=db_path,
    )
    record_recovery_event(
        existing["task_id"],
        "checkpoint_invalidated",
        {"checkpoint_id": checkpoint_id, "reason": reason},
        checkpoint_id=checkpoint_id,
        db_path=db_path,
    )
    return updated


def record_recovery_event(
    task_id: str,
    event_type: str,
    payload: dict[str, Any] | None = None,
    *,
    checkpoint_id: str = "",
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    if not task_id:
        raise ValueError("task_id is required for recovery events.")

    safe_payload = redact_sensitive_data(payload or {})
    event_id = None
    resolved = _ensure_db(db_path)
    connection = sqlite3.connect(str(resolved))
    try:
        cursor = connection.execute(
            """
            INSERT INTO recovery_events (task_id, checkpoint_id, event_type, payload, timestamp, status)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                task_id,
                checkpoint_id,
                redact_text(event_type),
                _serialize_json(safe_payload),
                _now_iso(),
                "recorded",
            ),
        )
        event_id = cursor.lastrowid
        connection.commit()
    finally:
        connection.close()

    record_audit_event(
        event_type,
        actor="execution_journal",
        tool="execution_checkpoint",
        target=str(task_id),
        result="recorded",
        reason="Recovery event persisted.",
        metadata={"checkpoint_id": checkpoint_id, "payload": safe_payload},
        db_path=db_path,
    )
    return {
        "id": event_id,
        "task_id": task_id,
        "checkpoint_id": checkpoint_id,
        "event_type": redact_text(event_type),
        "payload": safe_payload,
        "timestamp": _now_iso(),
        "status": "recorded",
    }
