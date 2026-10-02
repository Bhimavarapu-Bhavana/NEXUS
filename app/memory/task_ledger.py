from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.security.audit_logger import record_audit_event
from app.security.sensitive_data import redact_sensitive_data, redact_text

DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "nexus_task_ledger.db"

VALID_STATUS_TRANSITIONS: dict[str, set[str]] = {
    "CREATED": {"RUNNING", "WAITING_APPROVAL", "PAUSED", "BLOCKED", "FAILED"},
    "RUNNING": {"WAITING_APPROVAL", "VERIFYING", "PAUSED", "BLOCKED", "FAILED", "COMPLETED"},
    "WAITING_APPROVAL": {"RUNNING", "BLOCKED", "CANCELLED", "VERIFYING"},
    "VERIFYING": {"COMPLETED", "FAILED", "RUNNING", "PAUSED"},
    "PAUSED": {"RUNNING", "WAITING_APPROVAL", "VERIFYING"},
    "COMPLETED": set(),
    "FAILED": {"RUNNING"},
    "BLOCKED": {"RUNNING"},
    "CANCELLED": set(),
}
TERMINAL_STATES = {"COMPLETED", "FAILED", "BLOCKED", "CANCELLED"}
MAX_TASK_ANSWER_CHARS = 4000
TASK_EVENT_TYPES = {
    "TASK_CREATED",
    "STAGE_CHANGED",
    "TOOL_SELECTED",
    "EVIDENCE_RECORDED",
    "ACTION_PROPOSED",
    "APPROVAL_REQUESTED",
    "APPROVAL_GRANTED",
    "APPROVAL_REJECTED",
    "ACTION_EXECUTED",
    "VERIFICATION_COMPLETED",
    "RETRY_REQUESTED",
    "TASK_PAUSED",
    "TASK_RESUMED",
    "TASK_COMPLETED",
    "TASK_FAILED",
    "TASK_BLOCKED",
    "TASK_CANCELLED",
    "STATUS_CHANGED",
    "AUTONOMOUS_EVENT_RECEIVED",
    "AUTONOMOUS_TASK_CREATED",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _bound_answer(value: Any) -> str:
    """Redact and bound a user-facing task answer for durable storage."""
    if value is None:
        return ""
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=True, default=str, separators=(",", ":"))
    text = redact_text(value)
    if len(text) > MAX_TASK_ANSWER_CHARS:
        return text[:MAX_TASK_ANSWER_CHARS].rstrip() + "\n...[TRUNCATED]"
    return text


def _ensure_db(db_path: str | Path | None = None) -> Path:
    resolved = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    resolved.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(resolved))
    connection.row_factory = sqlite3.Row
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS task_ledger (
                task_id TEXT PRIMARY KEY,
                objective TEXT NOT NULL,
                current_stage TEXT NOT NULL DEFAULT 'REQUEST',
                current_sub_goal TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'CREATED',
                selected_tools TEXT NOT NULL DEFAULT '[]',
                evidence_refs TEXT NOT NULL DEFAULT '[]',
                action_lineage TEXT NOT NULL DEFAULT '{}',
                approval_lineage TEXT NOT NULL DEFAULT '{}',
                verification_history TEXT NOT NULL DEFAULT '[]',
                retry_history TEXT NOT NULL DEFAULT '[]',
                final_outcome TEXT NOT NULL DEFAULT '',
                goal_plan TEXT NOT NULL DEFAULT '[]',
                subgoal_statuses TEXT NOT NULL DEFAULT '{}',
                current_subgoal_id TEXT NOT NULL DEFAULT '',
                plan_version TEXT NOT NULL DEFAULT 'v1',
                plan_hash TEXT NOT NULL DEFAULT '',
                plan_revisions INTEGER NOT NULL DEFAULT 0,
                task_retry_count INTEGER NOT NULL DEFAULT 0,
                subgoal_retry_count TEXT NOT NULL DEFAULT '{}',
                failure_classifications TEXT NOT NULL DEFAULT '{}',
                adaptation_history TEXT NOT NULL DEFAULT '[]',
                completion_evidence TEXT NOT NULL DEFAULT '[]',
                subgoal_lineage TEXT NOT NULL DEFAULT '{}',
                execution_ids TEXT NOT NULL DEFAULT '{}',
                consumed_execution_ids TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                resumed_at TEXT NOT NULL DEFAULT '',
                resume_reason TEXT NOT NULL DEFAULT '',
                status_reason TEXT NOT NULL DEFAULT '',
                status_output TEXT NOT NULL DEFAULT '',
                task_answer TEXT NOT NULL DEFAULT '',
                parent_goal TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT '',
                source_reference TEXT NOT NULL DEFAULT '',
                priority TEXT NOT NULL DEFAULT 'NORMAL',
                deadline TEXT NOT NULL DEFAULT '',
                deadline_confidence TEXT NOT NULL DEFAULT '',
                deadline_evidence TEXT NOT NULL DEFAULT '[]',
                commitment TEXT NOT NULL DEFAULT '',
                dependencies TEXT NOT NULL DEFAULT '[]',
                blocked_by TEXT NOT NULL DEFAULT '[]',
                associated_files TEXT NOT NULL DEFAULT '[]',
                associated_conversations TEXT NOT NULL DEFAULT '[]',
                associated_applications TEXT NOT NULL DEFAULT '[]',
                associated_browser_context TEXT NOT NULL DEFAULT '{}',
                completion_criteria TEXT NOT NULL DEFAULT '[]',
                verification_status TEXT NOT NULL DEFAULT 'PENDING',
                status_history TEXT NOT NULL DEFAULT '[]'
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS task_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL DEFAULT '{}',
                timestamp TEXT NOT NULL,
                current_stage TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT ''
            )
            """
        )
        columns = [row[1] for row in connection.execute("PRAGMA table_info(task_ledger)").fetchall()]
        required_columns = {
            "goal_plan": "TEXT NOT NULL DEFAULT '[]'",
            "subgoal_statuses": "TEXT NOT NULL DEFAULT '{}'",
            "current_subgoal_id": "TEXT NOT NULL DEFAULT ''",
            "plan_version": "TEXT NOT NULL DEFAULT 'v1'",
            "plan_hash": "TEXT NOT NULL DEFAULT ''",
            "plan_revisions": "INTEGER NOT NULL DEFAULT 0",
            "task_retry_count": "INTEGER NOT NULL DEFAULT 0",
            "subgoal_retry_count": "TEXT NOT NULL DEFAULT '{}'",
            "failure_classifications": "TEXT NOT NULL DEFAULT '{}'",
            "adaptation_history": "TEXT NOT NULL DEFAULT '[]'",
            "completion_evidence": "TEXT NOT NULL DEFAULT '[]'",
            "subgoal_lineage": "TEXT NOT NULL DEFAULT '{}'",
            "execution_ids": "TEXT NOT NULL DEFAULT '{}'",
            "consumed_execution_ids": "TEXT NOT NULL DEFAULT '[]'",
            "plan_history": "TEXT NOT NULL DEFAULT '[]'",
            "recovery_history": "TEXT NOT NULL DEFAULT '[]'",
            "recovery_attempts": "INTEGER NOT NULL DEFAULT 0",
            "parent_goal": "TEXT NOT NULL DEFAULT ''",
            "source": "TEXT NOT NULL DEFAULT ''",
            "source_reference": "TEXT NOT NULL DEFAULT ''",
            "priority": "TEXT NOT NULL DEFAULT 'NORMAL'",
            "deadline": "TEXT NOT NULL DEFAULT ''",
            "deadline_confidence": "TEXT NOT NULL DEFAULT ''",
            "deadline_evidence": "TEXT NOT NULL DEFAULT '[]'",
            "commitment": "TEXT NOT NULL DEFAULT ''",
            "dependencies": "TEXT NOT NULL DEFAULT '[]'",
            "blocked_by": "TEXT NOT NULL DEFAULT '[]'",
            "associated_files": "TEXT NOT NULL DEFAULT '[]'",
            "associated_conversations": "TEXT NOT NULL DEFAULT '[]'",
            "associated_applications": "TEXT NOT NULL DEFAULT '[]'",
            "associated_browser_context": "TEXT NOT NULL DEFAULT '{}'",
            "completion_criteria": "TEXT NOT NULL DEFAULT '[]'",
            "verification_status": "TEXT NOT NULL DEFAULT 'PENDING'",
            "status_history": "TEXT NOT NULL DEFAULT '[]'",
            "task_answer": "TEXT NOT NULL DEFAULT ''",
        }
        for column_name, column_sql in required_columns.items():
            if column_name not in columns:
                connection.execute(f"ALTER TABLE task_ledger ADD COLUMN {column_name} {column_sql}")
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_task_ledger_status ON task_ledger(status)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_task_events_task_id ON task_events(task_id)"
        )
        connection.commit()
    finally:
        connection.close()
    return resolved


def _sanitize_json(value: Any) -> Any:
    safe = redact_sensitive_data(value)
    if isinstance(safe, (dict, list, tuple)):
        return safe
    return safe


def _serialize_json(value: Any) -> str:
    payload = _sanitize_json(value)
    return json.dumps(payload, ensure_ascii=True, default=str, separators=(",", ":"))


def _deserialize_json(value: Any, default: Any = None) -> Any:
    if value in (None, "", "null"):
        return default if default is not None else []
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default if default is not None else []
    return parsed


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
        return {str(key): value for key, value in value.items()}
    return {"value": str(value)}


def _safe_task_summary(task: dict[str, Any]) -> str:
    objective = str(task.get("objective") or "")
    status = str(task.get("status") or "UNKNOWN")
    stage = str(task.get("current_stage") or "UNKNOWN")
    reason = str(task.get("status_reason") or "")
    approval = task.get("approval_lineage") or {}
    approval_text = json.dumps(approval, ensure_ascii=True, default=str, separators=(",", ":"))
    return (
        f"TASK {task.get('task_id', 'unknown')} | "
        f"STATUS: {status} | STAGE: {stage} | "
        f"OBJECTIVE: {redact_text(objective)[:400]} | "
        f"REASON: {redact_text(reason)[:300]} | "
        f"APPROVAL: {redact_text(approval_text)[:400]}"
    )


def _status_is_terminal(status: str) -> bool:
    return str(status or "").upper() in TERMINAL_STATES


def _validate_transition(current_status: str, next_status: str) -> None:
    current = str(current_status or "").upper()
    next = str(next_status or "").upper()
    if current == next:
        return
    allowed = VALID_STATUS_TRANSITIONS.get(current, set())
    if next not in allowed:
        raise ValueError(
            f"Invalid status transition from {current_status} to {next_status}."
        )


def _coerce_task_row(row: sqlite3.Row | tuple[Any, ...] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    if isinstance(row, sqlite3.Row):
        values = dict(row)
    else:
        values = {"task_id": row[0]}
    task = {
        "task_id": values.get("task_id", ""),
        "objective": values.get("objective", ""),
        "current_stage": values.get("current_stage", "REQUEST"),
        "current_sub_goal": values.get("current_sub_goal", ""),
        "status": values.get("status", "CREATED"),
        "selected_tools": _deserialize_json(values.get("selected_tools", "[]"), default=[]),
        "evidence_refs": _deserialize_json(values.get("evidence_refs", "[]"), default=[]),
        "action_lineage": _deserialize_json(values.get("action_lineage", "{}"), default={}),
        "approval_lineage": _deserialize_json(values.get("approval_lineage", "{}"), default={}),
        "verification_history": _deserialize_json(values.get("verification_history", "[]"), default=[]),
        "retry_history": _deserialize_json(values.get("retry_history", "[]"), default=[]),
        "final_outcome": values.get("final_outcome", ""),
        "goal_plan": _deserialize_json(values.get("goal_plan", "[]"), default=[]),
        "subgoal_statuses": _deserialize_json(values.get("subgoal_statuses", "{}"), default={}),
        "current_subgoal_id": values.get("current_subgoal_id", ""),
        "plan_version": values.get("plan_version", "v1"),
        "plan_hash": values.get("plan_hash", ""),
        "plan_revisions": int(values.get("plan_revisions", 0) or 0),
        "task_retry_count": int(values.get("task_retry_count", 0) or 0),
        "subgoal_retry_count": _deserialize_json(values.get("subgoal_retry_count", "{}"), default={}),
        "failure_classifications": _deserialize_json(values.get("failure_classifications", "{}"), default={}),
        "adaptation_history": _deserialize_json(values.get("adaptation_history", "[]"), default=[]),
        "completion_evidence": _deserialize_json(values.get("completion_evidence", "[]"), default=[]),
        "subgoal_lineage": _deserialize_json(values.get("subgoal_lineage", "{}"), default={}),
        "execution_ids": _deserialize_json(values.get("execution_ids", "{}"), default={}),
        "consumed_execution_ids": _deserialize_json(values.get("consumed_execution_ids", "[]"), default=[]),
        "plan_history": _deserialize_json(values.get("plan_history", "[]"), default=[]),
        "recovery_history": _deserialize_json(values.get("recovery_history", "[]"), default=[]),
        "recovery_attempts": int(values.get("recovery_attempts", 0) or 0),
        "created_at": values.get("created_at", _now_iso()),
        "updated_at": values.get("updated_at", _now_iso()),
        "resumed_at": values.get("resumed_at", ""),
        "resume_reason": values.get("resume_reason", ""),
        "status_reason": values.get("status_reason", ""),
        "status_output": values.get("status_output", ""),
        "task_answer": _bound_answer(values.get("task_answer", "")),
        "parent_goal": values.get("parent_goal", ""),
        "source": values.get("source", ""),
        "source_reference": values.get("source_reference", ""),
        "priority": values.get("priority", "NORMAL"),
        "deadline": values.get("deadline", ""),
        "deadline_confidence": values.get("deadline_confidence", ""),
        "deadline_evidence": _deserialize_json(values.get("deadline_evidence", "[]"), default=[]),
        "commitment": values.get("commitment", ""),
        "dependencies": _deserialize_json(values.get("dependencies", "[]"), default=[]),
        "blocked_by": _deserialize_json(values.get("blocked_by", "[]"), default=[]),
        "associated_files": _deserialize_json(values.get("associated_files", "[]"), default=[]),
        "associated_conversations": _deserialize_json(values.get("associated_conversations", "[]"), default=[]),
        "associated_applications": _deserialize_json(values.get("associated_applications", "[]"), default=[]),
        "associated_browser_context": _deserialize_json(values.get("associated_browser_context", "{}"), default={}),
        "completion_criteria": _deserialize_json(values.get("completion_criteria", "[]"), default=[]),
        "verification_status": values.get("verification_status", "PENDING"),
        "status_history": _deserialize_json(values.get("status_history", "[]"), default=[]),
    }
    task["approval_lineage"] = redact_sensitive_data(task["approval_lineage"])
    task["selected_tools"] = [redact_text(item) for item in task["selected_tools"]]
    task["evidence_refs"] = [redact_text(item) for item in task["evidence_refs"]]
    task["verification_history"] = [redact_text(item) for item in task["verification_history"]]
    task["retry_history"] = [redact_text(item) for item in task["retry_history"]]
    task["goal_plan"] = [redact_sensitive_data(item) for item in task["goal_plan"]]
    task["subgoal_statuses"] = redact_sensitive_data(task["subgoal_statuses"])
    task["subgoal_retry_count"] = redact_sensitive_data(task["subgoal_retry_count"])
    task["failure_classifications"] = redact_sensitive_data(task["failure_classifications"])
    task["adaptation_history"] = [redact_sensitive_data(item) for item in task["adaptation_history"]]
    task["plan_history"] = [redact_sensitive_data(item) for item in task["plan_history"]]
    task["recovery_history"] = [redact_sensitive_data(item) for item in task["recovery_history"]]
    task["completion_evidence"] = [redact_text(item) for item in task["completion_evidence"]]
    for field in ("deadline_evidence", "dependencies", "blocked_by", "associated_files", "associated_conversations", "associated_applications", "completion_criteria", "status_history"):
        task[field] = redact_sensitive_data(task[field])
    task["associated_browser_context"] = redact_sensitive_data(task["associated_browser_context"])
    for field in ("parent_goal", "source", "source_reference", "priority", "deadline", "deadline_confidence", "commitment", "verification_status"):
        task[field] = redact_text(task[field])
    task["objective"] = redact_text(task["objective"])
    task["status_reason"] = redact_text(task["status_reason"])
    if not task["status_output"]:
        task["status_output"] = _safe_task_summary(task)
    return task


def _read_task_events(task_id: str, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    resolved = _ensure_db(db_path)
    connection = sqlite3.connect(str(resolved))
    try:
        rows = connection.execute(
            """
            SELECT id, task_id, event_type, payload, timestamp, current_stage, status
            FROM task_events
            WHERE task_id = ?
            ORDER BY id ASC
            """,
            (task_id,),
        ).fetchall()
    finally:
        connection.close()
    events: list[dict[str, Any]] = []
    for row in rows:
        payload = _deserialize_json(row[3], default={})
        if isinstance(payload, dict):
            payload = redact_sensitive_data(payload)
        elif isinstance(payload, list):
            payload = [redact_text(item) for item in payload]
        else:
            payload = redact_text(payload)
        events.append({
            "id": row[0],
            "task_id": row[1],
            "event_type": row[2],
            "payload": json.dumps(payload, ensure_ascii=True, default=str, separators=(",", ":")) if payload not in ({}, []) else "{}",
            "timestamp": row[4],
            "current_stage": row[5],
            "status": row[6],
        })
    return events


def _record_task_event_record(task_id: str, event_type: str, payload: Any, *, db_path: str | Path | None = None, current_stage: str = "", status: str = "") -> dict[str, Any]:
    if event_type not in TASK_EVENT_TYPES:
        raise ValueError(f"Unsupported task event type: {event_type}")
    safe_payload = _sanitize_json(payload)
    resolved = _ensure_db(db_path)
    connection = sqlite3.connect(str(resolved))
    connection.row_factory = sqlite3.Row
    try:
        connection.execute(
            """
            INSERT INTO task_events (task_id, event_type, payload, timestamp, current_stage, status)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                task_id,
                event_type,
                _serialize_json(safe_payload),
                _now_iso(),
                str(current_stage or ""),
                str(status or ""),
            ),
        )
        connection.commit()
    finally:
        connection.close()

    audit_metadata = {"task_id": task_id, "event_type": event_type, "payload": safe_payload}
    record_audit_event(
        "task_event",
        actor="task_ledger",
        tool="sqlite",
        target=task_id,
        result=event_type,
        reason="Task ledger event recorded.",
        metadata=audit_metadata,
        db_path=db_path,
    )
    return {"task_id": task_id, "event_type": event_type, "payload": safe_payload, "timestamp": _now_iso()}


def create_task(
    objective: str,
    *,
    task_id: str | None = None,
    current_stage: str = "REQUEST",
    current_sub_goal: str = "",
    status: str = "CREATED",
    selected_tools: list[str] | tuple[str, ...] | None = None,
    evidence_refs: list[str] | tuple[str, ...] | None = None,
    action_lineage: dict[str, Any] | None = None,
    approval_lineage: dict[str, Any] | None = None,
    verification_history: list[str] | tuple[str, ...] | None = None,
    retry_history: list[str] | tuple[str, ...] | None = None,
    final_outcome: str = "",
    status_reason: str = "Task created.",
    parent_goal: str = "",
    source: str = "",
    source_reference: str = "",
    priority: str = "NORMAL",
    deadline: str = "",
    deadline_confidence: str = "",
    deadline_evidence: list[dict[str, Any]] | None = None,
    commitment: str = "",
    dependencies: list[str] | None = None,
    blocked_by: list[str] | None = None,
    associated_files: list[str] | None = None,
    associated_conversations: list[str] | None = None,
    associated_applications: list[str] | None = None,
    associated_browser_context: dict[str, Any] | None = None,
    completion_criteria: list[str] | None = None,
    verification_status: str = "PENDING",
    task_answer: str = "",
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    task_id = task_id or f"task-{uuid.uuid4().hex[:12]}"
    safe_obj = redact_text(objective or "")
    payload = {
        "task_id": task_id,
        "objective": safe_obj,
        "current_stage": current_stage,
        "current_sub_goal": current_sub_goal,
        "status": status,
        "selected_tools": list(_normalize_list(selected_tools)),
        "evidence_refs": list(_normalize_list(evidence_refs)),
        "action_lineage": dict(_normalize_dict(action_lineage)),
        "approval_lineage": dict(_normalize_dict(approval_lineage)),
        "verification_history": list(_normalize_list(verification_history)),
        "retry_history": list(_normalize_list(retry_history)),
        "final_outcome": final_outcome,
        "goal_plan": [],
        "subgoal_statuses": {},
        "current_subgoal_id": "",
        "plan_version": "v1",
        "plan_hash": "",
        "plan_revisions": 0,
        "task_retry_count": 0,
        "subgoal_retry_count": {},
        "failure_classifications": {},
        "adaptation_history": [],
        "completion_evidence": [],
        "subgoal_lineage": {},
        "execution_ids": {},
        "consumed_execution_ids": [],
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
        "resumed_at": "",
"resume_reason": "",
        "status_reason": status_reason,
        "status_output": "",
        "task_answer": _bound_answer(task_answer),
        "parent_goal": parent_goal,
        "source": source,
        "source_reference": source_reference,
        "priority": priority,
        "deadline": deadline,
        "deadline_confidence": deadline_confidence,
        "deadline_evidence": list(deadline_evidence or []),
        "commitment": commitment,
        "dependencies": list(dependencies or []),
        "blocked_by": list(blocked_by or []),
        "associated_files": list(associated_files or []),
        "associated_conversations": list(associated_conversations or []),
        "associated_applications": list(associated_applications or []),
        "associated_browser_context": dict(associated_browser_context or {}),
        "completion_criteria": list(completion_criteria or []),
        "verification_status": verification_status,
        "status_history": [{"status": str(status).upper(), "timestamp": _now_iso(), "reason": status_reason}],
    }
    task = {
        **payload,
        "selected_tools": [redact_text(tool) for tool in payload["selected_tools"]],
        "evidence_refs": [redact_text(ref) for ref in payload["evidence_refs"]],
        "action_lineage": redact_sensitive_data(payload["action_lineage"]),
        "approval_lineage": redact_sensitive_data(payload["approval_lineage"]),
        "verification_history": [redact_text(item) for item in payload["verification_history"]],
        "retry_history": [redact_text(item) for item in payload["retry_history"]],
        "goal_plan": list(payload.get("goal_plan") or []),
        "subgoal_statuses": dict(payload.get("subgoal_statuses") or {}),
        "current_subgoal_id": str(payload.get("current_subgoal_id") or ""),
        "plan_version": str(payload.get("plan_version") or "v1"),
        "plan_hash": str(payload.get("plan_hash") or ""),
        "plan_revisions": int(payload.get("plan_revisions") or 0),
        "task_retry_count": int(payload.get("task_retry_count") or 0),
        "subgoal_retry_count": dict(payload.get("subgoal_retry_count") or {}),
        "failure_classifications": dict(payload.get("failure_classifications") or {}),
        "adaptation_history": list(payload.get("adaptation_history") or []),
        "completion_evidence": list(payload.get("completion_evidence") or []),
        "subgoal_lineage": dict(payload.get("subgoal_lineage") or {}),
        "execution_ids": dict(payload.get("execution_ids") or {}),
        "consumed_execution_ids": list(payload.get("consumed_execution_ids") or []),
        "status_output": "",
        "parent_goal": str(payload.get("parent_goal") or ""),
        "source": str(payload.get("source") or ""),
        "source_reference": str(payload.get("source_reference") or ""),
        "priority": str(payload.get("priority") or "NORMAL"),
        "deadline": str(payload.get("deadline") or ""),
        "deadline_confidence": str(payload.get("deadline_confidence") or ""),
        "deadline_evidence": list(payload.get("deadline_evidence") or []),
        "commitment": str(payload.get("commitment") or ""),
        "dependencies": list(payload.get("dependencies") or []),
        "blocked_by": list(payload.get("blocked_by") or []),
        "associated_files": list(payload.get("associated_files") or []),
        "associated_conversations": list(payload.get("associated_conversations") or []),
        "associated_applications": list(payload.get("associated_applications") or []),
        "associated_browser_context": dict(payload.get("associated_browser_context") or {}),
        "completion_criteria": list(payload.get("completion_criteria") or []),
        "verification_status": str(payload.get("verification_status") or "PENDING"),
        "status_history": list(payload.get("status_history") or []),
    }
    task["status_output"] = _safe_task_summary(task)

    resolved = _ensure_db(db_path)
    connection = sqlite3.connect(str(resolved))
    connection.row_factory = sqlite3.Row
    try:
        connection.execute(
            """
            INSERT INTO task_ledger (
                task_id, objective, current_stage, current_sub_goal, status,
                selected_tools, evidence_refs, action_lineage, approval_lineage,
                verification_history, retry_history, final_outcome,
                goal_plan, subgoal_statuses, current_subgoal_id, plan_version, plan_hash,
                plan_revisions, task_retry_count, subgoal_retry_count, failure_classifications,
                adaptation_history, completion_evidence, subgoal_lineage, execution_ids, consumed_execution_ids,
created_at, updated_at, resumed_at, resume_reason, status_reason, status_output,
                task_answer,
                parent_goal, source, source_reference, priority, deadline, deadline_confidence,
                deadline_evidence, commitment, dependencies, blocked_by, associated_files,
                associated_conversations, associated_applications, associated_browser_context,
                completion_criteria, verification_status, status_history
            ) VALUES (
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?
            )
            """,
            (
                task_id,
                task["objective"],
                task["current_stage"],
                task["current_sub_goal"],
                task["status"],
                _serialize_json(task["selected_tools"]),
                _serialize_json(task["evidence_refs"]),
                _serialize_json(task["action_lineage"]),
                _serialize_json(task["approval_lineage"]),
                _serialize_json(task["verification_history"]),
                _serialize_json(task["retry_history"]),
                task["final_outcome"],
                _serialize_json(task["goal_plan"]),
                _serialize_json(task["subgoal_statuses"]),
                task["current_subgoal_id"],
                task["plan_version"],
                task["plan_hash"],
                task["plan_revisions"],
                task["task_retry_count"],
                _serialize_json(task["subgoal_retry_count"]),
                _serialize_json(task["failure_classifications"]),
                _serialize_json(task["adaptation_history"]),
                _serialize_json(task["completion_evidence"]),
                _serialize_json(task["subgoal_lineage"]),
                _serialize_json(task["execution_ids"]),
                _serialize_json(task["consumed_execution_ids"]),
                task["created_at"],
                task["updated_at"],
                task["resumed_at"],
                task["resume_reason"],
                task["status_reason"],
                task["status_output"],
                task["task_answer"],
                task["parent_goal"],
                task["source"],
                task["source_reference"],
                task["priority"],
                task["deadline"],
                task["deadline_confidence"],
                _serialize_json(task["deadline_evidence"]),
                task["commitment"],
                _serialize_json(task["dependencies"]),
                _serialize_json(task["blocked_by"]),
                _serialize_json(task["associated_files"]),
                _serialize_json(task["associated_conversations"]),
                _serialize_json(task["associated_applications"]),
                _serialize_json(task["associated_browser_context"]),
                _serialize_json(task["completion_criteria"]),
                task["verification_status"],
                _serialize_json(task["status_history"]),
            ),
        )
        connection.commit()
    finally:
        connection.close()

    _record_task_event_record(
        task_id,
        "TASK_CREATED",
        {"objective": task["objective"], "current_stage": task["current_stage"], "status": task["status"]},
        db_path=db_path,
        current_stage=task["current_stage"],
        status=task["status"],
    )
    stored = get_task(task_id, db_path=db_path)
    if stored is None:
        return task
    return stored


def get_task(task_id: str, *, db_path: str | Path | None = None) -> dict[str, Any] | None:
    resolved = _ensure_db(db_path)
    connection = sqlite3.connect(str(resolved))
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            "SELECT * FROM task_ledger WHERE task_id = ?",
            (task_id,),
        ).fetchone()
    finally:
        connection.close()
    task = _coerce_task_row(row)
    if task is None:
        return None
    task["event_history"] = _read_task_events(task_id, db_path=db_path)
    task["status_output"] = _safe_task_summary(task)
    return task


def list_recent_tasks(limit: int = 10, *, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    resolved = _ensure_db(db_path)
    connection = sqlite3.connect(str(resolved))
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            "SELECT task_id FROM task_ledger ORDER BY created_at DESC LIMIT ?",
            (max(1, min(int(limit), 100)),),
        ).fetchall()
    finally:
        connection.close()
    tasks: list[dict[str, Any]] = []
    for row in rows:
        task = get_task(row[0], db_path=db_path)
        if task is not None:
            tasks.append(task)
    return tasks


def record_task_event(
    task_id: str,
    event_type: str,
    payload: Any | None = None,
    *,
    db_path: str | Path | None = None,
    current_stage: str = "",
    status: str = "",
) -> dict[str, Any]:
    return _record_task_event_record(task_id, event_type, payload or {}, db_path=db_path, current_stage=current_stage, status=status)


def update_task_commitments(
    task_id: str,
    *,
    parent_goal: str | None = None,
    source: str | None = None,
    source_reference: str | None = None,
    priority: str | None = None,
    deadline: str | None = None,
    deadline_confidence: str | None = None,
    deadline_evidence: list[dict[str, Any]] | None = None,
    commitment: str | None = None,
    dependencies: list[str] | None = None,
    blocked_by: list[str] | None = None,
    associated_files: list[str] | None = None,
    associated_conversations: list[str] | None = None,
    associated_applications: list[str] | None = None,
    associated_browser_context: dict[str, Any] | None = None,
    completion_criteria: list[str] | None = None,
    verification_status: str | None = None,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    existing = get_task(task_id, db_path=db_path)
    if existing is None:
        raise ValueError(f"Task {task_id} was not found.")
    values = {
        "parent_goal": parent_goal,
        "source": source,
        "source_reference": source_reference,
        "priority": priority,
        "deadline": deadline,
        "deadline_confidence": deadline_confidence,
        "deadline_evidence": deadline_evidence,
        "commitment": commitment,
        "dependencies": dependencies,
        "blocked_by": blocked_by,
        "associated_files": associated_files,
        "associated_conversations": associated_conversations,
        "associated_applications": associated_applications,
        "associated_browser_context": associated_browser_context,
        "completion_criteria": completion_criteria,
        "verification_status": verification_status,
    }
    updates = {key: value for key, value in values.items() if value is not None}
    if priority is not None and str(priority).upper() not in {"LOW", "NORMAL", "HIGH", "CRITICAL"}:
        raise ValueError("Unknown task priority.")
    if deadline is not None:
        from app.agent.task_commitments import validate_deadline
        validate_deadline(deadline=deadline, source=source or existing.get("source", ""), evidence=deadline_evidence or existing.get("deadline_evidence", []), confidence=deadline_confidence or existing.get("deadline_confidence", ""))
    if not updates:
        return existing
    assignments = []
    parameters: list[Any] = []
    for key, value in updates.items():
        assignments.append(f"{key} = ?")
        parameters.append(_serialize_json(value) if key in {"deadline_evidence", "dependencies", "blocked_by", "associated_files", "associated_conversations", "associated_applications", "associated_browser_context", "completion_criteria"} else redact_text(value))
    assignments.append("updated_at = ?")
    parameters.append(_now_iso())
    parameters.append(task_id)
    connection = sqlite3.connect(str(_ensure_db(db_path)))
    try:
        connection.execute(f"UPDATE task_ledger SET {', '.join(assignments)} WHERE task_id = ?", parameters)
        connection.commit()
    finally:
        connection.close()
    record_task_event(task_id, "STATUS_CHANGED", {"commitment_fields_updated": sorted(updates)}, db_path=db_path, status=existing.get("status", ""))
    return get_task(task_id, db_path=db_path) or existing


def update_task_status(
    task_id: str,
    new_status: str,
    *,
    current_stage: str | None = None,
    current_sub_goal: str | None = None,
    selected_tools: list[str] | tuple[str, ...] | None = None,
    evidence_refs: list[str] | tuple[str, ...] | None = None,
    action_lineage: dict[str, Any] | None = None,
    approval_lineage: dict[str, Any] | None = None,
    verification_history: list[str] | tuple[str, ...] | None = None,
    retry_history: list[str] | tuple[str, ...] | None = None,
    final_outcome: str | None = None,
    status_reason: str | None = None,
    resume_reason: str | None = None,
    goal_plan: list[dict[str, Any]] | None = None,
    subgoal_statuses: dict[str, str] | None = None,
    current_subgoal_id: str | None = None,
    plan_version: str | None = None,
    plan_hash: str | None = None,
    plan_revisions: int | None = None,
    task_retry_count: int | None = None,
    subgoal_retry_count: dict[str, int] | None = None,
    failure_classifications: dict[str, str] | None = None,
    adaptation_history: list[dict[str, Any]] | None = None,
    completion_evidence: list[str] | None = None,
    subgoal_lineage: dict[str, dict[str, Any]] | None = None,
    execution_ids: dict[str, str] | None = None,
    consumed_execution_ids: list[str] | None = None,
    plan_history: list[dict[str, Any]] | None = None,
    recovery_history: list[dict[str, Any]] | None = None,
    recovery_attempts: int | None = None,
    task_answer: str | None = None,
    verification_status: str | None = None,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    existing = get_task(task_id, db_path=db_path)
    if existing is None:
        raise ValueError(f"Task {task_id} was not found.")

    next_status = str(new_status or "").upper()
    _validate_transition(existing["status"], next_status)

    updates: dict[str, Any] = {
        "status": next_status,
        "updated_at": _now_iso(),
        "current_stage": current_stage or existing["current_stage"],
        "current_sub_goal": current_sub_goal or existing["current_sub_goal"],
        "status_reason": redact_text(status_reason or existing.get("status_reason") or "Task state updated."),
        "resume_reason": redact_text(resume_reason or existing.get("resume_reason") or ""),
    }
    if selected_tools is not None:
        updates["selected_tools"] = [redact_text(item) for item in _normalize_list(selected_tools)]
    else:
        updates["selected_tools"] = existing["selected_tools"]
    if "goal_plan" in existing:
        updates["goal_plan"] = existing.get("goal_plan", [])
    if "subgoal_statuses" in existing:
        updates["subgoal_statuses"] = existing.get("subgoal_statuses", {})
    if "current_subgoal_id" in existing:
        updates["current_subgoal_id"] = existing.get("current_subgoal_id", "")
    if "plan_version" in existing:
        updates["plan_version"] = existing.get("plan_version", "v1")
    if "plan_hash" in existing:
        updates["plan_hash"] = existing.get("plan_hash", "")
    if "task_retry_count" in existing:
        updates["task_retry_count"] = int(existing.get("task_retry_count", 0) or 0)
    if "subgoal_retry_count" in existing:
        updates["subgoal_retry_count"] = existing.get("subgoal_retry_count", {})
    if "failure_classifications" in existing:
        updates["failure_classifications"] = existing.get("failure_classifications", {})
    if "adaptation_history" in existing:
        updates["adaptation_history"] = existing.get("adaptation_history", [])
    if "completion_evidence" in existing:
        updates["completion_evidence"] = existing.get("completion_evidence", [])
    if "subgoal_lineage" in existing:
        updates["subgoal_lineage"] = existing.get("subgoal_lineage", {})
    if "execution_ids" in existing:
        updates["execution_ids"] = existing.get("execution_ids", {})
    if "consumed_execution_ids" in existing:
        updates["consumed_execution_ids"] = existing.get("consumed_execution_ids", [])
    if goal_plan is not None:
        updates["goal_plan"] = [dict(item) for item in goal_plan]
    if subgoal_statuses is not None:
        updates["subgoal_statuses"] = dict(subgoal_statuses)
    if current_subgoal_id is not None:
        updates["current_subgoal_id"] = str(current_subgoal_id)
    if plan_version is not None:
        updates["plan_version"] = str(plan_version)
    if plan_hash is not None:
        updates["plan_hash"] = str(plan_hash)
    if plan_revisions is not None:
        updates["plan_revisions"] = int(plan_revisions)
    if task_retry_count is not None:
        updates["task_retry_count"] = int(task_retry_count)
    if subgoal_retry_count is not None:
        updates["subgoal_retry_count"] = dict(subgoal_retry_count)
    if failure_classifications is not None:
        updates["failure_classifications"] = dict(failure_classifications)
    if adaptation_history is not None:
        updates["adaptation_history"] = [dict(item) for item in adaptation_history]
    if completion_evidence is not None:
        updates["completion_evidence"] = [str(item) for item in completion_evidence]
    if subgoal_lineage is not None:
        updates["subgoal_lineage"] = redact_sensitive_data(dict(subgoal_lineage))
    if execution_ids is not None:
        updates["execution_ids"] = {str(key): str(value) for key, value in execution_ids.items()}
    if consumed_execution_ids is not None:
        updates["consumed_execution_ids"] = [str(item) for item in consumed_execution_ids]
    if plan_history is not None:
        updates["plan_history"] = [dict(item) for item in plan_history]
    if recovery_history is not None:
        updates["recovery_history"] = [dict(item) for item in recovery_history]
    if recovery_attempts is not None:
        updates["recovery_attempts"] = int(recovery_attempts)
    if evidence_refs is not None:
        updates["evidence_refs"] = [redact_text(item) for item in _normalize_list(evidence_refs)]
    else:
        updates["evidence_refs"] = existing["evidence_refs"]
    if action_lineage is not None:
        updates["action_lineage"] = redact_sensitive_data(dict(_normalize_dict(action_lineage)))
    else:
        updates["action_lineage"] = existing["action_lineage"]
    if approval_lineage is not None:
        updates["approval_lineage"] = redact_sensitive_data(dict(_normalize_dict(approval_lineage)))
    else:
        updates["approval_lineage"] = existing["approval_lineage"]
    if verification_history is not None:
        updates["verification_history"] = [redact_text(item) for item in _normalize_list(verification_history)]
    else:
        updates["verification_history"] = existing["verification_history"]
    if retry_history is not None:
        updates["retry_history"] = [redact_text(item) for item in _normalize_list(retry_history)]
    else:
        updates["retry_history"] = existing["retry_history"]
    if final_outcome is not None:
        updates["final_outcome"] = final_outcome
    else:
        updates["final_outcome"] = existing["final_outcome"]
    if task_answer is not None:
        updates["task_answer"] = _bound_answer(task_answer)
    else:
        updates["task_answer"] = existing.get("task_answer", "")
    if verification_status is not None:
        updates["verification_status"] = redact_text(verification_status)[:120]
    else:
        updates["verification_status"] = existing.get("verification_status", "PENDING")

    resolved = _ensure_db(db_path)
    connection = sqlite3.connect(str(resolved))
    connection.row_factory = sqlite3.Row
    try:
        connection.execute(
            """
            UPDATE task_ledger SET
                current_stage = ?,
                current_sub_goal = ?,
                status = ?,
                selected_tools = ?,
                evidence_refs = ?,
                action_lineage = ?,
                approval_lineage = ?,
                verification_history = ?,
                retry_history = ?,
                final_outcome = ?,
                goal_plan = ?,
                subgoal_statuses = ?,
                current_subgoal_id = ?,
                plan_version = ?,
                plan_hash = ?,
                plan_revisions = ?,
                task_retry_count = ?,
                subgoal_retry_count = ?,
                failure_classifications = ?,
                adaptation_history = ?,
                completion_evidence = ?,
                subgoal_lineage = ?,
                execution_ids = ?,
                consumed_execution_ids = ?,
                plan_history = ?,
                recovery_history = ?,
                recovery_attempts = ?,
                updated_at = ?,
                resume_reason = ?,
                status_reason = ?,
                status_output = ?,
                task_answer = ?,
                verification_status = ?
            WHERE task_id = ?
            """,
            (
                updates["current_stage"],
                updates["current_sub_goal"],
                updates["status"],
                _serialize_json(updates["selected_tools"]),
                _serialize_json(updates["evidence_refs"]),
                _serialize_json(updates["action_lineage"]),
                _serialize_json(updates["approval_lineage"]),
                _serialize_json(updates["verification_history"]),
                _serialize_json(updates["retry_history"]),
                updates["final_outcome"],
                _serialize_json(updates.get("goal_plan", existing.get("goal_plan", []))),
                _serialize_json(updates.get("subgoal_statuses", existing.get("subgoal_statuses", {}))),
                updates.get("current_subgoal_id", existing.get("current_subgoal_id", "")),
                updates.get("plan_version", existing.get("plan_version", "v1")),
                updates.get("plan_hash", existing.get("plan_hash", "")),
                int(existing.get("plan_revisions", 0) or 0),
                int(updates.get("task_retry_count", existing.get("task_retry_count", 0) or 0)),
                _serialize_json(updates.get("subgoal_retry_count", existing.get("subgoal_retry_count", {}))),
                _serialize_json(updates.get("failure_classifications", existing.get("failure_classifications", {}))),
                _serialize_json(updates.get("adaptation_history", existing.get("adaptation_history", []))),
                _serialize_json(updates.get("completion_evidence", existing.get("completion_evidence", []))),
                _serialize_json(updates.get("subgoal_lineage", existing.get("subgoal_lineage", {}))),
                _serialize_json(updates.get("execution_ids", existing.get("execution_ids", {}))),
                _serialize_json(updates.get("consumed_execution_ids", existing.get("consumed_execution_ids", []))),
                _serialize_json(updates.get("plan_history", existing.get("plan_history", []))),
                _serialize_json(updates.get("recovery_history", existing.get("recovery_history", []))),
                int(updates.get("recovery_attempts", existing.get("recovery_attempts", 0) or 0)),
                updates["updated_at"],
                updates["resume_reason"],
                updates["status_reason"],
                _safe_task_summary({**existing, **updates}),
                updates["task_answer"],
                updates["verification_status"],
                task_id,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    event_map = {
        "CREATED": "TASK_CREATED",
        "RUNNING": "STATUS_CHANGED",
        "WAITING_APPROVAL": "APPROVAL_REQUESTED",
        "VERIFYING": "VERIFICATION_COMPLETED",
        "PAUSED": "TASK_PAUSED",
        "COMPLETED": "TASK_COMPLETED",
        "FAILED": "TASK_FAILED",
        "BLOCKED": "TASK_BLOCKED",
        "CANCELLED": "TASK_CANCELLED",
    }
    payload = {
        "from_status": existing["status"],
        "to_status": next_status,
        "current_stage": updates["current_stage"],
        "status_reason": updates["status_reason"],
        "final_outcome": updates["final_outcome"],
        "approval_lineage": updates["approval_lineage"],
        "verification_history": updates["verification_history"],
        "retry_history": updates["retry_history"],
    }
    if updates["current_stage"] != existing["current_stage"] or next_status != existing["status"]:
        _record_task_event_record(
            task_id,
            "STAGE_CHANGED",
            {
                "from_stage": existing["current_stage"],
                "to_stage": updates["current_stage"],
                "from_status": existing["status"],
                "to_status": next_status,
                "status_reason": updates["status_reason"],
            },
            db_path=db_path,
            current_stage=updates["current_stage"],
            status=next_status,
        )
    event_type = event_map.get(next_status, "STATUS_CHANGED")
    _record_task_event_record(
        task_id,
        event_type,
        payload,
        db_path=db_path,
        current_stage=updates["current_stage"],
        status=next_status,
    )
    return get_task(task_id, db_path=db_path)


def resume_task(
    task_id: str,
    *,
    resume_reason: str | None = None,
    force: bool = False,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    task = get_task(task_id, db_path=db_path)
    if task is None:
        raise ValueError(f"Task {task_id} does not exist.")

    status = str(task["status"] or "").upper()
    if status in {"COMPLETED", "CANCELLED"}:
        raise ValueError("Completed and cancelled tasks cannot be resumed silently.")
    if status in {"FAILED", "BLOCKED"} and not force:
        raise ValueError("Failed or blocked tasks require an explicit resume request and a forced resume path.")
    if status not in {"PAUSED", "RUNNING", "WAITING_APPROVAL", "VERIFYING", "CREATED", "FAILED", "BLOCKED"}:
        raise ValueError(f"Task {task_id} is not eligible for resume.")
    if not resume_reason and status in {"FAILED", "BLOCKED"}:
        raise ValueError("A resume reason is required before a failed or blocked task can resume.")
    if not resume_reason and status in {"PAUSED", "WAITING_APPROVAL", "VERIFYING"}:
        raise ValueError("A resume reason is required to continue a paused or waiting task.")

    task["resume_reason"] = redact_text(resume_reason or task.get("resume_reason") or "Explicit resume requested.")
    task["resumed_at"] = _now_iso()
    if task.get("approval_lineage"):
        task["approval_lineage"] = redact_sensitive_data({
            **task["approval_lineage"],
            "status": "STALE",
            "reason": "Approval invalidated before resume; fresh approval required.",
        })

    updated = update_task_status(
        task_id,
        "RUNNING",
        current_stage=(task["current_stage"] or "REQUEST"),
        current_sub_goal=task["current_sub_goal"],
        selected_tools=task["selected_tools"],
        evidence_refs=task["evidence_refs"],
        action_lineage=task["action_lineage"],
        approval_lineage=task["approval_lineage"],
        verification_history=task["verification_history"],
        retry_history=task["retry_history"],
        final_outcome=task["final_outcome"],
        status_reason="Task resumed after explicit revalidation.",
        resume_reason=task["resume_reason"],
        db_path=db_path,
    )
    updated["resumed_at"] = task["resumed_at"]
    updated["resume_reason"] = task["resume_reason"]
    resolved = _ensure_db(db_path)
    connection = sqlite3.connect(str(resolved))
    try:
        connection.execute(
            "UPDATE task_ledger SET resumed_at = ?, resume_reason = ? WHERE task_id = ?",
            (updated["resumed_at"], updated["resume_reason"], task_id),
        )
        connection.commit()
    finally:
        connection.close()
    _record_task_event_record(
        task_id,
        "TASK_RESUMED",
        {"resume_reason": updated["resume_reason"], "current_stage": updated["current_stage"], "status": "RUNNING"},
        db_path=db_path,
        current_stage=updated["current_stage"],
        status="RUNNING",
    )
    return get_task(task_id, db_path=db_path)
