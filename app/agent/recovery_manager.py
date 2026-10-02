from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.agent.execution_journal import (
    invalidate_checkpoint,
    list_checkpoints_for_task,
    load_checkpoint,
    record_recovery_event,
)
from app.memory.task_ledger import get_task
from app.security.audit_logger import record_audit_event as _store_audit_event
from app.security.permissions import is_authorized_path
from app.security.risk_engine import BLOCKED, evaluate_risk
from app.security.sensitive_data import redact_sensitive_data, redact_text


def record_audit_event(event_type: str, **payload: Any) -> bool:
    """Module-local audit entry point.

    Recovery decisions are security decisions: they are recorded in the
    calling store as before and additionally mirrored to the central audit
    database so halt/block/revalidate outcomes stay centrally discoverable.
    """
    payload.setdefault("mirror_central", True)
    return _store_audit_event(event_type, **payload)

TERMINAL_TASKS = {"COMPLETED", "FAILED", "BLOCKED", "CANCELLED"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _hash_file(path: str | Path) -> str:
    candidate = Path(path)
    if not candidate.exists() or not candidate.is_file():
        return ""
    digest = hashlib.sha256()
    with candidate.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _current_target_hash(target: str, workspace_root: str | Path) -> str:
    root = Path(workspace_root).resolve()
    candidate = Path(target)
    resolved = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    if not resolved.exists() or not resolved.is_file():
        return ""
    return _hash_file(resolved)


def _validate_workspace_binding(action_target: str, workspace_root: str | Path | None = None) -> tuple[bool, str]:
    if not action_target:
        return False, "No recovery target was supplied."
    root = Path(workspace_root).resolve() if workspace_root is not None else Path("workspace").resolve()
    candidate = Path(action_target)
    resolved = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    if not is_authorized_path(str(resolved), root):
        return False, "Target is outside the authorized workspace."
    return True, "authorized"


def _decision(decision: str, task_id: str, checkpoint_id: str, *, reason: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = {
        "task_id": task_id,
        "checkpoint_id": checkpoint_id,
        "decision": decision,
        "reason": redact_text(reason),
        "details": redact_sensitive_data(details or {}),
        "timestamp": _now_iso(),
    }
    return payload


def evaluate_recovery(
    task_id: str,
    *,
    current_state: dict[str, Any] | None = None,
    workspace_root: str | Path | None = None,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    state = dict(current_state or {})
    if not task_id:
        return _decision("HALT_AND_BLOCK", "", "", reason="Recovery requires a valid task identifier.", details={"error": "missing_task_id"})

    task = get_task(task_id, db_path=db_path)
    if task is None:
        decision = _decision("HALT_AND_BLOCK", task_id, "", reason="Task does not exist; recovery cannot continue.", details={"error": "unknown_task"})
        record_audit_event("recovery_failed", actor="recovery_manager", tool="execution_recovery", target=task_id, result="HALT_AND_BLOCK", reason=decision["reason"], metadata={"error": "unknown_task"}, db_path=db_path)
        return decision

    status = str(task.get("status") or "").upper()
    if status in TERMINAL_TASKS:
        decision = _decision("HALT_AND_BLOCK", task_id, "", reason="Terminal tasks cannot be resumed silently without an explicit recovery path.", details={"terminal_status": status})
        record_audit_event("recovery_failed", actor="recovery_manager", tool="execution_recovery", target=task_id, result="HALT_AND_BLOCK", reason=decision["reason"], metadata={"terminal_status": status}, db_path=db_path)
        return decision

    checkpoints = list_checkpoints_for_task(task_id, db_path=db_path)
    if not checkpoints:
        decision = _decision("HALT_AND_BLOCK", task_id, "", reason="No valid execution checkpoint was found for this task.", details={"reason": "missing_checkpoint"})
        record_audit_event("recovery_failed", actor="recovery_manager", tool="execution_recovery", target=task_id, result="HALT_AND_BLOCK", reason=decision["reason"], metadata={"error": "missing_checkpoint"}, db_path=db_path)
        return decision

    checkpoint = checkpoints[0]
    checkpoint_id = checkpoint.get("checkpoint_id", "")
    if checkpoint.get("is_valid") == 0:
        decision = _decision("HALT_AND_BLOCK", task_id, checkpoint_id, reason=f"Checkpoint is invalid: {checkpoint.get('invalid_reason', 'unknown reason')}", details={"invalid_reason": checkpoint.get("invalid_reason", "")})
        record_audit_event("recovery_failed", actor="recovery_manager", tool="execution_recovery", target=task_id, result="HALT_AND_BLOCK", reason=decision["reason"], metadata={"checkpoint_id": checkpoint_id}, db_path=db_path)
        return decision

    record_recovery_event(task_id, "recovery_attempt", {"checkpoint_id": checkpoint_id, "task_status": status}, checkpoint_id=checkpoint_id, db_path=db_path)

    selected_tools = state.get("selected_tools") or checkpoint.get("selected_tools") or []
    action_type = checkpoint.get("action_type") or state.get("action_type") or ""
    action_target = checkpoint.get("action_target") or state.get("target_file") or ""
    proposal_hash = checkpoint.get("proposal_hash") or state.get("proposal_hash") or ""
    risk_level = checkpoint.get("risk_level") or state.get("risk_level") or ""
    approval_binding = checkpoint.get("approval_binding") or state.get("approval_binding") or {}
    approval_status = checkpoint.get("approval_status") or state.get("approval_status") or "UNKNOWN"
    approval_expiry = checkpoint.get("approval_expiry") or state.get("approval_expiry") or ""

    if not action_type or not action_target:
        decision = _decision("HALT_AND_BLOCK", task_id, checkpoint_id, reason="Execution checkpoint does not contain enough action information to safely resume.", details={"missing": ["action_type", "action_target"]})
        record_audit_event("recovery_failed", actor="recovery_manager", tool="execution_recovery", target=task_id, result="HALT_AND_BLOCK", reason=decision["reason"], metadata={"checkpoint_id": checkpoint_id}, db_path=db_path)
        return decision

    is_external_action = action_type.startswith("browser_") or action_type.startswith("desktop_")
    if not is_external_action:
        is_valid_target, target_reason = _validate_workspace_binding(action_target, workspace_root)
        if not is_valid_target:
            decision = _decision("HALT_AND_BLOCK", task_id, checkpoint_id, reason=target_reason, details={"target": action_target})
            record_audit_event("recovery_failed", actor="recovery_manager", tool="execution_recovery", target=task_id, result="HALT_AND_BLOCK", reason=decision["reason"], metadata={"target": action_target}, db_path=db_path)
            return decision

    stored_environment = str(checkpoint.get("environment_fingerprint") or "")
    current_environment = str(state.get("environment_fingerprint") or "")
    if stored_environment and current_environment and stored_environment != current_environment:
        decision = _decision("HALT_AND_BLOCK", task_id, checkpoint_id, reason="Execution environment drift detected during recovery.", details={"stored_environment": stored_environment, "current_environment": current_environment})
        record_audit_event("recovery_environment_drift", actor="recovery_manager", tool="execution_recovery", target=task_id, result="HALT_AND_BLOCK", reason=decision["reason"], db_path=db_path)
        return decision

    stored_target_hash = checkpoint.get("target_hash") or ""
    current_target_hash = "" if is_external_action else _current_target_hash(action_target, workspace_root)
    if stored_target_hash and current_target_hash and stored_target_hash != current_target_hash:
        decision = _decision("REBUILD_PROPOSAL", task_id, checkpoint_id, reason="Target state drift detected; the prior action no longer matches the current workspace state.", details={"stored_target_hash": stored_target_hash, "current_target_hash": current_target_hash, "target": action_target})
        record_audit_event("recovery_drift_detected", actor="recovery_manager", tool="execution_recovery", target=task_id, result="REBUILD_PROPOSAL", reason=decision["reason"], metadata={"stored_target_hash": stored_target_hash, "current_target_hash": current_target_hash}, db_path=db_path)
        invalidate_checkpoint(checkpoint_id, "Target drift detected during recovery validation.", db_path=db_path)
        return decision

    if stored_target_hash and not current_target_hash:
        if approval_binding and (str(approval_binding.get("expires_at") or "") or approval_expiry):
            expiry_value = approval_binding.get("expires_at") or approval_expiry
            expiry = _parse_datetime(expiry_value)
            if expiry is not None and expiry <= datetime.now(timezone.utc):
                decision = _decision("REVALIDATE_APPROVAL", task_id, checkpoint_id, reason="Approval is expired and must be revalidated.", details={"approval_expiry": expiry_value, "target": action_target})
                record_audit_event("recovery_validation", actor="recovery_manager", tool="execution_recovery", target=task_id, result="REVALIDATE_APPROVAL", reason=decision["reason"], metadata={"approval_expiry": expiry_value}, db_path=db_path)
                return decision
        decision = _decision("HALT_AND_BLOCK", task_id, checkpoint_id, reason="The target file no longer exists or cannot be validated in the current workspace.", details={"target": action_target})
        record_audit_event("recovery_failed", actor="recovery_manager", tool="execution_recovery", target=task_id, result="HALT_AND_BLOCK", reason=decision["reason"], metadata={"target": action_target}, db_path=db_path)
        return decision

    if checkpoint.get("selected_tools") and selected_tools:
        checkpoint_tools = {str(item).strip() for item in checkpoint.get("selected_tools", []) if str(item).strip()}
        current_tools = {str(item).strip() for item in selected_tools if str(item).strip()}
        if checkpoint_tools and not current_tools.issubset(checkpoint_tools):
            decision = _decision("REBUILD_PROPOSAL", task_id, checkpoint_id, reason="The selected tool plan does not match the durable checkpoint.", details={"checkpoint_tools": sorted(checkpoint_tools), "current_tools": sorted(current_tools)})
            record_audit_event("recovery_failed", actor="recovery_manager", tool="execution_recovery", target=task_id, result="REBUILD_PROPOSAL", reason=decision["reason"], metadata={"checkpoint_tools": sorted(checkpoint_tools), "current_tools": sorted(current_tools)}, db_path=db_path)
            return decision

    tool_name = (selected_tools[0] if isinstance(selected_tools, list) and selected_tools else None) or (checkpoint.get("selected_tools") or [None])[0]
    risk_decision = evaluate_risk(action_type, target_path=None if is_external_action else action_target, workspace_root=workspace_root, tool_name=str(tool_name) if tool_name else None)
    if risk_decision.get("risk_level") == BLOCKED or risk_decision.get("allowed") is False:
        decision = _decision("HALT_AND_BLOCK", task_id, checkpoint_id, reason=risk_decision.get("reason", "Current risk evaluation blocked recovery."), details={"risk_decision": risk_decision})
        record_audit_event("recovery_blocked", actor="recovery_manager", tool="execution_recovery", target=task_id, result="HALT_AND_BLOCK", reason=decision["reason"], metadata={"risk_decision": risk_decision}, db_path=db_path)
        return decision

    if risk_level and risk_decision.get("risk_level") != risk_level:
        decision = _decision("REVALIDATE_APPROVAL", task_id, checkpoint_id, reason="Current risk classification differs from the persisted checkpoint. Fresh approval is required.", details={"stored_risk": risk_level, "current_risk": risk_decision.get("risk_level")})
        record_audit_event("recovery_validation", actor="recovery_manager", tool="execution_recovery", target=task_id, result="REVALIDATE_APPROVAL", reason=decision["reason"], metadata={"stored_risk": risk_level, "current_risk": risk_decision.get("risk_level")}, db_path=db_path)
        return decision

    if risk_decision.get("risk_level") == "READ_ONLY" and not action_type.startswith(("browser_", "desktop_", "fix")):
        decision = _decision("CONTINUE_READ_ONLY", task_id, checkpoint_id, reason="Read-only checkpoint is valid and can resume without consequential approval.", details={"risk_level": risk_decision.get("risk_level"), "target_hash": current_target_hash})
        record_audit_event("recovery_validation", actor="recovery_manager", tool="execution_recovery", target=task_id, result="CONTINUE_READ_ONLY", reason=decision["reason"], metadata={"checkpoint_id": checkpoint_id, "risk_level": risk_decision.get("risk_level")}, db_path=db_path)
        return decision

    if not approval_binding:
        decision = _decision("REVALIDATE_APPROVAL", task_id, checkpoint_id, reason="The checkpoint is missing a valid approval binding.", details={"approval_status": approval_status})
        record_audit_event("recovery_validation", actor="recovery_manager", tool="execution_recovery", target=task_id, result="REVALIDATE_APPROVAL", reason=decision["reason"], metadata={"approval_status": approval_status}, db_path=db_path)
        return decision

    if str(approval_binding.get("task_id") or "") not in {task_id, ""} and approval_binding.get("task_id") != task_id:
        decision = _decision("HALT_AND_BLOCK", task_id, checkpoint_id, reason="Approval binding does not match the task identity.", details={"approval_binding": approval_binding})
        record_audit_event("recovery_failed", actor="recovery_manager", tool="execution_recovery", target=task_id, result="HALT_AND_BLOCK", reason=decision["reason"], metadata={"approval_binding": approval_binding}, db_path=db_path)
        return decision

    if str(approval_binding.get("action_type") or "") and approval_binding.get("action_type") != action_type:
        decision = _decision("REVALIDATE_APPROVAL", task_id, checkpoint_id, reason="Approval was granted for a different action type.", details={"stored_action": approval_binding.get("action_type"), "current_action": action_type})
        record_audit_event("recovery_validation", actor="recovery_manager", tool="execution_recovery", target=task_id, result="REVALIDATE_APPROVAL", reason=decision["reason"], metadata={"stored_action": approval_binding.get("action_type"), "current_action": action_type}, db_path=db_path)
        return decision

    if str(approval_binding.get("target") or "") and approval_binding.get("target") != action_target:
        decision = _decision("REVALIDATE_APPROVAL", task_id, checkpoint_id, reason="Approval target does not match the restored target.", details={"stored_target": approval_binding.get("target"), "current_target": action_target})
        record_audit_event("recovery_validation", actor="recovery_manager", tool="execution_recovery", target=task_id, result="REVALIDATE_APPROVAL", reason=decision["reason"], metadata={"stored_target": approval_binding.get("target"), "current_target": action_target}, db_path=db_path)
        return decision

    if str(approval_binding.get("proposal_hash") or "") and approval_binding.get("proposal_hash") != proposal_hash:
        decision = _decision("REVALIDATE_APPROVAL", task_id, checkpoint_id, reason="Approval proposal hash does not match the current proposal.", details={"stored_proposal_hash": approval_binding.get("proposal_hash"), "current_proposal_hash": proposal_hash})
        record_audit_event("recovery_validation", actor="recovery_manager", tool="execution_recovery", target=task_id, result="REVALIDATE_APPROVAL", reason=decision["reason"], metadata={"stored_proposal_hash": approval_binding.get("proposal_hash"), "current_proposal_hash": proposal_hash}, db_path=db_path)
        return decision

    if str(approval_binding.get("risk_level") or "") and approval_binding.get("risk_level") != risk_decision.get("risk_level"):
        decision = _decision("REVALIDATE_APPROVAL", task_id, checkpoint_id, reason="Approval risk level does not match the current risk classification.", details={"stored_risk": approval_binding.get("risk_level"), "current_risk": risk_decision.get("risk_level")})
        record_audit_event("recovery_validation", actor="recovery_manager", tool="execution_recovery", target=task_id, result="REVALIDATE_APPROVAL", reason=decision["reason"], metadata={"stored_risk": approval_binding.get("risk_level"), "current_risk": risk_decision.get("risk_level")}, db_path=db_path)
        return decision

    if approval_status.upper() != "APPROVED" and approval_status.upper() != "GRANTED":
        decision = _decision("REVALIDATE_APPROVAL", task_id, checkpoint_id, reason="The durable approval is not currently marked as approved.", details={"approval_status": approval_status})
        record_audit_event("recovery_validation", actor="recovery_manager", tool="execution_recovery", target=task_id, result="REVALIDATE_APPROVAL", reason=decision["reason"], metadata={"approval_status": approval_status}, db_path=db_path)
        return decision

    expiry_value = approval_binding.get("expires_at") or approval_expiry
    expiry = _parse_datetime(expiry_value)
    if expiry is not None and expiry <= datetime.now(timezone.utc):
        decision = _decision("REVALIDATE_APPROVAL", task_id, checkpoint_id, reason="Approval is expired and must be revalidated.", details={"approval_expiry": expiry_value})
        record_audit_event("recovery_validation", actor="recovery_manager", tool="execution_recovery", target=task_id, result="REVALIDATE_APPROVAL", reason=decision["reason"], metadata={"approval_expiry": expiry_value}, db_path=db_path)
        return decision

    if status in {"PAUSED", "WAITING_APPROVAL", "VERIFYING", "FAILED", "BLOCKED"}:
        resume_reason = str(state.get("resume_reason") or checkpoint.get("resume_reason") or "").strip()
        if not resume_reason:
            decision = _decision("HALT_AND_BLOCK", task_id, checkpoint_id, reason="An explicit resume reason is required before recovery continues from a paused or waiting task.", details={"status": status})
            record_audit_event("recovery_failed", actor="recovery_manager", tool="execution_recovery", target=task_id, result="HALT_AND_BLOCK", reason=decision["reason"], metadata={"status": status}, db_path=db_path)
            return decision

    decision = _decision("CONTINUE_APPROVED_ACTION", task_id, checkpoint_id, reason="Checkpoint is valid and matches the current workspace and approval constraints.", details={"risk_level": risk_decision.get("risk_level"), "target_hash": current_target_hash})
    record_audit_event("recovery_validation", actor="recovery_manager", tool="execution_recovery", target=task_id, result="CONTINUE_APPROVED_ACTION", reason=decision["reason"], metadata={"checkpoint_id": checkpoint_id, "risk_level": risk_decision.get("risk_level")}, db_path=db_path)
    return decision
