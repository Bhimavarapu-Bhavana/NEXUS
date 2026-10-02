from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.agent.execution_journal import (
    create_checkpoint,
    invalidate_checkpoint,
    list_checkpoints_for_task,
    load_checkpoint,
    mark_checkpoint_validated,
    record_recovery_event,
    update_checkpoint,
)
from app.agent.recovery_manager import evaluate_recovery
from app.memory.task_ledger import create_task, update_task_status
from app.security.audit_logger import get_recent_audit_events, record_audit_event
from app.security.sensitive_data import contains_sensitive_data


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "nexus_phase24.db"


def test_phase24_checkpoint_create_persist_and_reload(db_path):
    task = create_task("Fix the local workspace bug.", db_path=db_path)
    checkpoint = create_checkpoint(
        task["task_id"],
        current_stage="APPROVAL_PENDING",
        current_sub_goal="Request approval for mutation.",
        selected_tools=["fixer"],
        action_type="apply approved code fix",
        action_target="workspace/demo_error.py",
        target_hash="hash-123",
        proposal_hash="proposal-hash-123",
        risk_level="MEDIUM_RISK",
        approval_binding={"task_id": task["task_id"], "approval_id": "approval-1"},
        approval_status="APPROVED",
        approval_expiry="2099-01-01T00:00:00+00:00",
        evidence_refs=["runtime:demo"],
        verification_snapshot="STATUS: SUCCESS",
        retry_count=0,
        retry_reason="",
        resume_required=False,
        resume_reason="",
        environment_fingerprint="env-1",
        db_path=db_path,
    )
    assert checkpoint["checkpoint_id"]
    loaded = load_checkpoint(task["task_id"], db_path=db_path)
    assert loaded is not None
    assert loaded["task_id"] == task["task_id"]
    assert loaded["approval_status"] == "APPROVED"


def test_phase24_checkpoint_update_and_invalidation(db_path):
    task = create_task("Review state after approval.", db_path=db_path)
    checkpoint = create_checkpoint(
        task["task_id"],
        current_stage="WAITING_APPROVAL",
        action_type="apply approved code fix",
        action_target="workspace/demo_error.py",
        proposal_hash="proposal-1",
        risk_level="MEDIUM_RISK",
        approval_status="PENDING",
        approval_expiry="2099-01-01T00:00:00+00:00",
        db_path=db_path,
    )
    updated = update_checkpoint(
        checkpoint["checkpoint_id"],
        approval_status="APPROVED",
        current_stage="ACTION",
        db_path=db_path,
    )
    assert updated["approval_status"] == "APPROVED"
    assert updated["current_stage"] == "ACTION"

    invalidated = invalidate_checkpoint(checkpoint["checkpoint_id"], "Approval was stale.", db_path=db_path)
    assert invalidated["is_valid"] == 0
    assert invalidated["invalid_reason"] == "Approval was stale."


def test_phase24_recovery_of_valid_checkpoint(db_path, tmp_path):
    task = create_task("Recover a valid execution checkpoint.", db_path=db_path)
    file_path = tmp_path / "demo_fix.py"
    file_path.write_text("print('ready')\n", encoding="utf-8")
    target_hash = __import__("hashlib").sha256(file_path.read_bytes()).hexdigest()

    checkpoint = create_checkpoint(
        task["task_id"],
        current_stage="ACTION",
        current_sub_goal="Apply approved change.",
        selected_tools=["fixer"],
        action_type="apply approved code fix",
        action_target=str(file_path),
        target_hash=target_hash,
        proposal_hash="proposal-match",
        risk_level="MEDIUM_RISK",
        approval_binding={
            "task_id": task["task_id"],
            "checkpoint_id": "checkpoint-1",
            "action_type": "apply approved code fix",
            "target": str(file_path),
            "risk_level": "MEDIUM_RISK",
            "proposal_hash": "proposal-match",
            "approval_id": "approval-1",
            "approval_status": "APPROVED",
            "expires_at": "2099-01-01T00:00:00+00:00",
        },
        approval_status="APPROVED",
        approval_expiry="2099-01-01T00:00:00+00:00",
        evidence_refs=["workspace:file=demo_fix.py"],
        verification_snapshot="STATUS: SUCCESS",
        retry_count=0,
        environment_fingerprint="env-1",
        db_path=db_path,
    )
    mark_checkpoint_validated(checkpoint["checkpoint_id"], db_path=db_path)

    task = update_task_status(task["task_id"], "RUNNING", current_stage="ACTION", status_reason="Recovery copy.", db_path=db_path)
    decision = evaluate_recovery(
        task["task_id"],
        current_state={"user_request": "Recover a valid execution checkpoint.", "target_file": str(file_path), "selected_tools": ["fixer"], "approval_required": True},
        workspace_root=str(tmp_path),
        db_path=db_path,
    )
    assert decision["decision"] in {"CONTINUE_APPROVED_ACTION", "REVALIDATE_APPROVAL"}


def test_phase24_expired_and_mismatched_approval_rejected(db_path):
    task = create_task("Recover with expired approval.", db_path=db_path)
    checkpoint = create_checkpoint(
        task["task_id"],
        current_stage="APPROVAL_PENDING",
        action_type="apply approved code fix",
        action_target="workspace/demo_error.py",
        target_hash="hash-1",
        proposal_hash="proposal-1",
        risk_level="MEDIUM_RISK",
        approval_binding={
            "task_id": task["task_id"],
            "checkpoint_id": "checkpoint-2",
            "action_type": "apply approved code fix",
            "target": "workspace/demo_error.py",
            "risk_level": "MEDIUM_RISK",
            "proposal_hash": "proposal-1",
            "approval_id": "approval-2",
            "approval_status": "APPROVED",
            "expires_at": "2020-01-01T00:00:00+00:00",
        },
        approval_status="APPROVED",
        approval_expiry="2020-01-01T00:00:00+00:00",
        db_path=db_path,
    )
    mark_checkpoint_validated(checkpoint["checkpoint_id"], db_path=db_path)

    decision = evaluate_recovery(
        task["task_id"],
        current_state={"user_request": "Recover with expired approval.", "target_file": "workspace/demo_error.py", "selected_tools": ["fixer"], "approval_required": True},
        workspace_root="workspace",
        db_path=db_path,
    )
    assert decision["decision"] == "REVALIDATE_APPROVAL"

    mismatch = create_checkpoint(
        task["task_id"],
        current_stage="APPROVAL_PENDING",
        action_type="apply approved code fix",
        action_target="workspace/demo_error.py",
        target_hash="hash-a",
        proposal_hash="different-proposal",
        risk_level="HIGH_RISK",
        approval_binding={"task_id": task["task_id"], "approval_id": "approval-3"},
        approval_status="APPROVED",
        approval_expiry="2099-01-01T00:00:00+00:00",
        db_path=db_path,
    )
    mark_checkpoint_validated(mismatch["checkpoint_id"], db_path=db_path)
    decision2 = evaluate_recovery(
        task["task_id"],
        current_state={"user_request": "Mismatch checks.", "target_file": "workspace/demo_error.py", "selected_tools": ["fixer"], "approval_required": True},
        workspace_root="workspace",
        db_path=db_path,
    )
    assert decision2["decision"] in {"REBUILD_PROPOSAL", "REVALIDATE_APPROVAL", "HALT_AND_BLOCK"}


def test_phase24_target_drift_workspace_and_tool_revalidation(db_path, tmp_path):
    task = create_task("Detect drift before action.", db_path=db_path)
    path = tmp_path / "drift_target.py"
    path.write_text("PRINT('old')\n", encoding="utf-8")
    checkpoint = create_checkpoint(
        task["task_id"],
        current_stage="ACTION",
        action_type="apply approved code fix",
        action_target=str(path),
        target_hash="old-hash",
        proposal_hash="proposal-2",
        risk_level="MEDIUM_RISK",
        approval_binding={"task_id": task["task_id"], "approval_id": "approval-4", "proposal_hash": "proposal-2", "risk_level": "MEDIUM_RISK"},
        approval_status="APPROVED",
        approval_expiry="2099-01-01T00:00:00+00:00",
        selected_tools=["fixer"],
        db_path=db_path,
    )
    mark_checkpoint_validated(checkpoint["checkpoint_id"], db_path=db_path)
    path.write_text("PRINT('new')\n", encoding="utf-8")

    decision = evaluate_recovery(
        task["task_id"],
        current_state={"user_request": "Detect drift.", "target_file": str(path), "selected_tools": ["fixer"], "approval_required": True},
        workspace_root=str(tmp_path),
        db_path=db_path,
    )
    assert decision["decision"] in {"REBUILD_PROPOSAL", "HALT_AND_BLOCK"}


def test_phase24_secret_redaction_and_audit_creation(db_path):
    task = create_task("Keep secrets out of the state record.", db_path=db_path)
    checkpoint = create_checkpoint(
        task["task_id"],
        current_stage="ACTION",
        action_type="apply approved code fix",
        action_target="workspace/demo_error.py",
        target_hash="hash-xyz",
        proposal_hash="proposal-xyz",
        risk_level="MEDIUM_RISK",
        approval_binding={"token": "super-secret-token", "approval_id": "approval-5"},
        approval_status="APPROVED",
        approval_expiry="2099-01-01T00:00:00+00:00",
        redacted_action_metadata={"token": "super-secret-token", "detail": "allowed"},
        db_path=db_path,
    )
    payload = json.dumps(checkpoint, default=str)
    assert "super-secret-token" not in payload
    assert "[REDACTED]" in payload or "detail" in payload

    audit_event = record_recovery_event(
        task["task_id"],
        "recovery_attempt",
        {"checkpoint_id": checkpoint["checkpoint_id"], "status": "recovery_checked"},
        checkpoint_id=checkpoint["checkpoint_id"],
        db_path=db_path,
    )
    assert audit_event["task_id"] == task["task_id"]

    events = get_recent_audit_events(limit=10, db_path=db_path)
    assert any(event["event_type"] == "recovery_attempt" or event["result"] == "recovery_checked" for event in events)


def test_phase24_audit_failure_fail_closed(db_path, monkeypatch):
    task = create_task("Audit should fail closed.", db_path=db_path)
    create_checkpoint(
        task["task_id"],
        current_stage="ACTION",
        action_type="apply approved code fix",
        action_target="workspace/demo_error.py",
        target_hash="hash-99",
        proposal_hash="proposal-99",
        risk_level="MEDIUM_RISK",
        approval_status="APPROVED",
        approval_expiry="2099-01-01T00:00:00+00:00",
        db_path=db_path,
    )

    def boom(*args, **kwargs):
        return False

    monkeypatch.setattr("app.agent.recovery_manager.record_audit_event", boom)
    decision = evaluate_recovery(
        task["task_id"],
        current_state={"user_request": "Audit fail closed.", "target_file": "workspace/demo_error.py", "selected_tools": ["fixer"], "approval_required": True},
        workspace_root="workspace",
        db_path=db_path,
    )
    assert decision["decision"] == "HALT_AND_BLOCK"


def test_phase24_invalid_terminal_resume_and_explicit_reason_required(db_path):
    task = create_task("Terminal tasks cannot resume silently.", db_path=db_path)
    update_task_status(task["task_id"], "RUNNING", current_stage="ACTION", status_reason="Start", db_path=db_path)
    update_task_status(task["task_id"], "COMPLETED", current_stage="FINAL_OUTCOME", final_outcome="SUCCESS", db_path=db_path)

    failure = evaluate_recovery(
        task["task_id"],
        current_state={"user_request": "Resume after completion.", "target_file": "workspace/demo_error.py", "selected_tools": ["fixer"], "approval_required": True},
        workspace_root="workspace",
        db_path=db_path,
    )
    assert failure["decision"] == "HALT_AND_BLOCK"

    task2 = create_task("Paused task needs reason.", db_path=db_path)
    update_task_status(task2["task_id"], "PAUSED", current_stage="PAUSED", status_reason="Waiting for user", db_path=db_path)
    decision = evaluate_recovery(
        task2["task_id"],
        current_state={"user_request": "Resume paused task.", "target_file": "workspace/demo_error.py", "selected_tools": ["fixer"], "approval_required": True, "resume_reason": ""},
        workspace_root="workspace",
        db_path=db_path,
    )
    assert decision["decision"] == "HALT_AND_BLOCK"


def test_phase24_recovery_rejects_untrusted_action_payloads(db_path):
    task = create_task("Reject arbitrary recovery actions.", db_path=db_path)
    checkpoint = create_checkpoint(
        task["task_id"],
        current_stage="ACTION",
        action_type="arbitrary command",
        action_target="workspace/demo_error.py",
        target_hash="hash-1",
        proposal_hash="proposal-1",
        risk_level="BLOCKED",
        approval_status="APPROVED",
        approval_expiry="2099-01-01T00:00:00+00:00",
        db_path=db_path,
    )
    mark_checkpoint_validated(checkpoint["checkpoint_id"], db_path=db_path)

    decision = evaluate_recovery(
        task["task_id"],
        current_state={"user_request": "Reject arbitrary action.", "target_file": "workspace/demo_error.py", "selected_tools": ["browser_controller"], "approval_required": True},
        workspace_root="workspace",
        db_path=db_path,
    )
    assert decision["decision"] in {"HALT_AND_BLOCK", "REBUILD_PROPOSAL"}


def test_phase24_list_checkpoints_for_task(db_path):
    task = create_task("List checkpoints.", db_path=db_path)
    first = create_checkpoint(task["task_id"], current_stage="REQUEST", action_type="inspect", action_target="workspace/demo.py", proposal_hash="p1", risk_level="READ_ONLY", db_path=db_path)
    second = create_checkpoint(task["task_id"], current_stage="ACTION", action_type="apply approved code fix", action_target="workspace/demo.py", proposal_hash="p2", risk_level="MEDIUM_RISK", db_path=db_path)
    checkpoints = list_checkpoints_for_task(task["task_id"], db_path=db_path)
    assert len(checkpoints) >= 2
    assert first["checkpoint_id"] in {item["checkpoint_id"] for item in checkpoints}
    assert second["checkpoint_id"] in {item["checkpoint_id"] for item in checkpoints}


def test_phase24_no_secret_values_are_persisted_in_task_state(db_path):
    task = create_task("Keep credentials out of task ledger.", db_path=db_path)
    checkpoint = create_checkpoint(
        task["task_id"],
        current_stage="ACTION",
        action_type="apply approved code fix",
        action_target="workspace/demo_error.py",
        target_hash="hash-overwrite",
        proposal_hash="proposal-overwrite",
        risk_level="MEDIUM_RISK",
        approval_binding={"password": "super-secret-password", "approval_id": "approval-x"},
        approval_status="APPROVED",
        approval_expiry="2099-01-01T00:00:00+00:00",
        redacted_action_metadata={"api_key": "super-secret-key"},
        db_path=db_path,
    )
    assert contains_sensitive_data(checkpoint["approval_binding"]) is False
    assert contains_sensitive_data(checkpoint["redacted_action_metadata"]) is False
