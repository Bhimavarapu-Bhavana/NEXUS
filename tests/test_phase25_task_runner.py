from __future__ import annotations

from app.agent.execution_journal import create_checkpoint
from app.memory.task_ledger import create_task, get_task, update_task_status
from app.agent.task_runner import TaskRunner


def test_phase25_start_task_and_status(tmp_path):
    runner = TaskRunner(
        workspace_root=str(tmp_path),
        db_path=tmp_path / "phase25_runner.db",
        graph_runner=lambda state: {**state, "final_outcome": "SUCCESS", "task_status": "COMPLETED"},
    )

    result = runner.start_task("Fix the demo workspace issue.")
    assert result["task_id"]
    assert result["status"] in {"RUNNING", "WAITING_APPROVAL", "PAUSED", "BLOCKED", "COMPLETED"}

    status = runner.inspect_task_status(result["task_id"])
    assert status["task_id"] == result["task_id"]


def test_phase25_recover_interrupted_task_rejects_stale_approval(tmp_path):
    db_path = tmp_path / "phase25_recovery.db"
    task = create_task("Recover after approval expiry.", db_path=db_path)
    create_checkpoint(
        task["task_id"],
        current_stage="WAITING_APPROVAL",
        action_type="apply approved code fix",
        action_target="workspace/demo_error.py",
        target_hash="hash-expired",
        proposal_hash="proposal-expired",
        risk_level="MEDIUM_RISK",
        approval_binding={
            "task_id": task["task_id"],
            "target": "workspace/demo_error.py",
            "proposal_hash": "proposal-expired",
            "approval_id": "approval-expired",
            "expires_at": "2020-01-01T00:00:00+00:00",
        },
        approval_status="APPROVED",
        approval_expiry="2020-01-01T00:00:00+00:00",
        db_path=db_path,
    )
    update_task_status(task["task_id"], "PAUSED", current_stage="WAITING_APPROVAL", status_reason="Waiting on approval.", db_path=db_path)

    runner = TaskRunner(workspace_root="workspace", db_path=db_path)
    recovered = runner.recover_interrupted_task(task["task_id"], current_state={"user_request": "Recover after approval expiry."})

    assert recovered["status"] in {"PAUSED", "BLOCKED"}
    assert "approval" in (recovered.get("status_reason") or "").lower() or "recover" in (recovered.get("status_reason") or "").lower()


def test_phase25_graceful_shutdown_persists_recoverable_state(tmp_path):
    db_path = tmp_path / "phase25_shutdown.db"
    task = create_task("Persist state before shutdown.", db_path=db_path)
    update_task_status(task["task_id"], "RUNNING", current_stage="ACTION", status_reason="Action in flight.", db_path=db_path)

    runner = TaskRunner(workspace_root=str(tmp_path), db_path=db_path)
    shutdown_state = runner.graceful_shutdown(task["task_id"], "Process exit while a task was active.")

    assert shutdown_state["status"] == "PAUSED"
    assert "shutdown" in (shutdown_state.get("resume_reason") or "").lower()
    assert get_task(task["task_id"], db_path=db_path)["resume_reason"]


def test_phase25_duplicate_start_and_own_task_id(tmp_path):
    db_path = tmp_path / "phase25_duplicate.db"
    runner = TaskRunner(workspace_root=str(tmp_path), db_path=db_path)

    first = runner.start_task("Only one runner should own this task.", task_id="task-duplicate-test", graph_runner=lambda state: {**state, "final_outcome": "SUCCESS", "task_status": "COMPLETED"})
    second = runner.start_task("Same task id should not create a second task.", task_id="task-duplicate-test", graph_runner=lambda state: {**state, "final_outcome": "SUCCESS", "task_status": "COMPLETED"})

    assert first["task_id"] == second["task_id"]
    assert first["task_id"] == "task-duplicate-test"
