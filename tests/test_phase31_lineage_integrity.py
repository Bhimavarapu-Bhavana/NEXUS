from app.agent.execution_journal import create_checkpoint, load_checkpoint
from app.agent.recovery_manager import evaluate_recovery
from app.memory.task_ledger import create_task, update_task_status


def test_environment_drift_blocks_recovery(tmp_path):
    db_path = tmp_path / "recovery.db"
    task = create_task("Recover a bound action.", db_path=db_path)
    checkpoint = create_checkpoint(task["task_id"], current_stage="ACTION", action_type="apply approved code fix", action_target="sample.py", target_hash="", proposal_hash="proposal", risk_level="MEDIUM_RISK", approval_binding={"task_id": task["task_id"], "action_type": "apply approved code fix", "target": "sample.py", "proposal_hash": "proposal", "risk_level": "MEDIUM_RISK", "status": "APPROVED", "expires_at": "2999-01-01T00:00:00+00:00"}, approval_status="APPROVED", approval_expiry="2999-01-01T00:00:00+00:00", environment_fingerprint="environment-a", db_path=db_path)
    update_task_status(task["task_id"], "PAUSED", current_stage="ACTION", resume_reason="resume", db_path=db_path)
    result = evaluate_recovery(task["task_id"], current_state={"selected_tools": ["fixer"], "resume_reason": "resume", "environment_fingerprint": "environment-b"}, workspace_root=str(tmp_path), db_path=db_path)
    assert result["decision"] == "HALT_AND_BLOCK"
    assert "environment" in result["reason"].lower()
    assert load_checkpoint(task["task_id"], checkpoint_id=checkpoint["checkpoint_id"], db_path=db_path)["is_valid"] == 1
