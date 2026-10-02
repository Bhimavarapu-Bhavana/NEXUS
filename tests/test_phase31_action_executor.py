from app.agent.action_executor import execute_authorized_action, proposal_hash
from app.agent.approval_authority import create_approval, decide_approval
from app.agent.execution_journal import create_checkpoint
from app.tools.fixer import fix_python_logic


def _state(tmp_path, approved=True):
    target = tmp_path / "sample.py"
    target.write_text('print("before")\n', encoding="utf-8")
    task_id = "task-executor-31"
    checkpoint_id = "cp-executor-31"
    digest = proposal_hash(action_type="apply approved code fix", tool_name="fixer", target="sample.py", old_code='print("before")', new_code='print("after")')
    checkpoint = create_checkpoint(task_id, current_stage="APPROVAL_PENDING", action_type="apply approved code fix", action_target="sample.py", proposal_hash=digest, risk_level="MEDIUM_RISK", approval_status="PENDING", db_path=tmp_path / "journal.db")
    approval = create_approval(task_id=task_id, checkpoint_id=checkpoint["checkpoint_id"], proposal_hash=digest, action_type="apply approved code fix", tool_name="fixer", target="sample.py", risk_level="MEDIUM_RISK", db_path=tmp_path / "approvals.db")
    if approved:
        decide_approval(approval["approval_id"], "APPROVED", db_path=tmp_path / "approvals.db")
    return target, {
        "task_id": task_id,
        "journal_checkpoint_id": checkpoint["checkpoint_id"],
        "approval_id": approval["approval_id"],
        "proposal_hash": digest,
        "action_type": "apply approved code fix",
        "action_tool": "fixer",
        "action_target": "sample.py",
        "target_file": "sample.py",
        "old_code": 'print("before")',
        "new_code": 'print("after")',
        "journal_db_path": str(tmp_path / "journal.db"),
    }


def test_authoritative_executor_requires_and_consumes_approval(tmp_path):
    target, state = _state(tmp_path)
    result = execute_authorized_action(state, workspace_root=str(tmp_path), db_path=tmp_path / "approvals.db")
    assert result["status"] == "COMPLETED"
    assert result["verification"] == "SUCCESS"
    assert target.read_text(encoding="utf-8") == 'print("after")\n'


def test_rejected_or_missing_approval_does_not_mutate(tmp_path):
    target, state = _state(tmp_path, approved=False)
    result = execute_authorized_action(state, workspace_root=str(tmp_path), db_path=tmp_path / "approvals.db")
    assert result["status"] == "BLOCKED"
    assert target.read_text(encoding="utf-8") == 'print("before")\n'


def test_direct_fixer_bypass_is_blocked(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text('print("before")\n', encoding="utf-8")
    result = fix_python_logic(str(tmp_path), "sample.py", 'print("before")', 'print("after")')
    assert "blocked" in result.lower()
    assert target.read_text(encoding="utf-8") == 'print("before")\n'
