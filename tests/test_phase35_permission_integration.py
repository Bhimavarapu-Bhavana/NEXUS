"""Phase 35 permission integration: Risk → Permission → Approval → Executor.

Enforcement activates when ``permission_db_path`` is explicitly bound in the
state; unwired states keep the legacy risk + approval behavior so existing
read-only and pre-permission flows continue working.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.agent.action_executor import execute_authorized_action, proposal_hash
from app.agent.approval_authority import create_approval, decide_approval, get_approval
from app.agent.execution_journal import create_checkpoint
from app.agent.graph import (
    _evaluate_action_permission,
    create_proposal,
    nexus_graph,
)
from app.memory.task_ledger import create_task
from app.security.audit_logger import get_recent_audit_events
from app.security.permission_authority import create_permission, revoke_permission
from app.tools.tool_registry import resolve_tool_permission


TASK_ID = "task-perm-35"


def _dbs(tmp_path):
    return {
        "persistence": tmp_path / "tasks.db",
        "journal": tmp_path / "journal.db",
        "approvals": tmp_path / "approvals.db",
        "permissions": tmp_path / "permissions.db",
        "audit": tmp_path / "audit.db",
    }


def _grant(tmp_path, dbs, **overrides):
    values = {
        "capability": "ACT",
        "action_class": "EXECUTE",
        "target_scope": "workspace-only",
        "task_id": TASK_ID,
        "db_path": dbs["permissions"],
        "audit_db_path": dbs["audit"],
    }
    values.update(overrides)
    return create_permission(**values)


def _fixer_proposal_state(tmp_path, dbs, *, task_id=TASK_ID):
    create_task(
        'Fix demo.py to print "hello".',
        task_id=task_id,
        db_path=dbs["persistence"],
    )
    (tmp_path / "workspace").mkdir(exist_ok=True)
    return {
        "user_request": 'Fix demo.py to print "hello".',
        "investigation": ["DIAGNOSIS:\nFIX_ALLOWED: YES\nThe greeting is wrong."],
        "selected_files": ["demo.py"],
        "observation_results": [
            {"tool": "logic_inspector", "status": "ok", "result": "--- FILE: demo.py ---\nprint(\"before\")\n"}
        ],
        "selected_tools": ["logic_inspector"],
        "task_id": task_id,
        "task_status": "RUNNING",
        "persistence_db_path": str(dbs["persistence"]),
        "journal_db_path": str(dbs["journal"]),
        "approval_db_path": str(dbs["approvals"]),
        "permission_db_path": str(dbs["permissions"]),
        "decision_stage": "REASON",
        "decision_reason": "",
        "final_outcome": "",
        "risk_decision": {},
        "audit_error": "",
        "approval_required": False,
        "approved": False,
    }


def _executor_state(tmp_path, dbs, *, task_id=TASK_ID, target="sample.py", before='print("before")\n', after='print("after")\n'):
    (tmp_path / target).write_text(before, encoding="utf-8")
    digest = proposal_hash(
        action_type="apply approved code fix",
        tool_name="fixer",
        target=target,
        old_code=before.strip(),
        new_code=after.strip(),
    )
    checkpoint = create_checkpoint(
        task_id,
        current_stage="APPROVAL_PENDING",
        action_type="apply approved code fix",
        action_target=target,
        proposal_hash=digest,
        risk_level="MEDIUM_RISK",
        approval_status="PENDING",
        db_path=dbs["journal"],
    )
    approval = create_approval(
        task_id=task_id,
        checkpoint_id=checkpoint["checkpoint_id"],
        proposal_hash=digest,
        action_type="apply approved code fix",
        tool_name="fixer",
        target=target,
        risk_level="MEDIUM_RISK",
        db_path=dbs["approvals"],
    )
    decide_approval(approval["approval_id"], "APPROVED", db_path=dbs["approvals"])
    return {
        "task_id": task_id,
        "journal_checkpoint_id": checkpoint["checkpoint_id"],
        "approval_id": approval["approval_id"],
        "proposal_hash": digest,
        "action_type": "apply approved code fix",
        "action_tool": "fixer",
        "action_target": target,
        "target_file": target,
        "old_code": before.strip(),
        "new_code": after.strip(),
        "journal_db_path": str(dbs["journal"]),
        "permission_db_path": str(dbs["permissions"]),
    }


def test_mapping_comes_from_registry_metadata():
    fixer = resolve_tool_permission("fixer")
    assert fixer["capability"] == "ACT"
    assert fixer["action_class"] == "EXECUTE"
    observer = resolve_tool_permission("logic_inspector")
    assert observer["action_class"] == "READ"
    email = resolve_tool_permission("email_send_action")
    assert email["capability"] == "EMAIL_SEND"
    assert email["action_class"] == "EXECUTE"
    calendar = resolve_tool_permission("calendar_event_action")
    assert calendar["capability"] == "CALENDAR_MUTATE"
    with pytest.raises(ValueError):
        resolve_tool_permission("shell_exec_not_a_tool")


def test_permitted_read_only_task_still_works():
    result = nexus_graph.invoke(
        {
            "user_request": "Read shop_project.py and explain what this program does. Do not modify anything.",
            "observations": [],
            "investigation": [],
            "selected_tools": [],
            "approval_required": False,
            "approved": False,
            "retry_count": 0,
            "monitoring_active": False,
            "decision_stage": "REQUEST",
            "task_id": "",
        }
    )
    assert isinstance(result, dict)
    assert result["final_outcome"] in {"READ_ONLY", "NO_ACTION", "NO_FIX", "SUCCESS"}
    assert result["final_outcome"] != "BLOCKED"


def test_unknown_capability_blocked_when_store_bound(tmp_path):
    dbs = _dbs(tmp_path)
    state = {"task_id": TASK_ID, "permission_db_path": str(dbs["permissions"]), "risk_decision": {}}
    assert _evaluate_action_permission(state, tool_name="fixer", target="demo.py") is False
    assert state["final_outcome"] == "BLOCKED"
    assert state["permission_decision"]["outcome"] == "UNKNOWN_CAPABILITY"


def test_out_of_scope_target_blocked(tmp_path):
    dbs = _dbs(tmp_path)
    _grant(tmp_path, dbs, target_pattern="docs/*.txt")
    state = {"task_id": TASK_ID, "permission_db_path": str(dbs["permissions"]), "risk_decision": {}}
    assert _evaluate_action_permission(state, tool_name="fixer", target="other.txt") is False
    assert state["permission_decision"]["outcome"] == "OUT_OF_SCOPE"


def test_gate_is_advisory_without_explicit_store(tmp_path):
    state = {"task_id": TASK_ID, "risk_decision": {}}
    assert _evaluate_action_permission(state, tool_name="fixer", target="demo.py") is True
    assert state["permission_decision"]["outcome"] == "UNKNOWN_CAPABILITY"
    assert state.get("final_outcome", "") != "BLOCKED"


def test_revoked_permission_blocks_execution(tmp_path):
    dbs = _dbs(tmp_path)
    record = _grant(tmp_path, dbs)
    state = _executor_state(tmp_path, dbs)
    revoke_permission(record["permission_id"], "withdrawn", db_path=dbs["permissions"], audit_db_path=dbs["audit"])
    result = execute_authorized_action(state, workspace_root=str(tmp_path), db_path=dbs["approvals"])
    assert result["status"] == "BLOCKED"
    assert result["permission_decision"]["outcome"] == "REVOKED"
    assert (tmp_path / "sample.py").read_text(encoding="utf-8") == 'print("before")\n'


def test_expired_permission_blocks_execution(tmp_path):
    dbs = _dbs(tmp_path)
    past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    _grant(tmp_path, dbs, expires_at=past)
    state = _executor_state(tmp_path, dbs)
    result = execute_authorized_action(state, workspace_root=str(tmp_path), db_path=dbs["approvals"])
    assert result["status"] == "BLOCKED"
    assert result["permission_decision"]["outcome"] == "EXPIRED"


def test_permission_exists_consequential_action_requires_approval(tmp_path):
    dbs = _dbs(tmp_path)
    record = _grant(tmp_path, dbs)
    state = _fixer_proposal_state(tmp_path, dbs)
    result = create_proposal(state)
    assert result["approval_required"] is True
    assert result["approval_id"]
    assert result["permission_decision"]["outcome"] == "APPROVAL_REQUIRED"
    assert result["permission_id"] == record["permission_id"]


def test_missing_permission_blocks_proposal(tmp_path):
    dbs = _dbs(tmp_path)
    state = _fixer_proposal_state(tmp_path, dbs)
    result = create_proposal(state)
    assert result["final_outcome"] == "BLOCKED"
    assert result["approved"] is False
    assert result["approval_required"] is False


def test_risk_blocked_overrides_permission(tmp_path):
    dbs = _dbs(tmp_path)
    _grant(tmp_path, dbs, target_scope="global")
    state = {
        "task_id": TASK_ID,
        "permission_db_path": str(dbs["permissions"]),
        "risk_decision": {"risk_level": "BLOCKED", "reason": "Prohibited operation."},
    }
    assert _evaluate_action_permission(state, tool_name="fixer", target="demo.py") is False
    assert state["permission_decision"]["outcome"] == "SECURITY_BLOCKED"


def test_approved_then_revoked_blocks_restart_and_preserves_claim(tmp_path):
    dbs = _dbs(tmp_path)
    record = _grant(tmp_path, dbs)
    state = _executor_state(tmp_path, dbs)
    approval_id = state["approval_id"]
    revoke_permission(record["permission_id"], "revoked before restart", db_path=dbs["permissions"], audit_db_path=dbs["audit"])
    # Simulate a restart: only durable bindings survive, re-read fresh.
    restarted = {key: state[key] for key in (
        "task_id", "journal_checkpoint_id", "approval_id", "proposal_hash",
        "action_type", "action_tool", "action_target", "target_file",
        "old_code", "new_code", "journal_db_path", "permission_db_path",
    )}
    result = execute_authorized_action(restarted, workspace_root=str(tmp_path), db_path=dbs["approvals"])
    assert result["status"] == "BLOCKED"
    assert result["permission_decision"]["outcome"] == "REVOKED"
    assert get_approval(approval_id, db_path=dbs["approvals"])["status"] == "APPROVED"


def test_recovery_cannot_broaden_permission(tmp_path):
    dbs = _dbs(tmp_path)
    _grant(tmp_path, dbs, target_pattern="docs/*.txt")
    state = _executor_state(tmp_path, dbs, target="other.txt")
    first = execute_authorized_action(state, workspace_root=str(tmp_path), db_path=dbs["approvals"])
    assert first["status"] == "BLOCKED"
    # Retry with the identical bindings still stops at the fresh check.
    second = execute_authorized_action(state, workspace_root=str(tmp_path), db_path=dbs["approvals"])
    assert second["status"] == "BLOCKED"
    assert second["permission_decision"]["outcome"] == "OUT_OF_SCOPE"


def test_permission_lineage_survives_execution(tmp_path):
    dbs = _dbs(tmp_path)
    record = _grant(tmp_path, dbs)
    proposed = create_proposal(_fixer_proposal_state(tmp_path, dbs))
    assert proposed["permission_id"] == record["permission_id"]
    decide_approval(proposed["approval_id"], "APPROVED", db_path=dbs["approvals"])
    target = tmp_path / "demo.py"
    target.write_text("print(\"before\")\n", encoding="utf-8")
    executing = dict(proposed)
    executing["journal_db_path"] = str(dbs["journal"])
    result = execute_authorized_action(executing, workspace_root=str(tmp_path), db_path=dbs["approvals"])
    assert result["status"] == "COMPLETED"
    assert result["permission_id"] == record["permission_id"]
    assert executing["permission_id"] == record["permission_id"]
    assert get_approval(proposed["approval_id"], db_path=dbs["approvals"])["status"] == "CONSUMED"


def test_no_secrets_in_permission_and_audit_records(tmp_path):
    dbs = _dbs(tmp_path)
    secret = "hunter2-secret-value-99"
    _grant(tmp_path, dbs, metadata={"note": f"password={secret}"})
    state = {"task_id": TASK_ID, "permission_db_path": str(dbs["permissions"]), "risk_decision": {}}
    assert _evaluate_action_permission(state, tool_name="fixer", target="demo.py") is True
    assert secret not in str(state["permission_decision"])
    events = get_recent_audit_events(limit=100, db_path=dbs["audit"])
    assert events
    assert secret not in str(events)
