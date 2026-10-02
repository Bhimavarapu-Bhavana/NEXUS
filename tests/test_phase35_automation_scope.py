"""Phase 35 automation-scope tests: store behavior plus StateGraph interaction.

Scope enforcement activates when ``scope_db_path`` is explicitly bound in the
state; unwired states keep legacy behavior so existing flows continue working.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app.agent.action_executor import execute_authorized_action, proposal_hash
from app.agent.approval_authority import create_approval, decide_approval, get_approval
from app.agent.execution_journal import create_checkpoint
from app.agent.graph import (
    _apply_user_preferences,
    _evaluate_action_permission,
    _evaluate_automation_scope,
    _evaluate_privacy,
    create_proposal,
    nexus_graph,
)
from app.memory.task_ledger import create_task
from app.security.audit_logger import get_recent_audit_events
from app.security.automation_scope import (
    check_scope,
    get_scope,
    grant_scope,
    list_scopes,
    revoke_scope,
    scope_area_for_tool,
)
from app.security.permission_authority import create_permission, revoke_permission
from app.security.privacy_policy import evaluate_privacy
from app.security.user_dna import check_authorization, create_dna_record

TASK_ID = "task-scope-35"


def _dbs(tmp_path):
    return {
        "persistence": tmp_path / "tasks.db",
        "journal": tmp_path / "journal.db",
        "approvals": tmp_path / "approvals.db",
        "permissions": tmp_path / "permissions.db",
        "scopes": tmp_path / "scopes.db",
        "dna": tmp_path / "dna.db",
        "audit": tmp_path / "audit.db",
    }


def _grant_scope(dbs, **overrides):
    values = {
        "area": "workspace",
        "decision": "ALLOW",
        "task_id": TASK_ID,
        "db_path": dbs["scopes"],
        "audit_db_path": dbs["audit"],
    }
    values.update(overrides)
    return grant_scope(**values)


def _grant_permission(dbs, **overrides):
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


def _proposal_state(tmp_path, dbs, *, task_id=TASK_ID, target="demo.py"):
    from app.memory.task_ledger import get_task

    if get_task(task_id, db_path=dbs["persistence"]) is None:
        create_task("Fix demo.", task_id=task_id, db_path=dbs["persistence"])
    (tmp_path / "workspace").mkdir(exist_ok=True)
    return {
        "user_request": 'Fix demo.py to print "hello".',
        "investigation": ["DIAGNOSIS:\nFIX_ALLOWED: YES\nThe greeting is wrong."],
        "selected_files": [target],
        "observation_results": [
            {"tool": "logic_inspector", "status": "ok", "result": f"--- FILE: {target} ---\nprint(\"before\")\n"}
        ],
        "selected_tools": ["logic_inspector"],
        "task_id": task_id,
        "task_status": "RUNNING",
        "persistence_db_path": str(dbs["persistence"]),
        "journal_db_path": str(dbs["journal"]),
        "approval_db_path": str(dbs["approvals"]),
        "permission_db_path": str(dbs["permissions"]),
        "scope_db_path": str(dbs["scopes"]),
        "dna_db_path": str(dbs["dna"]),
        "decision_stage": "REASON",
        "decision_reason": "",
        "final_outcome": "",
        "risk_decision": {},
        "audit_error": "",
        "approval_required": False,
        "approved": False,
    }


def _executor_state(tmp_path, dbs, *, task_id=TASK_ID, target="sample.py"):
    before, after = 'print("before")\n', 'print("after")\n'
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
        "scope_db_path": str(dbs["scopes"]),
        "dna_db_path": str(dbs["dna"]),
    }


# --- store behavior ---------------------------------------------------------


def test_scope_area_mapping_comes_from_registry():
    assert scope_area_for_tool("fixer") == "workspace"
    assert scope_area_for_tool("browser_follow_observed_link") == "browser"
    assert scope_area_for_tool("desktop_focus_authorized_window") == "desktop"
    assert scope_area_for_tool("email_send_action") == "email"
    assert scope_area_for_tool("calendar_event_action") == "calendar"
    assert scope_area_for_tool("comms_send_action") == "comms"
    assert scope_area_for_tool("security_scan") == "security"
    assert scope_area_for_tool("git_inspector") == "git"
    with pytest.raises(ValueError):
        scope_area_for_tool("shell_exec_not_a_tool")
    with pytest.raises(ValueError):
        check_scope(area="shell", target="x", db_path=":memory:")


def test_scope_allow_and_deny(tmp_path):
    dbs = _dbs(tmp_path)
    _grant_scope(dbs)
    allowed = check_scope(area="workspace", target="demo.py", task_id=TASK_ID, db_path=dbs["scopes"], audit_db_path=dbs["audit"])
    assert allowed["outcome"] == "ALLOWED"
    assert allowed["allowed"] is True

    _grant_scope(dbs, area="browser", decision="DENY")
    denied = check_scope(area="browser", target="https://example.com", task_id=TASK_ID, db_path=dbs["scopes"], audit_db_path=dbs["audit"])
    assert denied["outcome"] == "DENIED"
    assert denied["allowed"] is False


def test_scope_denied_by_default_without_grant(tmp_path):
    dbs = _dbs(tmp_path)
    decision = check_scope(area="email", target="msg-1", task_id=TASK_ID, db_path=dbs["scopes"], audit_db_path=dbs["audit"])
    assert decision["outcome"] == "DENIED"
    assert decision["allowed"] is False


def test_scope_expiration(tmp_path):
    dbs = _dbs(tmp_path)
    past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    record = _grant_scope(dbs, expires_at=past)
    assert get_scope(record["scope_id"], db_path=dbs["scopes"])["status"] == "EXPIRED"
    decision = check_scope(area="workspace", target="demo.py", task_id=TASK_ID, db_path=dbs["scopes"], audit_db_path=dbs["audit"])
    assert decision["outcome"] == "EXPIRED"
    assert decision["allowed"] is False
    with pytest.raises(ValueError):
        _grant_scope(dbs, expires_at="not-a-timestamp")


def test_scope_revocation(tmp_path):
    dbs = _dbs(tmp_path)
    record = _grant_scope(dbs)
    with pytest.raises(ValueError):
        revoke_scope(record["scope_id"], "   ", db_path=dbs["scopes"], audit_db_path=dbs["audit"])
    revoked = revoke_scope(record["scope_id"], "user withdrew scope", db_path=dbs["scopes"], audit_db_path=dbs["audit"])
    assert revoked["status"] == "REVOKED"
    decision = check_scope(area="workspace", target="demo.py", task_id=TASK_ID, db_path=dbs["scopes"], audit_db_path=dbs["audit"])
    assert decision["outcome"] == "REVOKED"
    assert decision["allowed"] is False
    assert revoke_scope("scope-missing", "reason", db_path=dbs["scopes"], audit_db_path=dbs["audit"]) is None


def test_scope_task_isolation_and_explicit_global(tmp_path):
    dbs = _dbs(tmp_path)
    _grant_scope(dbs, task_id="task-a")
    other = check_scope(area="workspace", target="demo.py", task_id="task-b", db_path=dbs["scopes"], audit_db_path=dbs["audit"])
    assert other["allowed"] is False

    _grant_scope(dbs, task_id="")
    strict = check_scope(area="workspace", target="demo.py", task_id="task-b", db_path=dbs["scopes"], audit_db_path=dbs["audit"])
    assert strict["allowed"] is False
    opted_in = check_scope(area="workspace", target="demo.py", task_id="task-b", db_path=dbs["scopes"], audit_db_path=dbs["audit"], allow_global=True)
    assert opted_in["outcome"] == "ALLOWED"


def test_scope_target_boundary(tmp_path):
    dbs = _dbs(tmp_path)
    _grant_scope(dbs, target_pattern="docs/*.txt")
    assert check_scope(area="workspace", target="docs/a.txt", task_id=TASK_ID, db_path=dbs["scopes"])["allowed"] is True
    assert check_scope(area="workspace", target="other.txt", task_id=TASK_ID, db_path=dbs["scopes"], audit_db_path=dbs["audit"])["allowed"] is False


def test_scope_audit_lands_in_audit_db_only(tmp_path):
    dbs = _dbs(tmp_path)
    record = _grant_scope(dbs)
    revoke_scope(record["scope_id"], "cleanup", db_path=dbs["scopes"], audit_db_path=dbs["audit"])
    connection = sqlite3.connect(str(dbs["scopes"]))
    try:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    finally:
        connection.close()
    assert "audit_events" not in tables
    event_types = {event["event_type"] for event in get_recent_audit_events(limit=50, db_path=dbs["audit"])}
    assert {"scope_granted", "scope_revoked"} <= event_types


# --- StateGraph interaction -------------------------------------------------


def test_graph_scope_gate_blocks_and_is_advisory_unbound(tmp_path):
    dbs = _dbs(tmp_path)
    bound = {"task_id": TASK_ID, "scope_db_path": str(dbs["scopes"]), "risk_decision": {}}
    assert _evaluate_automation_scope(bound, tool_name="fixer", target="demo.py") is False
    assert bound["final_outcome"] == "BLOCKED"
    assert bound["scope_decision"]["outcome"] == "DENIED"

    unbound = {"task_id": TASK_ID, "risk_decision": {}}
    assert _evaluate_automation_scope(unbound, tool_name="fixer", target="demo.py") is True
    assert unbound.get("final_outcome", "") != "BLOCKED"


def test_graph_scope_allows_with_grant(tmp_path):
    dbs = _dbs(tmp_path)
    record = _grant_scope(dbs)
    state = {"task_id": TASK_ID, "scope_db_path": str(dbs["scopes"]), "risk_decision": {}}
    assert _evaluate_automation_scope(state, tool_name="fixer", target="demo.py") is True
    assert state["scope_decision"]["outcome"] == "ALLOWED"
    assert list_scopes(area="workspace", db_path=dbs["scopes"])[0]["scope_id"] == record["scope_id"]


def test_executor_rechecks_scope_fresh_and_blocks_revoked(tmp_path):
    dbs = _dbs(tmp_path)
    _grant_permission(dbs)
    record = _grant_scope(dbs)
    state = _executor_state(tmp_path, dbs)
    revoke_scope(record["scope_id"], "revoked after approval", db_path=dbs["scopes"], audit_db_path=dbs["audit"])
    result = execute_authorized_action(state, workspace_root=str(tmp_path), db_path=dbs["approvals"])
    assert result["status"] == "BLOCKED"
    assert result["scope_decision"]["outcome"] == "REVOKED"
    assert (tmp_path / "sample.py").read_text(encoding="utf-8") == 'print("before")\n'
    assert get_approval(state["approval_id"], db_path=dbs["approvals"])["status"] == "APPROVED"


def test_restart_with_revoked_scope_remains_blocked(tmp_path):
    dbs = _dbs(tmp_path)
    _grant_permission(dbs)
    record = _grant_scope(dbs)
    state = _executor_state(tmp_path, dbs)
    revoke_scope(record["scope_id"], "revoked before restart", db_path=dbs["scopes"], audit_db_path=dbs["audit"])
    restarted = {key: state[key] for key in (
        "task_id", "journal_checkpoint_id", "approval_id", "proposal_hash",
        "action_type", "action_tool", "action_target", "target_file",
        "old_code", "new_code", "journal_db_path", "permission_db_path",
        "scope_db_path", "dna_db_path",
    )}
    result = execute_authorized_action(restarted, workspace_root=str(tmp_path), db_path=dbs["approvals"])
    assert result["status"] == "BLOCKED"
    assert result["scope_decision"]["outcome"] == "REVOKED"


def test_recovery_cannot_broaden_scope(tmp_path):
    dbs = _dbs(tmp_path)
    _grant_permission(dbs, target_scope="global")
    _grant_scope(dbs, target_pattern="docs/*.txt")
    state = _executor_state(tmp_path, dbs, target="other.txt")
    first = execute_authorized_action(state, workspace_root=str(tmp_path), db_path=dbs["approvals"])
    assert first["status"] == "BLOCKED"
    second = execute_authorized_action(state, workspace_root=str(tmp_path), db_path=dbs["approvals"])
    assert second["status"] == "BLOCKED"
    assert second["scope_decision"]["outcome"] == "DENIED"


def test_permission_and_scope_both_required(tmp_path):
    dbs = _dbs(tmp_path)
    _grant_permission(dbs)
    # Permission granted but no scope grant: proposal stops at the scope gate.
    state = _proposal_state(tmp_path, dbs)
    result = create_proposal(state)
    assert result["final_outcome"] == "BLOCKED"
    assert result["permission_decision"]["outcome"] == "APPROVAL_REQUIRED"
    assert result["scope_decision"]["allowed"] is False

    # With both granted, the consequential action reaches approval as before.
    _grant_scope(dbs)
    state = _proposal_state(tmp_path, dbs)
    result = create_proposal(state)
    assert result["approval_required"] is True
    assert result["approval_id"]
    assert result["scope_decision"]["outcome"] == "ALLOWED"


def test_consequential_action_still_requires_approval(tmp_path):
    dbs = _dbs(tmp_path)
    _grant_permission(dbs)
    _grant_scope(dbs)
    state = _proposal_state(tmp_path, dbs)
    result = create_proposal(state)
    assert result["approval_required"] is True
    assert result["approved"] is False
    assert result["final_outcome"] != "SUCCESS"


def test_scanner_threat_grants_no_remediation_authority(tmp_path):
    dbs = _dbs(tmp_path)
    # A permission sized for the read-only scanner cannot satisfy the fixer.
    grant_scope(area="security", decision="ALLOW", task_id=TASK_ID, db_path=dbs["scopes"], audit_db_path=dbs["audit"])
    create_permission(
        capability="OBSERVE",
        action_class="READ",
        target_scope="global",
        task_id=TASK_ID,
        db_path=dbs["permissions"],
        audit_db_path=dbs["audit"],
    )
    grant_scope(area="workspace", decision="ALLOW", task_id=TASK_ID, db_path=dbs["scopes"], audit_db_path=dbs["audit"])
    state = {
        "task_id": TASK_ID,
        "permission_db_path": str(dbs["permissions"]),
        "risk_decision": {"risk_level": "MEDIUM_RISK"},
    }
    assert _evaluate_action_permission(state, tool_name="fixer", target="demo.py") is False
    assert state["permission_decision"]["outcome"] == "UNKNOWN_CAPABILITY"


def test_privacy_denies_secret_target_despite_permission(tmp_path):
    dbs = _dbs(tmp_path)
    _grant_permission(dbs, target_scope="global")
    _grant_scope(dbs)
    state = {"task_id": TASK_ID, "permission_db_path": str(dbs["permissions"]), "dna_db_path": str(dbs["dna"]), "risk_decision": {}}
    assert _evaluate_action_permission(state, tool_name="fixer", target="passwords.txt") is True
    assert _evaluate_privacy(state, tool_name="fixer", target="passwords.txt") is False
    assert state["privacy_decision"]["decision"] == "DENY"
    assert state["final_outcome"] == "BLOCKED"


def test_sensitive_data_needs_explicit_authorization(tmp_path):
    dbs = _dbs(tmp_path)
    _grant_permission(dbs, target_scope="global")
    _grant_scope(dbs)
    state = {"task_id": TASK_ID, "permission_db_path": str(dbs["permissions"]), "dna_db_path": str(dbs["dna"]), "risk_decision": {}}
    assert _evaluate_privacy(state, tool_name="fixer", target="financial_record.txt") is False
    assert state["privacy_decision"]["decision"] == "REQUIRES_AUTHORIZATION"

    create_dna_record(
        kind="AUTHORIZATION",
        key="data:SENSITIVE",
        value="granted for review",
        provenance_source="user-stated",
        db_path=dbs["dna"],
        audit_db_path=dbs["audit"],
    )
    assert check_authorization("data:SENSITIVE", db_path=dbs["dna"]) is True
    state = {"task_id": TASK_ID, "permission_db_path": str(dbs["permissions"]), "dna_db_path": str(dbs["dna"]), "risk_decision": {}}
    assert _evaluate_privacy(state, tool_name="fixer", target="financial_record.txt") is True
    assert state["privacy_decision"]["decision"] == "ALLOW"


def test_dna_preference_affects_selection_context_not_authorization(tmp_path):
    dbs = _dbs(tmp_path)
    create_dna_record(
        kind="PREFERENCE",
        key="detail_level",
        value="verbose",
        provenance_source="user-stated",
        db_path=dbs["dna"],
        audit_db_path=dbs["audit"],
    )
    state = {"task_id": TASK_ID, "user_request": "Inspect demo.", "dna_db_path": str(dbs["dna"])}
    _apply_user_preferences(state)
    assert state["dna_preferences"] == [{"key": "detail_level", "value": "verbose", "confidence": "STATED"}]
    # The preference changes nothing about authorization.
    assert check_authorization("detail_level", db_path=dbs["dna"]) is False
    gated = {"task_id": TASK_ID, "permission_db_path": str(dbs["permissions"]), "dna_db_path": str(dbs["dna"]), "risk_decision": {}}
    assert _evaluate_action_permission(gated, tool_name="fixer", target="demo.py") is False


def test_read_only_flows_ignore_unbound_stores(tmp_path):
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


def test_permission_and_privacy_lineage_on_proposal(tmp_path):
    dbs = _dbs(tmp_path)
    _grant_permission(dbs)
    _grant_scope(dbs)
    result = create_proposal(_proposal_state(tmp_path, dbs))
    assert result["approval_required"] is True
    assert result["privacy_decision"]["decision"] == "ALLOW"
    assert result["scope_decision"]["outcome"] == "ALLOWED"
    assert result["permission_decision"]["outcome"] == "APPROVAL_REQUIRED"
    assert evaluate_privacy("INTERNAL", operation="OBSERVE")["decision"] == "ALLOW"
