from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from app.agent.approval_authority import create_approval, get_approval
from app.agent.autonomous_service import AutonomousService
from app.agent.execution_journal import create_checkpoint
from app.agent.graph import nexus_graph
from app.agent.task_runner import TERMINAL_TASKS, TaskRunner
from app.control_plane import ControlPlane, create_control_app, run_server
from app.memory.task_ledger import create_task, get_task, update_task_status


def _workspace_and_db(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return workspace, tmp_path / "cp.db"


def _stub_read_only(state):
    return {**state, "task_status": "COMPLETED", "final_outcome": "READ_ONLY"}


def _stub_waiting_approval(state):
    return {
        **state,
        "task_status": "RUNNING",
        "approval_required": True,
        "approved": False,
        "decision_stage": "WAITING_APPROVAL",
        "decision_reason": "Approval is required before execution.",
        "final_outcome": "",
    }


def _make_cp(tmp_path, **kwargs):
    workspace, db = _workspace_and_db(tmp_path)
    runner = TaskRunner(workspace_root=str(workspace), db_path=db, graph_runner=_stub_read_only)
    kwargs.setdefault("task_runner", runner)
    start = kwargs.pop("start", True)
    cp = ControlPlane(workspace_root=str(workspace), db_path=db, **kwargs)
    if start:
        cp.lifecycle("START")
    return cp


def _pending_approval(db, *, task_id="task-45", checkpoint_id="cp-45", target="fixture-job-0001", expires_at=None):
    return create_approval(
        task_id=task_id,
        checkpoint_id=checkpoint_id,
        proposal_hash="proposal-hash",
        action_type="job_application_submit_action",
        tool_name="application_submitter",
        target=target,
        risk_level="HIGH_RISK",
        reason="Control-plane test approval.",
        expires_at=expires_at,
        db_path=db,
    )


def test_phase45_status_aggregates_all_sources(tmp_path):
    workspace, db = _workspace_and_db(tmp_path)
    cp = ControlPlane(workspace_root=str(workspace), db_path=db, task_runner=TaskRunner(workspace_root=str(workspace), db_path=db, graph_runner=_stub_read_only))
    pending = _pending_approval(db)
    active = create_task("Goal for the active control task.", current_stage="DECOMPOSE", current_sub_goal="plan subgoals", status="RUNNING", status_reason="control test", db_path=db)
    create_checkpoint(
        active["task_id"],
        current_stage="DECOMPOSE",
        current_sub_goal="plan subgoals",
        selected_tools=["goal_decomposer"],
        action_type="task_runner_checkpoint",
        action_target=str(workspace),
        risk_level="READ_ONLY",
        approval_status="UNKNOWN",
        resume_required=False,
        resume_reason="",
        environment_fingerprint=str(workspace),
        db_path=db,
    )
    cp.service.security_monitor.record_event({"event_type": "prompt_injection_detected", "source": "untrusted_evidence", "reason": "control test", "recommended_containment": "RESTRICT"})
    status = cp.status()
    assert status["lifecycle"]["state"] in {"STOPPED", "RUNNING"}
    assert "health" in status["service_health"]
    assert "cpu_percent" in status["resource"] and "memory_bytes" in status["resource"]
    assert status["task_counts"]["RUNNING"] >= 1
    assert status["approvals"]["pending_count"] >= 1
    assert status["approvals"]["pending_preview"][0]["approval_id"] == pending["approval_id"]
    assert "recovery_failures" in status["recovery"] and "max_recovery_failures" in status["recovery"]
    assert status["active_task"]["task_id"] == active["task_id"]
    assert status["active_checkpoint"]["checkpoint_id"]
    assert status["active_task"]["objective"] == "Goal for the active control task."
    assert status["active_task"]["current_stage"] == "DECOMPOSE"
    assert status["active_task"]["current_sub_goal"] == "plan subgoals"
    assert len(status["providers"]) >= 24
    assert "health_state" in status["security"]
    assert status["workspace"]["workspace_root"]
    assert "loop_count" in status["autonomous"]
    decided = cp.decide(pending["approval_id"], "REJECTED")
    assert decided["accepted"] is True
    assert cp.list_approvals()["count"] == 0


def _assert_transition(cp, command, *, expected_state=None, accepted=None):
    result = cp.lifecycle(command)
    if accepted is not None:
        assert result["accepted"] is accepted, result
    if expected_state is not None:
        assert result.get("result", {}).get("state") == expected_state, result
    return result


def test_phase45_lifecycle_start_stop_pause_resume_restart_shutdown(tmp_path):
    cp = _make_cp(tmp_path, start=False)
    _assert_transition(cp, "START", accepted=True, expected_state="RUNNING")
    _assert_transition(cp, "STOP", accepted=True, expected_state="STOPPED")
    cp.lifecycle("START")
    _assert_transition(cp, "PAUSE", accepted=True, expected_state="PAUSED")
    _assert_transition(cp, "RESUME", accepted=True, expected_state="RUNNING")
    _assert_transition(cp, "RESTART", accepted=True, expected_state="RUNNING")
    _assert_transition(cp, "SHUTDOWN", accepted=True, expected_state="SHUTDOWN")
    _assert_transition(cp, "START", accepted=True, expected_state="RUNNING")


def test_phase45_invalid_lifecycle_transitions_fail_safely(tmp_path):
    cp = _make_cp(tmp_path, start=False)
    stopped = cp.lifecycle("STOP")
    assert stopped["accepted"] is False and "not legal" in stopped["reason"]
    assert stopped["current_state"] == "STOPPED"
    assert cp.lifecycle("PAUSE")["accepted"] is False
    assert cp.lifecycle("SHUTDOWN")["accepted"] is False
    cp.lifecycle("START")
    assert cp.lifecycle("START")["accepted"] is False
    assert cp.lifecycle("RESUME")["accepted"] is False
    assert "not legal" in cp.lifecycle("RESUME")["reason"]
    assert cp.lifecycle("PAUSE")["accepted"] is True
    assert cp.lifecycle("STOP")["accepted"] is True
    assert cp.lifecycle("SHUTDOWN")["accepted"] is False
    assert cp.lifecycle("FROBNICATE")["accepted"] is False
    result = cp.lifecycle("BOGUS")
    assert result["accepted"] is False and "Unknown lifecycle command" in result["reason"]


def test_phase45_task_list_active_paused_blocked_inspection(tmp_path):
    cp = _make_cp(tmp_path)
    running = create_task("Run active inspect", current_stage="EXECUTE_SUBGOAL", current_sub_goal="apply approved change", db_path=cp.db_path)
    update_task_status(running["task_id"], "RUNNING", current_stage="EXECUTE_SUBGOAL", current_sub_goal="apply approved change", status_reason="active", db_path=cp.db_path)
    paused = create_task("Paused task", db_path=cp.db_path)
    update_task_status(paused["task_id"], "PAUSED", current_stage="REQUEST", current_sub_goal="", status_reason="paused by user", resume_reason="waiting on input", db_path=cp.db_path)
    blocked = create_task("Blocked task", db_path=cp.db_path)
    update_task_status(blocked["task_id"], "BLOCKED", current_stage="REQUEST", current_sub_goal="", status_reason="security block", final_outcome="BLOCKED", db_path=cp.db_path)
    view = cp.list_tasks("PAUSED")
    assert view["accepted"] is True
    assert any(item["task_id"] == paused["task_id"] for item in view["items"])
    assert view["counts"]["RUNNING"] == 1
    assert view["counts"]["PAUSED"] == 1
    assert view["counts"]["BLOCKED"] == 1
    assert view["filter"] == "PAUSED"
    active = cp.status()["active_task"]
    assert active["task_id"] == running["task_id"]
    detail = cp.inspect_task(running["task_id"])
    assert detail["accepted"] is True
    assert detail["task"]["current_stage"] == "EXECUTE_SUBGOAL"
    assert detail["task"]["current_sub_goal"] == "apply approved change"
    assert detail["task"]["status"] == "RUNNING"
    assert cp.inspect_task("does-not-exist-000")["accepted"] is False
    assert cp.inspect_task("bad id!")["accepted"] is False
    assert cp.list_tasks("BLOCKED")["counts"]["BLOCKED"] == 1


def test_phase45_recovery_inspection(tmp_path):
    cp = _make_cp(tmp_path)
    paused = create_task("Paused for recovery", db_path=cp.db_path)
    update_task_status(paused["task_id"], "PAUSED", status_reason="worker interruption", resume_reason="shutdown: interrupted", db_path=cp.db_path)
    blocked = create_task("Blocked for recovery", db_path=cp.db_path)
    update_task_status(blocked["task_id"], "BLOCKED", status_reason="unsafe recovery state", final_outcome="BLOCKED", db_path=cp.db_path)
    recovery = cp.recovery()
    assert "recovery_failures" in recovery and "max_recovery_failures" in recovery
    assert recovery["paused_tasks"] >= 1 and recovery["blocked_tasks"] >= 1
    task_ids = {signal["task_id"] for signal in recovery["recent_signals"]}
    assert paused["task_id"] in task_ids and blocked["task_id"] in task_ids
    assert cp.status()["recovery"]["paused_tasks"] >= 1
    recovery_view = cp.dispatch("recovery")
    assert recovery_view["accepted"] is True and recovery_view["recovery"]["blocked_tasks"] >= 1


def test_phase45_pending_approval_inspection_and_decision(tmp_path):
    cp = _make_cp(tmp_path)
    approval = _pending_approval(cp.db_path)
    view = cp.list_approvals()
    assert view["accepted"] is True
    assert view["count"] == 1
    assert view["items"][0]["approval_id"] == approval["approval_id"]
    assert view["items"][0]["target"] == "fixture-job-0001"
    approved = cp.decide(approval["approval_id"], "APPROVED", expected_task_id="task-45", expected_target="fixture-job-0001")
    assert approved["accepted"] is True
    assert approved["approval"]["status"] == "APPROVED"
    replay = cp.decide(approval["approval_id"], "APPROVED")
    assert replay["accepted"] is False
    assert "only pending" in replay["reason"]
    assert cp.list_approvals()["count"] == 0


def test_phase45_expired_approval_rejection(tmp_path):
    cp = _make_cp(tmp_path)
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(timespec="seconds")
    approval = _pending_approval(cp.db_path, task_id="task-expired", checkpoint_id="cp-expired", expires_at=past)
    result = cp.decide(approval["approval_id"], "APPROVED")
    assert result["accepted"] is False
    assert "EXPIRED" in result["reason"] or "expired" in result["reason"].lower()
    assert cp.list_approvals()["count"] == 0


def test_phase45_approval_mismatch_rejection(tmp_path):
    cp = _make_cp(tmp_path)
    approval = _pending_approval(cp.db_path, task_id="task-real", checkpoint_id="cp-mismatch", target="fixture-job-0001")
    wrong_task = cp.decide(approval["approval_id"], "APPROVED", expected_task_id="task-imposter")
    assert wrong_task["accepted"] is False
    assert "mismatch for task_id" in wrong_task["reason"]
    wrong_target = cp.decide(approval["approval_id"], "APPROVED", expected_target="unrelated-target")
    assert wrong_target["accepted"] is False
    assert "mismatch for target" in wrong_target["reason"]
    assert get_approval(approval["approval_id"], db_path=cp.db_path)["status"] == "PENDING"


def test_phase45_provider_and_capability_health(tmp_path):
    cp = _make_cp(tmp_path)
    providers = cp.provider_health()
    assert len(providers) >= 24
    indexed = {provider["provider_id"]: provider for provider in providers}
    assert indexed["fixture_email"]["status"] == "CAPABILITY_AUTHORIZED"
    assert indexed["fixture_email"]["fixture_or_mock"] is True
    assert indexed["fixture_email"]["real"] is False
    assert indexed["gmail_real"]["status"] == "NOT_CONFIGURED"
    assert indexed["gmail_real"]["real"] is True
    assert indexed["gmail_real"]["fixture_or_mock"] is False
    assert indexed["u_email"]["status"] == "UNAVAILABLE"
    assert indexed["u_email"]["configured"] is False
    application = indexed["fixture_application"]
    capabilities = {capability["capability_id"]: capability for capability in application["capabilities"]}
    assert capabilities["APPLICATION_SUBMIT"]["status"] == "CAPABILITY_AUTHORIZED"
    submit_operations = {operation["name"]: operation for operation in capabilities["APPLICATION_SUBMIT"]["operations"]}
    assert submit_operations["submit"]["requires_approval"] is True
    assert submit_operations["submit"]["status"] == "OPERATION_REQUIRES_APPROVAL"
    prepare_operations = {operation["name"]: operation for operation in capabilities["APPLICATION_PREPARE"]["operations"]}
    assert prepare_operations["prepare"]["read_only"] is True
    assert prepare_operations["prepare"]["status"] == "OPERATION_PERMITTED"
    browse_operations = {operation["name"]: operation for operation in indexed["fixture_browser"]["capabilities"][0]["operations"]}
    assert browse_operations["observe_page"]["status"] == "OPERATION_PERMITTED"


def test_phase45_security_health_and_secret_redaction(tmp_path):
    cp = _make_cp(tmp_path)
    cp.service.security_monitor.record_event({"event_type": "unauthorized_tool_request", "source": "action_bridge", "reason": "simulated unauthorized escalation", "recommended_containment": "RESTRICT"})
    snapshot = cp.security_health()
    assert "health_state" in snapshot
    event_types = [event.get("event_type") for event in snapshot["recent_security_events"]]
    assert "unauthorized_tool_request" in event_types
    assert any(str(event.get("severity") or "").upper() in {"HIGH", "MEDIUM", "CRITICAL"} for event in snapshot["recent_security_events"])
    task = create_task("Review the configuration; token=superSekret123 must not leak and password=hunter2secret must stay hidden.", db_path=cp.db_path)
    rendered = json.dumps(cp.inspect_task(task["task_id"]), default=str)
    assert "superSekret123" not in rendered
    assert "hunter2secret" not in rendered
    assert "[REDACTED]" in rendered


def test_phase45_resource_health_preserves_restricted(tmp_path):
    workspace, db = _workspace_and_db(tmp_path)
    overloaded = ControlPlane(workspace_root=str(workspace), db_path=db, resource_provider=lambda: {"cpu_percent": 99, "memory_bytes": 999999}, task_runner=TaskRunner(workspace_root=str(workspace), db_path=db, graph_runner=_stub_read_only))
    assert overloaded.resource_health()["status"] == "RESTRICTED"
    assert overloaded.status()["resource"]["status"] == "RESTRICTED"
    assert "RESTRICTED" in overloaded.resource_health()["message"]
    nominal = ControlPlane(workspace_root=str(workspace), db_path=db, resource_provider=lambda: {"cpu_percent": 5, "memory_bytes": 1000}, task_runner=TaskRunner(workspace_root=str(workspace), db_path=db, graph_runner=_stub_read_only))
    assert nominal.resource_health()["status"] == "NORMAL"
    resource_view = nominal.dispatch("resources")
    assert resource_view["accepted"] is True and resource_view["resources"]["status"] == "NORMAL"


def test_phase45_unknown_operation_rejection(tmp_path):
    cp = _make_cp(tmp_path)
    unknown = cp.dispatch("explode")
    assert unknown["accepted"] is False and "Unknown control-plane operation" in unknown["reason"]
    assert cp.dispatch("frobnicate now")["accepted"] is False
    assert cp.dispatch("lifecycle")["accepted"] is False
    assert cp.dispatch("task")["accepted"] is False
    assert cp.dispatch("approve")["accepted"] is False
    assert cp.handle("status")["accepted"] is True


def test_phase45_arbitrary_execution_rejection(tmp_path):
    cp = _make_cp(tmp_path)
    for attempt in (
        "run-python os.system('dir')",
        "execute-tool anything",
        "shell: del /q workspace",
        "run_command net user",
        "exec(eval('__import__(\"os\")'))",
        "os.system('format c:')",
    ):
        result = cp.submit(attempt)
        assert result["accepted"] is False, attempt
        assert "not a control-plane operation" in result["reason"]
    assert cp.handle("! dir")["accepted"] is False
    assert not hasattr(cp, "execute_tool")
    assert not hasattr(cp, "run_shell")


def test_phase45_localhost_boundary(tmp_path):
    with pytest.raises(ValueError):
        run_server(host="0.0.0.0", control=None)
    cp = _make_cp(tmp_path)
    app = create_control_app(cp)
    client = app.test_client()
    for path in ("/api/status", "/api/providers", "/api/approvals", "/api/security", "/api/resources", "/api/audit", "/api/tasks"):
        response = client.get(path)
        assert response.status_code == 200, path
    assert client.get("/api/execute").status_code == 404
    assert client.get("/api/shell").status_code == 404
    assert client.post("/api/run-command", json={}).status_code == 404
    assert client.post("/api/run-python", json={}).status_code == 404
    assert client.post("/api/approvals/nope/approve", json={}).status_code == 200


def test_phase45_audit_logging(tmp_path):
    cp = _make_cp(tmp_path)
    cp.lifecycle("START")
    cp.submit("Inspect the authorized workspace read only. Do not modify anything.")
    approval = _pending_approval(cp.db_path, task_id="task-audit", checkpoint_id="cp-audit")
    cp.decide(approval["approval_id"], "REJECTED", reason="control-plane audit test")
    events = cp.audit()["events"]
    types = {event["event_type"] for event in events}
    assert "control_plane_lifecycle" in types
    assert "control_plane_request" in types
    assert "approval_denied" in types
    rendered = json.dumps(events, default=str)
    assert "superSekret" not in rendered


def test_phase45_stategraph_integration_default_runner(tmp_path):
    from app.agent.graph import nexus_graph as compiled

    workspace, db = _workspace_and_db(tmp_path)
    runner = TaskRunner(workspace_root=str(workspace), db_path=db)
    assert runner.graph_runner == compiled.invoke
    cp = ControlPlane(workspace_root=str(workspace), db_path=db, task_runner=runner)
    assert cp.service.task_runner.graph_runner == compiled.invoke
    assert cp.lifecycle("START")["accepted"] is True
    result = cp.submit("Inspect the authorized workspace read only. Do not modify anything.", graph_runner=_stub_read_only)
    assert result["accepted"] is True
    assert result["status"] == "COMPLETED"
    assert "READ_ONLY" in result["final_outcome"]


def test_phase45_task_runner_regression(tmp_path):
    workspace, db = _workspace_and_db(tmp_path)
    runner = TaskRunner(workspace_root=str(workspace), db_path=db, graph_runner=_stub_read_only)
    cp = ControlPlane(workspace_root=str(workspace), db_path=db, task_runner=runner)
    assert cp.lifecycle("START")["accepted"] is True
    result = cp.submit("Inspect the public workspace file classic-project.py.")
    assert result["accepted"] is True
    assert result["status"] == "COMPLETED"
    assert get_task(result["task_id"], db_path=db)["status"] == "COMPLETED"
    assert result["status"] in TERMINAL_TASKS
    waiting = runner.start_task("Submit the internship application for fixture-job-0001.", graph_runner=_stub_waiting_approval)
    assert waiting["status"] == "WAITING_APPROVAL"
    assert get_task(waiting["task_id"], db_path=db)["status"] == "WAITING_APPROVAL"
    natural = cp.handle("Inspect the workspace read only.")
    assert natural["accepted"] is True


def test_phase45_autonomous_service_regression(tmp_path):
    workspace, db = _workspace_and_db(tmp_path)
    service = AutonomousService(
        workspace,
        db_path=db,
        task_runner=TaskRunner(workspace_root=str(workspace), db_path=db, graph_runner=_stub_read_only),
    )
    cp = ControlPlane(workspace_root=str(workspace), db_path=db, service=service)
    assert cp.service is service
    assert cp.lifecycle("START")["accepted"] is True
    assert service.status()["state"] == "RUNNING"
    assert service.run_once()["status"] == "RUNNING"
    assert cp.lifecycle("PAUSE")["result"]["state"] == "PAUSED"
    assert service.run_once()["status"] == "NOT_RUNNING"
    assert cp.lifecycle("RESUME")["result"]["state"] == "RUNNING"
    assert service.run_once()["status"] == "RUNNING"
    assert cp.lifecycle("SHUTDOWN")["result"]["state"] == "SHUTDOWN"
    assert service.run_once()["status"] == "NOT_RUNNING"