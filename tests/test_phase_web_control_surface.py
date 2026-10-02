"""Web Control Surface tests.

Covers the local NEXUS web UI foundation and its integration with the existing
control plane. The web layer is a user interface only: tasks are submitted as
natural language and routed through TaskRunner -> StateGraph; approvals go
through the existing ApprovalAuthority; no arbitrary execution endpoint exists.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from app.agent.approval_authority import create_approval, get_approval
from app.agent.task_runner import TaskRunner
from app.control_plane import ControlPlane, create_control_app, run_server
from app.memory.task_ledger import MAX_TASK_ANSWER_CHARS, get_task

ROOT = Path(__file__).resolve().parents[1]


def _workspace_and_db(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return workspace, tmp_path / "web.db"


def _stub_read_only(state):
    return {**state, "task_status": "COMPLETED", "final_outcome": "READ_ONLY"}


def _task_result_runner(*, status="COMPLETED", final_outcome="READ_ONLY", observations=None, action_result=None, decision_reason="Subgoals were verified with bounded evidence.", approval_required=False, approved=True):
    def _runner(state):
        return {
            **state,
            "task_status": status,
            "final_outcome": final_outcome,
            "observation_results": list(observations or []),
            "action_result": action_result if action_result is not None else state.get("action_result", ""),
            "decision_reason": decision_reason,
            "approval_required": approval_required,
            "approved": approved,
        }
    return _runner


def _client_for_runner(tmp_path, runner):
    cp = ControlPlane(workspace_root=runner.workspace_root, db_path=runner.db_path, task_runner=runner)
    cp.lifecycle("START")
    app = create_control_app(cp)
    app.config.update(TESTING=True)
    return app.test_client(), cp, runner.db_path


def _make_cp(tmp_path, **kwargs):
    workspace, db = _workspace_and_db(tmp_path)
    runner = TaskRunner(workspace_root=str(workspace), db_path=db, graph_runner=_stub_read_only)
    kwargs.setdefault("task_runner", runner)
    cp = ControlPlane(workspace_root=str(workspace), db_path=db, **kwargs)
    cp.lifecycle("START")
    return cp, db


def _make_client(tmp_path, **kwargs):
    cp, db = _make_cp(tmp_path, **kwargs)
    app = create_control_app(cp)
    app.config.update(TESTING=True)
    return app.test_client(), cp, db


def _pending_approval(db, *, task_id="task-web", checkpoint_id="cp-web", target="fixture-job-0001"):
    return create_approval(
        task_id=task_id,
        checkpoint_id=checkpoint_id,
        proposal_hash="proposal-web",
        action_type="job_application_submit_action",
        tool_name="application_submitter",
        target=target,
        risk_level="HIGH_RISK",
        reason="Web control surface test approval.",
        db_path=db,
    )


def test_web_ui_loads(tmp_path):
    client, _, _ = _make_client(tmp_path)
    response = client.get("/")
    assert response.status_code == 200
    assert b"NEXUS" in response.data
    assert b"sidebar" in response.data
    assert b"view-dashboard" in response.data
    assert b"/static/app.js" in response.data


def test_dashboard_assets_load(tmp_path):
    client, _, _ = _make_client(tmp_path)
    assert client.get("/static/styles.css").status_code == 200
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/").status_code == 200


def test_status_endpoint_works(tmp_path):
    client, _, _ = _make_client(tmp_path)
    response = client.get("/api/status")
    assert response.status_code == 200
    payload = response.get_json()["status"]
    assert "lifecycle" in payload
    assert "task_counts" in payload
    assert "security" in payload
    assert "providers" in payload
    assert "observed_at" in payload


def test_health_endpoint_works(tmp_path):
    client, _, _ = _make_client(tmp_path)
    response = client.get("/api/health")
    assert response.status_code == 200
    payload = response.get_json()
    assert "health" in payload
    assert "state" in payload
    assert payload["local_only"] is True
    assert payload["host"] == "127.0.0.1"


def test_task_submission_reaches_existing_nexus_task_path(tmp_path):
    client, cp, db = _make_client(tmp_path)
    response = client.post("/api/tasks", json={"request": "Inspect the workspace read only. Do not modify anything."})
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["accepted"] is True
    task_id = payload["task_id"]
    assert task_id.startswith("task-")
    ledger = get_task(task_id, db_path=db)
    assert ledger is not None
    assert ledger["status"] == "COMPLETED"
    assert "READ_ONLY" in str(payload.get("final_outcome", ""))
    assert cp.service.task_runner is not None


def test_task_submission_returns_task_identifier(tmp_path):
    client, _, _ = _make_client(tmp_path)
    payload = client.post("/api/tasks", json={"request": "check git status"}).get_json()
    assert payload["accepted"] is True
    assert payload["task_id"].startswith("task-")


def test_task_inspection_works(tmp_path):
    client, _, db = _make_client(tmp_path)
    created = client.post("/api/tasks", json={"request": "Analyze the error in demo_error.py."}).get_json()
    task_id = created["task_id"]
    response = client.get(f"/api/tasks/{task_id}")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["accepted"] is True
    assert payload["task"]["task_id"] == task_id
    assert payload["checkpoint"] is not None or payload["checkpoint"] is None


def test_unknown_task_returns_structured_error(tmp_path):
    client, _, _ = _make_client(tmp_path)
    response = client.get("/api/tasks/task-does-not-exist")
    assert response.status_code == 200
    assert response.get_json()["accepted"] is False


def test_task_submission_rejects_non_request_fields(tmp_path):
    client, _, _ = _make_client(tmp_path)
    response = client.post("/api/tasks", json={"request": "do something", "tool_name": "shell"})
    assert response.status_code == 400
    assert response.get_json()["accepted"] is False
    response = client.post("/api/tasks", json={"request": "do something", "python": "print(1)"})
    assert response.status_code == 400


def test_task_submission_requires_natural_language(tmp_path):
    client, _, _ = _make_client(tmp_path)
    assert client.post("/api/tasks", json={}).status_code == 400
    assert client.post("/api/tasks", json={"request": "   "}).status_code == 400
    assert client.post("/api/tasks", data="not json", content_type="text/plain").status_code == 400


def test_pending_approvals_can_be_displayed(tmp_path):
    client, _, db = _make_client(tmp_path)
    approval = _pending_approval(db)
    payload = client.get("/api/approvals").get_json()
    assert payload["count"] == 1
    assert any(item["approval_id"] == approval["approval_id"] for item in payload["items"])
    item = next(item for item in payload["items"] if item["approval_id"] == approval["approval_id"])
    assert item["task_id"] == "task-web"
    assert item["risk_level"] == "HIGH_RISK"
    assert item["target"] == "fixture-job-0001"


def test_approval_ui_cannot_bypass_approval_authority(tmp_path):
    client, _, db = _make_client(tmp_path)
    approval = _pending_approval(db)
    malicious = client.post(
        f"/api/approvals/{approval['approval_id']}/approve",
        json={"action_type": "shell", "tool_name": "arbitrary", "target": "/", "risk_level": "LOW_RISK"},
    )
    assert malicious.status_code == 400
    assert get_approval(approval["approval_id"], db_path=db)["status"] == "PENDING"
    fabricated = client.post("/api/approvals/approval-fake123/approve", json={})
    assert fabricated.get_json()["accepted"] is False


def test_approve_works_through_existing_mechanism(tmp_path):
    client, _, db = _make_client(tmp_path)
    approval = _pending_approval(db)
    response = client.post(f"/api/approvals/{approval['approval_id']}/approve", json={"reason": "web test"})
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["accepted"] is True
    assert payload["decision"] == "APPROVED"
    assert get_approval(approval["approval_id"], db_path=db)["status"] == "APPROVED"


def test_reject_works_through_existing_mechanism(tmp_path):
    client, _, db = _make_client(tmp_path)
    approval = _pending_approval(db)
    response = client.post(f"/api/approvals/{approval['approval_id']}/reject", json={})
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["accepted"] is True
    assert payload["decision"] == "REJECTED"
    record = get_approval(approval["approval_id"], db_path=db)
    assert record["status"] == "REJECTED"
    pending = client.get("/api/approvals").get_json()
    assert pending["count"] == 0


def test_arbitrary_shell_execution_endpoint_does_not_exist(tmp_path):
    client, _, _ = _make_client(tmp_path)
    assert client.get("/api/shell").status_code == 404
    assert client.post("/api/shell", json={"command": "dir"}).status_code == 404
    assert client.get("/api/execute").status_code == 404
    assert client.post("/api/execute", json={}).status_code == 404


def test_arbitrary_python_execution_endpoint_does_not_exist(tmp_path):
    client, _, _ = _make_client(tmp_path)
    assert client.post("/api/run-python", json={"code": "print(1)"}).status_code == 404
    assert client.post("/api/run-command", json={"command": "dir"}).status_code == 404


def test_service_control_is_bounded_to_lifecycle(tmp_path):
    client, _, _ = _make_client(tmp_path)
    assert client.post("/api/service/start", json={}).status_code == 200
    assert client.post("/api/service/execute", json={}).status_code == 400
    assert client.post("/api/service/bash", json={}).status_code == 400


def test_task_submission_requires_running_service(tmp_path):
    workspace, db = _workspace_and_db(tmp_path)
    runner = TaskRunner(workspace_root=str(workspace), db_path=db, graph_runner=_stub_read_only)
    cp = ControlPlane(workspace_root=str(workspace), db_path=db, task_runner=runner)
    app = create_control_app(cp)
    app.config.update(TESTING=True)
    client = app.test_client()
    payload = client.post("/api/tasks", json={"request": "inspect the workspace"}).get_json()
    assert payload["accepted"] is False
    assert "RUNNING" in payload["reason"]


def test_server_binds_only_to_localhost(tmp_path):
    cp, _ = _make_cp(tmp_path)
    with pytest.raises(ValueError):
        run_server(host="0.0.0.0", control=cp)


def test_run_server_auto_starts_service_when_stopped(tmp_path, monkeypatch):
    from app.control_plane import create_control_app as _real_create_app

    workspace, db = _workspace_and_db(tmp_path)
    cp = ControlPlane(workspace_root=str(workspace), db_path=db)
    assert cp.service.status().get("state") == "STOPPED"

    served = {}

    def _serving_app(control=None, *, web_ui=True):
        app = _real_create_app(control, web_ui=web_ui)

        def _run(**kwargs):
            served.update(kwargs)

        app.run = _run
        return app

    monkeypatch.setattr("app.control_plane.create_control_app", _serving_app)
    run_server(host="127.0.0.1", port=0, control=cp)

    assert served.get("host") == "127.0.0.1"
    assert int(served.get("port")) == 0
    assert cp.service.status().get("state") == "RUNNING"
    client = _real_create_app(cp).test_client()
    client.application.config.update(TESTING=True)
    payload = client.get("/api/status").get_json()["status"]
    assert payload["lifecycle"]["state"] == "RUNNING"


def test_run_server_start_is_idempotent_when_already_running(tmp_path, monkeypatch):
    from app.control_plane import create_control_app as _real_create_app

    workspace, db = _workspace_and_db(tmp_path)
    cp = ControlPlane(workspace_root=str(workspace), db_path=db)
    cp.lifecycle("START")
    assert cp.service.status().get("state") == "RUNNING"

    def _break_on_start(command):
        raise AssertionError("run_server must not re-issue START on an already RUNNING service")

    monkeypatch.setattr(cp, "lifecycle", _break_on_start)

    def _serving_app(control=None, *, web_ui=True):
        app = _real_create_app(control, web_ui=web_ui)
        app.run = lambda **_kwargs: None
        return app

    monkeypatch.setattr("app.control_plane.create_control_app", _serving_app)
    run_server(host="127.0.0.1", port=0, control=cp)
    assert cp.service.status().get("state") == "RUNNING"


def test_run_server_fails_closed_when_service_cannot_start(tmp_path, monkeypatch):
    from app.control_plane import create_control_app as _real_create_app

    workspace, db = _workspace_and_db(tmp_path)
    cp = ControlPlane(workspace_root=str(workspace), db_path=db)
    assert cp.service.status().get("state") == "STOPPED"

    def _broken_start(command):
        return {"accepted": False, "command": command, "current_state": "STOPPED", "reason": "simulated start failure"}

    monkeypatch.setattr(cp, "lifecycle", _broken_start)

    served = {"called": False}

    def _serving_app(control=None, *, web_ui=True):
        app = _real_create_app(control, web_ui=web_ui)
        app.run = lambda **_kwargs: served.__setitem__("called", True)
        return app

    monkeypatch.setattr("app.control_plane.create_control_app", _serving_app)

    with pytest.raises(RuntimeError, match="could not auto-start"):
        run_server(host="127.0.0.1", port=0, control=cp)
    assert served["called"] is False
    assert cp.service.status().get("state") == "STOPPED"


def test_secret_values_are_not_exposed(tmp_path):
    client, _, db = _make_client(tmp_path)
    secret_token = "superSekretWeb001"
    secret_password = "hunter2secret"
    created = client.post("/api/tasks", json={"request": f"analyze this config: token={secret_token} password={secret_password}"}).get_json()
    task_id = created["task_id"]
    combined = ""
    for path in (
        "/api/status",
        "/api/health",
        "/api/tasks",
        f"/api/tasks/{task_id}",
        "/api/activity",
        "/api/audit",
        "/api/security",
    ):
        combined += client.get(path).get_data(as_text=True)
    assert secret_token not in combined
    assert secret_password not in combined
    assert "REDACTED" in combined


def test_activity_and_sections_endpoints_work(tmp_path):
    client, _, _ = _make_client(tmp_path)
    activity = client.get("/api/activity").get_json()
    assert activity["accepted"] is True
    assert isinstance(activity["audit"], list)
    assert activity["count"] >= 0
    sections = client.get("/api/sections/browser").get_json()
    assert sections["accepted"] is True
    assert isinstance(sections["providers"], list)
    invalid = client.get("/api/sections/../etc").get_json()
    assert invalid["accepted"] is False


def test_terminal_python_main_remains_intact():
    completed = subprocess.run(
        [sys.executable, "main.py"],
        input="Inspect the workspace read only. Do not modify anything.\n",
        text=True,
        capture_output=True,
        cwd=ROOT,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    output = completed.stdout
    assert '"task_id": "task-' in output
    assert '"accepted": true' in output


def test_completed_read_only_task_exposes_result(tmp_path):
    workspace, db = _workspace_and_db(tmp_path)
    runner = TaskRunner(
        workspace_root=str(workspace),
        db_path=db,
        graph_runner=_task_result_runner(action_result="Found 3 Python modules, 2 relevant files, and no syntax errors."),
    )
    client, _, db = _client_for_runner(tmp_path, runner)
    created = client.post("/api/tasks", json={"request": "Inspect the workspace read only. Do not modify anything."}).get_json()
    assert created["accepted"] is True
    assert created["status"] == "COMPLETED"
    answer = created["task_answer"]
    assert answer
    assert "no syntax errors" in answer.lower()
    ledger = get_task(created["task_id"], db_path=db)
    assert ledger["task_answer"] == answer
    detail = client.get("/api/tasks/" + created["task_id"]).get_json()
    assert detail["accepted"] is True
    assert detail["task"]["task_answer"] == answer


def test_browser_task_exposes_bounded_page_result(tmp_path):
    workspace, db = _workspace_and_db(tmp_path)
    browser_evidence = {
        "source": "browser",
        "url": "https://example.com/",
        "final_url": "https://example.com/",
        "title": "Example Domain",
        "visible_text": "This domain is for use in illustrative examples in documents. " * 400,
        "headings": ["Example Domain", "More information..."],
        "links": [{"text": "More information...", "url": "https://www.iana.org/domains/example"}],
        "status": "OK",
        "truncated": False,
    }
    runner = TaskRunner(
        workspace_root=str(workspace),
        db_path=db,
        graph_runner=_task_result_runner(observations=[{"tool": "browser_observer", "status": "ok", "result": browser_evidence}]),
    )
    client, _, _ = _client_for_runner(tmp_path, runner)
    created = client.post("/api/tasks", json={"request": "Open https://example.com and tell me the page title. Do not modify anything."}).get_json()
    assert created["accepted"] is True
    assert created["status"] == "COMPLETED"
    assert "READ_ONLY" in created["final_outcome"]
    answer = created["task_answer"]
    assert "Example Domain" in answer
    assert "https://example.com/" in answer
    assert len(answer) <= MAX_TASK_ANSWER_CHARS + 32


def test_task_answer_is_redacted(tmp_path):
    workspace, db = _workspace_and_db(tmp_path)
    secret = "superSekretTaskAnswer001"
    runner = TaskRunner(
        workspace_root=str(workspace),
        db_path=db,
        graph_runner=_task_result_runner(action_result=f"token={secret} password=hunter2banana"),
    )
    client, _, _ = _client_for_runner(tmp_path, runner)
    created = client.post("/api/tasks", json={"request": "analyze this result"}).get_json()
    answer = created["task_answer"]
    assert "[REDACTED]" in answer
    combined = answer + client.get("/api/tasks/" + created["task_id"]).get_data(as_text=True)
    assert secret not in combined
    assert "hunter2banana" not in combined


def test_consequential_task_remains_waiting_approval(tmp_path):
    workspace, db = _workspace_and_db(tmp_path)
    runner = TaskRunner(
        workspace_root=str(workspace),
        db_path=db,
        graph_runner=_task_result_runner(status="WAITING_APPROVAL", final_outcome="READ_ONLY", approval_required=True, approved=False),
    )
    client, _, db = _client_for_runner(tmp_path, runner)
    created = client.post("/api/tasks", json={"request": "fix the critical bug in shop_project.py"}).get_json()
    assert created["accepted"] is True
    assert created["status"] == "WAITING_APPROVAL"
    assert get_task(created["task_id"], db_path=db)["status"] == "WAITING_APPROVAL"


def test_browser_without_explicit_url_is_blocked(tmp_path):
    workspace, db = _workspace_and_db(tmp_path)
    runner = TaskRunner(workspace_root=str(workspace), db_path=db)
    client, _, db = _client_for_runner(tmp_path, runner)
    created = client.post("/api/tasks", json={"request": "Open YouTube"}).get_json()
    assert created["accepted"] is True
    assert created["status"] == "BLOCKED"
    assert "HUMAN_REQUIRED" in str(created.get("final_outcome", ""))
    assert "explicit" in created.get("task_answer", "").lower()
    ledger = get_task(created["task_id"], db_path=db)
    assert ledger["status"] == "BLOCKED"
    assert ledger["final_outcome"] == "HUMAN_REQUIRED"


def test_static_ui_renders_task_result(tmp_path):
    client, _, _ = _make_client(tmp_path)
    app_js = client.get("/static/app.js").get_data(as_text=True)
    styles = client.get("/static/styles.css").get_data(as_text=True)
    assert "task_answer" in app_js
    assert "renderResultPanel" in app_js
    assert ".result-panel" in styles