"""STEP 9 GAP CLOSURE: UI HTTP submission -> REAL Chromium (no direct executor call).

REAL CHROMIUM — NOT MOCKED. Uses Flask test_client (no external server):
POST /api/tasks (api_submit_task -> plane.submit -> TaskRunner.start_task ->
nexus_graph.invoke) -> WAITING_APPROVAL -> POST /api/approvals/<id>/approve
(existing approval-resume: plane.decide -> _resume_approved_browser_task ->
TaskRunner.start_task same task_id) -> Action Executor -> browser_controller ->
real sync_playwright -> real Chromium -> verification -> audit -> close_page.

This file NEVER imports/calls execute_authorized_action directly.
"""

from __future__ import annotations

import uuid

from app.agent.task_runner import TaskRunner
from app.control_plane import ControlPlane, create_control_app
from app.tools.browser_controller import _ACTIVE_PAGES, close_page

BASE_URL = "https://example.com"


def _runtime_url() -> str:
    return f"{BASE_URL}/?probe-{uuid.uuid4().hex[:12]}"


def _plane(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    db_path = tmp_path / "ui_gap.db"
    runner = TaskRunner(workspace_root=str(workspace), db_path=db_path)
    assert runner.graph_runner is not None
    plane = ControlPlane(workspace_root=str(workspace), db_path=db_path, task_runner=runner)
    started = plane.lifecycle("START")
    assert started.get("accepted") is True, started
    return plane


def test_ui_missing_url_stays_human_required_without_approval(tmp_path):
    """Negative: 'open youtube in chrome' (no URL) never fabricates a target."""
    _ACTIVE_PAGES.clear()
    plane = _plane(tmp_path)
    app = create_control_app(plane)
    app.config.update(TESTING=True)
    client = app.test_client()
    submitted = client.post("/api/tasks", json={"request": "Open youtube in chrome."}).get_json()
    assert submitted.get("accepted") is True
    assert submitted.get("status") in {"BLOCKED", "FAILED", "WAITING_APPROVAL"}
    assert submitted.get("final_outcome") in {"HUMAN_REQUIRED", "NO_ACTION", "BLOCKED", "APPROVAL_REQUIRED"}
    approvals = client.get("/api/approvals").get_json().get("items") or []
    assert [a for a in approvals if a.get("task_id") == submitted.get("task_id")] == []
    assert _ACTIVE_PAGES == {}


def test_ui_readonly_browser_stays_readonly_without_approval(tmp_path):
    """Negative: read-only observation stays READ_ONLY with no approval."""
    _ACTIVE_PAGES.clear()
    plane = _plane(tmp_path)
    app = create_control_app(plane)
    app.config.update(TESTING=True)
    client = app.test_client()
    url = _runtime_url()
    submitted = client.post(
        "/api/tasks", json={"request": f"Inspect {url} and report what is on the page. Do not modify anything."}
    ).get_json()
    assert submitted.get("accepted") is True
    assert submitted.get("status") == "COMPLETED"
    assert submitted.get("final_outcome") == "READ_ONLY"
    approvals = client.get("/api/approvals").get_json().get("items") or []
    assert [a for a in approvals if a.get("task_id") == submitted.get("task_id")] == []
    assert _ACTIVE_PAGES == {}


def test_ui_rejected_browser_approval_launches_nothing(tmp_path):
    """Negative: rejected approval never reaches Playwright."""
    import app.tools.browser_controller as controller_module

    launches: list[dict] = []
    real_launch_page = controller_module._launch_page

    def recording_launch(url: str, *, timeout_seconds: int = 15):
        launches.append({"url": url})
        return real_launch_page(url, timeout_seconds=timeout_seconds)

    controller_module._launch_page = recording_launch
    try:
        _ACTIVE_PAGES.clear()
        plane = _plane(tmp_path)
        app = create_control_app(plane)
        app.config.update(TESTING=True)
        client = app.test_client()
        url = _runtime_url()
        task_id = client.post(
            "/api/tasks", json={"request": f"Open {url} in the real browser and report what you see."}
        ).get_json()["task_id"]
        items = client.get("/api/approvals").get_json().get("items") or []
        approval_id = next(a["approval_id"] for a in items if a.get("task_id") == task_id)
        rejected = client.post(f"/api/approvals/{approval_id}/reject", json={}).get_json()
        assert rejected.get("accepted") is True
        assert rejected.get("decision") == "REJECTED"
        assert launches == []
        assert _ACTIVE_PAGES == {}
        detail = client.get(f"/api/tasks/{task_id}").get_json()
        assert detail["task"]["status"] in {"WAITING_APPROVAL", "BLOCKED", "CANCELLED", "FAILED"}
    finally:
        controller_module._launch_page = real_launch_page
        for page_id in list(_ACTIVE_PAGES.keys()):
            try:
                close_page(page_id)
            except Exception:
                pass
        _ACTIVE_PAGES.clear()


def test_ui_interactive_browser_reaches_real_chromium_via_approval_resume(tmp_path):
    import app.tools.browser_controller as controller_module

    launches: list[dict] = []
    real_launch_page = controller_module._launch_page

    def recording_launch(url: str, *, timeout_seconds: int = 15):
        launches.append({"url": url})
        return real_launch_page(url, timeout_seconds=timeout_seconds)

    controller_module._launch_page = recording_launch
    try:
        _ACTIVE_PAGES.clear()
        plane = _plane(tmp_path)
        app = create_control_app(plane)
        app.config.update(TESTING=True)
        client = app.test_client()

        url = _runtime_url()
        request_text = f"Open {url} in the real browser and report what you see."
        submitted = client.post("/api/tasks", json={"request": request_text})
        assert submitted.status_code == 200
        first = submitted.get_json()
        assert first.get("accepted") is True
        task_id = first.get("task_id")
        assert task_id

        # 1-5: UI endpoint -> TaskRunner -> StateGraph -> dynamic planning.
        # Interactive must stop at approval (never auto-execute).
        assert first.get("status") == "WAITING_APPROVAL", first

        approvals = client.get("/api/approvals").get_json()
        items = approvals.get("items") or []
        match = [a for a in items if a.get("task_id") == task_id]
        assert match, f"No pending approval for UI task {task_id}: {approvals}"
        assert match[0].get("tool_name") == "browser_controller", match[0]
        assert match[0].get("target") == url, match[0]
        approval_id = match[0].get("approval_id")
        assert approval_id

        detail = client.get(f"/api/tasks/{task_id}").get_json()
        checkpoint = detail.get("checkpoint") or {}
        assert checkpoint.get("action_type") == "browser_controller", checkpoint
        assert checkpoint.get("action_target") == url, checkpoint

        # Existing approval-resume mechanism continues SAME task (no direct executor call).
        decided = client.post(f"/api/approvals/{approval_id}/approve", json={})
        assert decided.status_code == 200
        decision = decided.get_json()
        assert decision.get("accepted") is True
        assert decision.get("decision") == "APPROVED"

        # 6-7: REAL Chromium launch + navigation occurred inside resume.
        assert launches, "Resume never reached browser_controller._launch_page"
        assert any(entry["url"] == url for entry in launches), launches

        resumed_task = (decision.get("task") or {})
        # Resume returns the re-executed task state; poll canonical view as well.
        detail = client.get(f"/api/tasks/{task_id}").get_json()
        task_view = detail.get("task", detail)
        answer = (resumed_task.get("task_answer") or task_view.get("task_answer") or "")
        # 8-9: verification + persisted answer from REAL observation (stable fields only).
        assert "Example Domain" in answer, answer[:500]
        assert url in answer or BASE_URL in answer

        # 10: cleanup — close any controller session the resume opened.
        assert _ACTIVE_PAGES != {} or launches, "No controller session was registered"
        for page_id in list(_ACTIVE_PAGES.keys()):
            assert close_page(page_id) is True
        assert _ACTIVE_PAGES == {}
    finally:
        controller_module._launch_page = real_launch_page
        for page_id in list(_ACTIVE_PAGES.keys()):
            try:
                close_page(page_id)
            except Exception:
                pass
        _ACTIVE_PAGES.clear()
