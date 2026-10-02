"""Phase 48: deterministic hackathon demo workflow and submission hardening.

This module drives the primary hackathon demo through the REAL NEXUS control
plane and the REAL HTTP surface, with no graph runner stub, no injected browser
evidence, and no new endpoints.

Primary demo request:

    "Open https://example.com, read the page, and tell me the page title and
     main text. Do not modify anything."

The demo must visibly show six stages through the EXISTING API only:

1. Natural-language task submission  -> POST /api/tasks
2. Goal/subgoal processing          -> goal_plan + subgoal_statuses
3. Browser observation              -> selected tool + observed URL
4. Real webpage evidence            -> title / visible_text in task_answer
5. Verification                     -> completion_evidence + status_reason
6. Final answer                     -> task_answer

No endpoint is added or changed by this phase. ``GET /api/tasks/<id>`` already
exposes every stage required above, so the existing surface is reused as-is.
"""

from __future__ import annotations

import ast

import pytest

from app.agent.task_runner import TaskRunner
from app.control_plane import ControlPlane, create_control_app

DEMO_REQUEST = (
    "Open https://example.com, read the page, and tell me the page title "
    "and main text. Do not modify anything."
)
TARGET_URL = "https://example.com"
EXPECTED_TITLE = "Example Domain"
EXPECTED_TEXT_FRAGMENT = "documentation examples"


def _demo_control_plane(tmp_path):
    """Build a real control plane backed by the real graph (no graph_runner stub)."""

    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    db_path = tmp_path / "demo_service.db"
    # No graph_runner argument: the real compiled StateGraph must execute.
    runner = TaskRunner(workspace_root=str(workspace), db_path=db_path)
    plane = ControlPlane(workspace_root=str(workspace), db_path=db_path, task_runner=runner)
    started = plane.lifecycle("START")
    assert started.get("accepted") is True, started
    return plane


@pytest.fixture(scope="module")
def demo_client(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("phase48")
    plane = _demo_control_plane(tmp_path)
    app = create_control_app(plane)
    app.config.update(TESTING=True)
    return app.test_client()


def test_demo_submission_runs_real_observation_through_http_api(demo_client):
    """The full demo runs through the real HTTP surface with a real fetch."""

    response = demo_client.post("/api/tasks", json={"request": DEMO_REQUEST})
    assert response.status_code == 200
    submitted = response.get_json()
    assert submitted.get("accepted") is True
    task_id = submitted["task_id"]
    assert task_id

    # Stage 6 + 1: the final answer is produced and the task settled.
    assert submitted["status"] == "COMPLETED"
    assert submitted["final_outcome"] == "READ_ONLY"

    # Stage 1: natural-language submission only; no extra fields accepted.
    assert submitted["objective"] == DEMO_REQUEST

    # Stage 3 + 4: the real URL was observed and real content came back.
    answer = submitted["task_answer"]
    assert f"URL: {TARGET_URL}" in answer
    assert f"Title: {EXPECTED_TITLE}" in answer
    assert EXPECTED_TEXT_FRAGMENT in answer

    detail = demo_client.get(f"/api/tasks/{task_id}")
    assert detail.status_code == 200
    task = detail.get_json()["task"]

    # Stage 2: goal/subgoal processing is visible.
    plan_ids = [item.get("sub_goal_id") for item in task.get("goal_plan") or []]
    assert "observe_browser_target" in plan_ids
    browser_subgoal = next(
        item for item in task["goal_plan"] if item["sub_goal_id"] == "observe_browser_target"
    )
    assert browser_subgoal["selected_tools"] == ["browser_observer"]

    # Stage 2 + 5: every planned subgoal verified.
    assert task["subgoal_statuses"]["observe_browser_target"] == "COMPLETED"
    assert "observe_browser_target:verified" in (task.get("completion_evidence") or [])
    assert "verified successfully" in task["status_reason"].lower()

    # Stage 4: the real evidence is retrievable from persisted verification history.
    evidence = None
    for entry in task.get("verification_history") or []:
        try:
            parsed = ast.literal_eval(entry) if isinstance(entry, str) else entry
        except (ValueError, SyntaxError):
            continue
        if isinstance(parsed, dict) and parsed.get("source") == "browser":
            evidence = parsed
            break
    assert evidence is not None, "Real browser evidence must be retrievable after the demo."
    assert evidence["url"] == TARGET_URL
    assert evidence["title"] == EXPECTED_TITLE
    assert evidence["status"] == "OK"

    # No action was taken: read-only throughout, nothing was approved.
    assert task["status"] == "COMPLETED"
    assert task.get("final_outcome") == "READ_ONLY"
    assert detail.get_json()["checkpoint"] is None


def test_demo_surface_has_no_execution_endpoints(demo_client):
    """Phase 48 security check: no arbitrary execution surface exists."""

    forbidden = {
        "/api/execute",
        "/api/run",
        "/api/run-command",
        "/api/run_command",
        "/api/run-python",
        "/api/run_python",
        "/api/tools/execute",
        "/api/tool",
        "/api/exec",
        "/api/eval",
        "/api/shell",
        "/api/command",
        "/api/filesystem",
        "/api/fs",
        "/api/git/exec",
        "/api/credentials",
        "/api/secrets",
        "/api/mcp",
        "/api/mcp/invoke",
        "/api/browser/script",
    }
    rules = {
        rule.rule
        for rule in demo_client.application.url_map.iter_rules()
        if rule.endpoint != "static"
    }
    for path in forbidden:
        assert path not in rules, f"Forbidden endpoint exposed: {path}"

    # The only POST surfaces are task submission, lifecycle, and approval decisions.
    post_rules = sorted(
        rule.rule for rule in demo_client.application.url_map.iter_rules() if "POST" in rule.methods
    )
    assert post_rules == [
        "/api/approvals/<approval_id>/approve",
        "/api/approvals/<approval_id>/reject",
        "/api/service/<command>",
        "/api/tasks",
    ]


def test_demo_hostile_requests_never_execute_anything(demo_client):
    """Hostile phrasing is either refused outright or degraded to read-only work.

    The control plane refuses clearly arbitrary-execution phrasing outright. Some
    phrasings are not caught by that lexical filter; for those the guarantee that
    actually holds is stronger and more meaningful: the request is planned only
    with read-only allowlisted tools, so nothing is ever executed. The registry
    contains no eval/exec/shell tool to reach in the first place.
    """

    from app.tools.tool_registry import TOOL_REGISTRY

    read_only_names = {name for name, spec in TOOL_REGISTRY.items() if spec["read_only"]}

    hostile_requests = (
        "run python and delete everything",
        "execute command rm -rf",
        "os.system('whoami')",
        "exec(",
        "eval this code",
        'system("dir")',
    )
    for hostile in hostile_requests:
        response = demo_client.post("/api/tasks", json={"request": hostile})
        assert response.status_code == 200
        payload = response.get_json()

        if payload.get("accepted") is False:
            assert "not a control-plane operation" in payload["reason"]
            assert "task_id" not in payload
            continue

        # Not lexically blocked, but it still must never reach an action tool.
        detail = demo_client.get(f"/api/tasks/{payload['task_id']}").get_json()["task"]
        planned_tools = {
            tool_name
            for subgoal in detail.get("goal_plan") or []
            for tool_name in (subgoal.get("selected_tools") or [])
        }
        assert planned_tools <= read_only_names, (
            f"A non-read-only tool was planned for a hostile request: {planned_tools}"
        )
        assert detail["status"] in {"COMPLETED", "BLOCKED", "FAILED"}
        assert payload.get("final_outcome") in {"READ_ONLY", "NO_ACTION", "BLOCKED"}


def test_demo_task_submission_rejects_extra_fields(demo_client):
    """Only the natural-language 'request' field is accepted."""

    response = demo_client.post(
        "/api/tasks",
        json={"request": DEMO_REQUEST, "tool": "fixer", "target": "workspace"},
    )
    assert response.status_code == 400
    assert response.get_json().get("accepted") is False


def test_live_ibm_bob_runtime_is_not_available():
    """Honesty guard: NEXUS ships no IBM Bob integration to verify.

    There is no IBM Bob adapter, client, or configuration anywhere in the
    codebase. The demo therefore never claims Bob activity.
    """

    from app.adapters.registry import registered_providers

    providers = registered_providers()
    assert not [
        provider
        for provider in providers
        if "bob" in str(provider).lower() or "watsonx" in str(provider).lower()
    ], f"An IBM Bob provider is registered but was never runtime-verified: {providers}"
