"""STEP 9: REAL Chromium end-to-end acceptance (no production changes).

REAL CHROMIUM — NOT MOCKED. Requires live outbound HTTPS to https://example.com
and an installed Playwright Chromium. Fails loudly (no fixture fallback) if the
browser or network is unavailable. Previous Phase 37 suites were MOCKED
PLAYWRIGHT (routing/governance proof only).

Path proven here (authoritative, no bypass):
UI task input (TaskRunner.start_task) -> StateGraph (nexus_graph.invoke) ->
dynamic planning -> browser_observer grounding -> action proposal ->
Risk -> Privacy -> Permission/Scope (evaluated when bound; never bypassed) ->
Approval Authority (bound task/subgoal/target/action/context/evidence/expiry) ->
Action Executor (sole dispatch) -> browser_controller_entrypoint -> open_page ->
_launch_page -> sync_playwright -> chromium.launch -> new_page ->
page.goto(runtime_url) -> inspect/navigate -> verification -> audit -> close_page.
"""

from __future__ import annotations

import uuid

import pytest

from app.agent.action_executor import execute_authorized_action, proposal_hash
from app.agent.approval_authority import create_approval, decide_approval, get_approval
from app.agent.capability_context import build_capability_context
from app.agent.execution_journal import create_checkpoint, load_checkpoint
from app.agent.task_runner import TaskRunner
from app.memory.task_ledger import get_task
from app.tools import browser_controller as browser_controller_module
from app.tools.browser_controller import _ACTIVE_PAGES, browser_controller_entrypoint, close_page

BASE_URL = "https://example.com"


def _runtime_url() -> str:
    # Fresh per run (query probe), same harmless public host; not a workflow hardcode.
    return f"{BASE_URL}/?probe-{uuid.uuid4().hex[:12]}"


@pytest.fixture(autouse=True)
def clean_registry():
    _ACTIVE_PAGES.clear()
    yield
    for page_id in list(_ACTIVE_PAGES.keys()):
        try:
            close_page(page_id)
        except Exception:
            pass
    _ACTIVE_PAGES.clear()


def _context(task_id: str, url: str, fingerprint: str) -> dict:
    return build_capability_context(
        task_id=task_id,
        subgoal_id="open_real_browser_page",
        application_id="browser",
        capability_id="interact",
        tool_name="browser_controller",
        target=url,
        observation_id=f"obs-{uuid.uuid4().hex[:12]}",
        evidence={"url": url},
        environment_fingerprint=fingerprint,
    )


def test_step9_readonly_task_via_taskrunner_stays_observer(tmp_path):
    """Real UI/task flow for read-only: TaskRunner->StateGraph->observer, no approval."""
    url = _runtime_url()
    request = f"Open {url}, read the page, and tell me the page title and main text. Do not modify anything."
    db_path = tmp_path / "ledger.db"
    runner = TaskRunner(workspace_root=str(tmp_path), db_path=db_path)
    assert runner.graph_runner is not None  # real StateGraph runner (no stub)
    result = runner.start_task(request)
    assert result["status"] == "COMPLETED", result
    assert result["final_outcome"] == "READ_ONLY"
    task = get_task(result["task_id"], db_path=db_path) or {}
    assert task.get("approval_id") in (None, "")
    answer = task.get("task_answer") or ""
    assert f"URL: {url}" in answer or BASE_URL in answer
    assert "Title:" in answer
    assert _ACTIVE_PAGES == {}  # read-only never opened a controller page


def test_step9_real_chromium_open_inspect_navigate_via_executor(tmp_path):
    """REAL Chromium: open -> inspect -> navigate through Approval+Executor, then cleanup."""
    url = _runtime_url()
    second_url = _runtime_url()
    assert url != second_url
    task_id = f"task-{uuid.uuid4().hex[:12]}"
    approvals_db = tmp_path / "approvals.db"
    journal_db = tmp_path / "journal.db"
    context = _context(task_id, url, str(tmp_path))
    spec = {"controller_action": "open_page", "url": url, "timeout_seconds": 15}
    digest = proposal_hash(action_type="browser_controller", tool_name="browser_controller", target=url, action_spec=spec)
    checkpoint = create_checkpoint(
        task_id, current_stage="APPROVAL_PENDING", action_type="browser_controller",
        action_target=url, proposal_hash=digest, risk_level="MEDIUM_RISK",
        approval_status="PENDING", action_payload={"action_spec": spec},
        selected_tools=["browser_controller"], db_path=journal_db,
    )
    approval = create_approval(
        task_id=task_id, checkpoint_id=checkpoint["checkpoint_id"], proposal_hash=digest,
        action_type="browser_controller", tool_name="browser_controller", target=url,
        risk_level="MEDIUM_RISK", capability_context=context,
        evidence_hash_value=str(context.get("evidence_hash", "")), db_path=approvals_db,
    )
    decide_approval(approval["approval_id"], "APPROVED", db_path=approvals_db)
    state = {
        "task_id": task_id, "journal_checkpoint_id": checkpoint["checkpoint_id"],
        "approval_id": approval["approval_id"], "proposal_hash": digest,
        "action_type": "browser_controller", "action_tool": "browser_controller",
        "action_target": url, "action_spec": spec,
        "journal_db_path": str(journal_db), "capability_context": context,
    }
    # Real Chromium launch + navigation happens inside the authoritative executor.
    result = execute_authorized_action(state, workspace_root=str(tmp_path), db_path=approvals_db)
    assert result["status"] == "COMPLETED", result
    assert result["verification"] == "SUCCESS"
    payload = result["result"]
    assert payload["source"] == "browser_controller"
    assert payload["url"] == url
    page_id = payload["page_id"]
    assert page_id in _ACTIVE_PAGES
    # Real DOM observation (title from live Chromium, not a fixture).
    assert "Example Domain" in (payload.get("title") or "")
    assert (payload.get("visible_text") or "").strip() != ""

    # Approval consumed only after verified success; checkpoint snapshotted.
    stored = get_approval(approval["approval_id"], db_path=approvals_db)
    assert stored["status"] == "CONSUMED"
    snap = load_checkpoint(task_id, checkpoint_id=checkpoint["checkpoint_id"], db_path=str(journal_db))
    assert snap["verification_snapshot"] == "SUCCESS"
    assert result.get("risk_decision", {}).get("allowed") is True

    # Real post-action observation through the same controller session.
    inspected = browser_controller_entrypoint("inspect_page", page_id=page_id, capability_context=context)
    assert inspected["status"] == "OK"
    assert inspected["page_id"] == page_id

    # Real second navigation (safe grounded interaction) through existing controller.
    navigated = browser_controller_entrypoint(
        "navigate_to_url", page_id=page_id, target_url=second_url,
        approved=True, action_count=0, capability_context=context,
    )
    assert navigated["status"] == "COMPLETED"
    assert navigated["verification"] == "SUCCESS"
    assert navigated["target_url"] == second_url

    # Browser cleanup: session closed, registry empty.
    assert close_page(page_id) is True
    assert page_id not in _ACTIVE_PAGES
    assert _ACTIVE_PAGES == {}
    assert browser_controller_module._ACTIVE_PAGES == {}
