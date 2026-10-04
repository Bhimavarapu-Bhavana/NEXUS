"""Grounded browser link selection tests.

The user names a link ("find the About link and open it"). NEXUS must resolve
that name against the observed links only, use the real observed index, and
fail closed when the named target is absent instead of substituting an
unrelated observed link. Requests that name no link keep the existing
first-observed-link behavior. Every assertion runs against the existing
StateGraph proposal node and the existing approval/executor chain.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.agent.action_executor import execute_authorized_action, proposal_hash
from app.agent.approval_authority import create_approval, decide_approval, list_pending_approvals
from app.agent.execution_journal import create_checkpoint
from app.agent.graph import (
    _requested_link_labels,
    create_action_proposal,
    extract_requested_url,
)
from app.agent.task_runner import TaskRunner
from app.memory.task_ledger import create_task
from app.tools import browser_actions as browser_actions_mod
from app.tools.browser_actions import _validate_structured_action
from app.tools.tool_registry import TOOL_REGISTRY

HOME_PAGE = {
    "source": "browser",
    "status": "OK",
    "url": "https://example.com",
    "final_url": "https://example.com",
    "title": "Example Domain",
    "links": [
        {"url": "https://example.com/", "text": "Home"},
        {"url": "https://example.com/about", "text": "About"},
        {"url": "https://example.com/docs", "text": "Documentation"},
    ],
    "headings": ["Example Domain"],
    "visible_text": "This domain is for use in illustrative examples in documents.",
}

ABOUT_PAGE = {
    "source": "browser",
    "status": "OK",
    "url": "https://example.com/about",
    "final_url": "https://example.com/about",
    "title": "About Example Domain",
    "links": [{"url": "https://example.com/", "text": "Home"}],
    "headings": ["About Example Domain"],
    "visible_text": "About this illustrative example domain and its reserved names.",
}


def _fake_observer(url, timeout_seconds=None):
    target = str(url or "")
    if "/about" in target:
        return ABOUT_PAGE
    return HOME_PAGE


def _patch_browser_observers(monkeypatch):
    monkeypatch.setattr(browser_actions_mod, "record_audit_event", lambda *args, **kwargs: True)
    monkeypatch.setattr(browser_actions_mod, "validate_browser_url", lambda url: str(url).split("#", 1)[0])
    monkeypatch.setattr(browser_actions_mod, "observe_browser_page", _fake_observer)
    monkeypatch.setitem(TOOL_REGISTRY["browser_observer"], "function", _fake_observer)
    from app.agent import graph as graph_mod

    monkeypatch.setattr(graph_mod, "record_audit_event", lambda *args, **kwargs: True)
    monkeypatch.setattr(graph_mod, "observe_browser_page", _fake_observer)
    return graph_mod


def _browser_state(request, *, task_id=""):
    return {
        "user_request": request,
        "observations": [],
        "priority": "",
        "selected_tool": "",
        "investigation": [],
        "plan": [],
        "target_file": "",
        "old_code": "",
        "new_code": "",
        "approval_required": False,
        "approved": False,
        "approval_override": "",
        "action_result": "",
        "verification": "",
        "retry_count": 0,
        "verification_history": [],
        "last_verification": "",
        "memory_context": "",
        "selected_tools": [],
        "selected_files": [],
        "observation_results": [{"tool": "browser_observer", "status": "ok", "result": HOME_PAGE}],
        "action_tool": "",
        "action_spec": {},
        "action_target": "",
        "action_type": "",
        "approval_id": "",
        "journal_checkpoint_id": "",
        "proposal_hash": "",
        "execution_id": "",
        "tool_results": [],
        "workspace_event": "",
        "monitoring_active": True,
        "decision_stage": "REQUEST",
        "decision_reason": "",
        "final_outcome": "",
        "risk_decision": {},
        "audit_error": "",
        "browser_url": extract_requested_url(request),
        "request_intent": "BROWSER_ACTION_REQUEST",
        "normalized_evidence": [],
        "evidence_correlations": [],
        "evidence_conflicts": [],
        "reasoning_context": "",
        "goal_plan": [],
        "goal_error": "",
        "task_id": task_id,
        "task_status": "",
        "task_resume_requested": False,
        "task_resume_reason": "",
        "task_context": "",
        "persistence_db_path": "",
        "journal_db_path": "",
        "approval_db_path": "",
        "autonomous_execution_enabled": True,
        "capability_context": {},
        "user_constraints": {},
    }


def _proposal(request, monkeypatch):
    _patch_browser_observers(monkeypatch)
    return create_action_proposal(_browser_state(request))


# ---------------------------------------------------------------------------
# Named target resolution
# ---------------------------------------------------------------------------


def test_named_link_that_is_not_first_uses_its_real_index(monkeypatch):
    result = _proposal("Open https://example.com and find the About link on this page and open it.", monkeypatch)
    assert result["action_tool"] == "browser_follow_observed_link"
    assert result["action_target"] == "https://example.com/about"
    assert result["action_spec"]["target_url"] == "https://example.com/about"
    assert result["action_spec"]["element_identifier"] == "link:1"
    assert result["action_spec"]["observed_target"] == "https://example.com"
    assert result["approval_required"] is True
    assert result["approved"] is False


def test_named_section_link_resolves_by_observed_text(monkeypatch):
    result = _proposal("Open https://example.com and navigate to the documentation section.", monkeypatch)
    assert result["action_tool"] == "browser_follow_observed_link"
    assert result["action_target"] == "https://example.com/docs"
    assert result["action_spec"]["element_identifier"] == "link:2"


def test_quoted_link_label_is_resolved(monkeypatch):
    result = _proposal('Open https://example.com and click the "Documentation" link.', monkeypatch)
    assert result["action_target"] == "https://example.com/docs"
    assert result["action_spec"]["element_identifier"] == "link:2"


def test_absent_named_target_fails_closed_without_link_invention(monkeypatch):
    result = _proposal("Open https://example.com and navigate to the installation section.", monkeypatch)
    assert result["final_outcome"] == "NO_ACTION"
    assert result["action_tool"] == ""
    assert result["action_target"] == ""
    assert result["action_spec"] == {}
    assert result["approved"] is False
    assert "installation" in result["decision_reason"]
    assert "no link was invented" in result["decision_reason"]


def test_absent_named_target_never_falls_back_to_first_link(monkeypatch):
    for request in (
        "Open https://example.com and navigate to the installation section.",
        "Open https://example.com and click the pricing link.",
        'Open https://example.com and open the "Terms of Service" link.',
    ):
        result = _proposal(request, monkeypatch)
        assert result["action_tool"] == "", request
        assert result["action_target"] != "https://example.com/", request


def test_ambiguous_named_targets_fail_closed(monkeypatch):
    result = _proposal("Open https://example.com and open the About link and then the Documentation link.", monkeypatch)
    assert result["final_outcome"] == "NO_ACTION"
    assert result["action_tool"] == ""


# ---------------------------------------------------------------------------
# Preserved behavior when no link target is named
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "user_request",
    [
        "Open https://example.com and navigate using only a link you actually observe. Ask for approval before taking the navigation action.",
        "Open https://example.com and click the first link you observe. Ask for approval.",
        "Navigate using an observed link. Ask for approval before taking the navigation action.",
        "Open https://example.com and follow the first link you observe.",
        "Open https://example.com and go to the link you observe.",
    ],
)
def test_requests_without_a_named_link_keep_first_observed_link(user_request, monkeypatch):
    result = _proposal(user_request, monkeypatch)
    assert result["action_tool"] == "browser_follow_observed_link"
    assert result["action_target"] == "https://example.com/"
    assert result["action_spec"]["element_identifier"] == "link:0"


def test_read_only_request_stays_read_only(monkeypatch):
    result = _proposal("Open https://example.com and tell me what is on the page.", monkeypatch)
    assert result["final_outcome"] == "NO_ACTION"
    assert result["action_tool"] == ""
    assert result["approval_required"] is False


def test_generic_wording_yields_no_specific_label():
    assert _requested_link_labels("navigate using only a link you actually observe") == []
    assert _requested_link_labels("click the first link you observe") == []
    assert _requested_link_labels("Navigate using an observed link.") == []
    assert _requested_link_labels("open https://example.com and go to the link you observe") == []
    assert _requested_link_labels("navigate to the next page") == []
    assert _requested_link_labels("tell me what is on the page") == []
    assert _requested_link_labels("find the About link on this page and open it") == ["about"]
    assert _requested_link_labels('click the "Documentation" link') == ["documentation"]
    assert _requested_link_labels("navigate to the installation section") == ["installation"]


# ---------------------------------------------------------------------------
# Security path is unchanged and still closed
# ---------------------------------------------------------------------------


def test_fail_closed_named_target_creates_no_approval(tmp_path, monkeypatch):
    _patch_browser_observers(monkeypatch)
    task_id = "task-named-link-absent"
    create_task("Navigate to a section that is not present.", task_id=task_id, current_stage="REQUEST", status="RUNNING", db_path=tmp_path / "ledger.db")
    state = _browser_state("Open https://example.com and navigate to the installation section.", task_id=task_id)
    state["persistence_db_path"] = str(tmp_path / "ledger.db")
    state["journal_db_path"] = str(tmp_path / "journal.db")
    state["approval_db_path"] = str(tmp_path / "approvals.db")
    result = create_action_proposal(state)
    assert result["final_outcome"] == "NO_ACTION"
    assert result["approval_id"] == ""
    assert result["journal_checkpoint_id"] == ""
    assert list_pending_approvals(db_path=tmp_path / "approvals.db") == []


def test_named_link_identifier_is_accepted_only_when_observed():
    with pytest.raises(ValueError):
        _validate_structured_action(
            {
                "action_type": "follow_observed_link",
                "element_identifier": "link:9",
                "observed_target": "https://example.com",
                "target_url": "https://example.com/about",
            },
            HOME_PAGE,
            "follow_observed_link",
        )
    with pytest.raises(ValueError):
        _validate_structured_action(
            {
                "action_type": "follow_observed_link",
                "element_identifier": "link:1",
                "observed_target": "https://example.com",
                "target_url": "https://example.com/contact",
            },
            HOME_PAGE,
            "follow_observed_link",
        )
    observed, target = _validate_structured_action(
        {
            "action_type": "follow_observed_link",
            "element_identifier": "link:1",
            "observed_target": "https://example.com",
            "target_url": "https://example.com/about",
        },
        HOME_PAGE,
        "follow_observed_link",
    )
    assert observed == "https://example.com"
    assert target == "https://example.com/about"


# ---------------------------------------------------------------------------
# Approved execution follows the named link
# ---------------------------------------------------------------------------


def test_approved_execution_follows_the_named_link(tmp_path, monkeypatch):
    _patch_browser_observers(monkeypatch)
    task_id = "task-named-link-exec"
    spec = {
        "action_type": "follow_observed_link",
        "element_identifier": "link:1",
        "observed_target": "https://example.com",
        "target_url": "https://example.com/about",
    }
    digest = proposal_hash(action_type="browser_follow_observed_link", tool_name="browser_follow_observed_link", target="https://example.com/about", old_code="", new_code="", action_spec=spec)
    checkpoint = create_checkpoint(task_id, current_stage="APPROVAL_PENDING", action_type="browser_follow_observed_link", action_target="https://example.com/about", proposal_hash=digest, risk_level="MEDIUM_RISK", approval_status="PENDING", db_path=tmp_path / "journal.db")
    approval = create_approval(task_id=task_id, checkpoint_id=checkpoint["checkpoint_id"], proposal_hash=digest, action_type="browser_follow_observed_link", tool_name="browser_follow_observed_link", target="https://example.com/about", risk_level="MEDIUM_RISK", db_path=tmp_path / "approvals.db")
    decide_approval(approval["approval_id"], "APPROVED", db_path=tmp_path / "approvals.db")
    execution = execute_authorized_action(
        {
            "task_id": task_id,
            "journal_checkpoint_id": checkpoint["checkpoint_id"],
            "approval_id": approval["approval_id"],
            "proposal_hash": digest,
            "action_type": "browser_follow_observed_link",
            "action_tool": "browser_follow_observed_link",
            "action_target": "https://example.com/about",
            "action_spec": spec,
            "journal_db_path": str(tmp_path / "journal.db"),
            "approval_db_path": str(tmp_path / "approvals.db"),
            "persistence_db_path": str(tmp_path / "ledger.db"),
            "observation_results": [{"tool": "browser_observer", "status": "ok", "result": HOME_PAGE}],
            "browser_revalidator": lambda: HOME_PAGE,
            "capability_context": {},
            "approved": True,
            "approval_required": False,
            "audit_error": "",
            "environment_fingerprint": "workspace",
        },
        db_path=tmp_path / "approvals.db",
    )
    assert execution["status"] == "COMPLETED"
    assert execution["verification"] == "SUCCESS"
    assert execution["result"]["target_url"] == "https://example.com/about"
    assert execution["result"]["post_action_observation"]["final_url"] == "https://example.com/about"


def test_end_to_end_named_link_reports_the_followed_page(tmp_path, monkeypatch):
    _patch_browser_observers(monkeypatch)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runner = TaskRunner(workspace_root=str(workspace), db_path=tmp_path / "runner.db")
    result = runner.start_task(
        "Open https://example.com and find the About link on this page and open it.",
        current_state={"approval_override": "APPROVED"},
    )
    assert result["status"] == "COMPLETED"
    assert result["final_outcome"] == "SUCCESS"
    answer = result["task_answer"]
    assert "https://example.com/about" in answer
    assert "About Example Domain" in answer


def test_end_to_end_absent_named_target_never_navigates(tmp_path, monkeypatch):
    _patch_browser_observers(monkeypatch)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runner = TaskRunner(workspace_root=str(workspace), db_path=tmp_path / "runner.db")
    result = runner.start_task(
        "Open https://example.com and navigate to the installation section.",
        current_state={"approval_override": "APPROVED"},
    )
    assert result["status"] != "COMPLETED" or result["final_outcome"] != "SUCCESS"
    from app.memory.task_ledger import get_task

    task = get_task(result["task_id"], db_path=tmp_path / "runner.db")
    assert "https://example.com/about" not in (task["task_answer"] or "")