"""Browser link-approval flow tests.

Covers the approval-gated, revalidated follow-observed-link capability:

- follow proposals are grounded to the FIRST observed link (never invented)
- observations required before a proposal; a deferred bridge fills the gap
- read-only explicit-URL observation requests stay read-only
- approval is required, and rejected/consumed/expired lineage fails closed
- the approved browser action revalidates the observed page, follows only the
  observed link, records the followed page, and persists it as task_answer
- "Open YouTube" behavior is unchanged; no arbitrary execution endpoint;
  SSRF protections remain active
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.agent.action_executor import execute_authorized_action, proposal_hash
from app.agent.approval_authority import create_approval, decide_approval
from app.agent.execution_journal import create_checkpoint
from app.agent.graph import create_action_proposal, extract_requested_url, request_approval
from app.agent.task_runner import TaskRunner, _build_task_answer
from app.control_plane import ControlPlane
from app.memory.task_ledger import create_task, get_task, update_task_status
from app.security.sensitive_data import REDACTION_MARKER
from app.tools import browser_actions as browser_actions_mod
from app.tools.browser_observer import validate_browser_url
from app.tools.tool_registry import TOOL_REGISTRY

EXAMPLE_PAGE = {
    "source": "browser",
    "status": "OK",
    "url": "https://example.com",
    "final_url": "https://example.com",
    "title": "Example Domain",
    "links": [{"url": "https://www.iana.org/domains/example", "text": "More information..."}],
    "headings": ["Example Domain"],
    "visible_text": "This domain is for use in illustrative examples in documents.",
}

IANA_PAGE = {
    "source": "browser",
    "status": "OK",
    "url": "https://www.iana.org/domains/example",
    "final_url": "https://www.iana.org/domains/example",
    "title": "IANA-managed Reserved Domains",
    "links": [{"url": "https://www.iana.org/domains", "text": "Domains"}],
    "headings": ["Example domains"],
    "visible_text": "These domains are reserved for illustrative examples in documents.",
}

CHANGED_PAGE = {
    "source": "browser",
    "status": "OK",
    "url": "https://example.com",
    "final_url": "https://example.com",
    "title": "Example Domain (changed)",
    "links": [{"url": "https://www.iana.org/something/else", "text": "Unrelated"}],
    "headings": ["Example Domain"],
    "visible_text": "The observed link is no longer present.",
}


def _fake_observer(url, timeout_seconds=None):
    target = str(url or "")
    if "iana.org" in target:
        return IANA_PAGE
    return EXAMPLE_PAGE


def _browser_state(request, *, task_id="", approval_override=""):
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
        "approval_override": approval_override,
        "action_result": "",
        "verification": "",
        "retry_count": 0,
        "verification_history": [],
        "last_verification": "",
        "memory_context": "",
        "selected_tools": [],
        "selected_files": [],
        "observation_results": [],
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


def _patch_browser_observers(monkeypatch):
    monkeypatch.setattr(browser_actions_mod, "record_audit_event", lambda *args, **kwargs: True)
    monkeypatch.setattr(browser_actions_mod, "validate_browser_url", lambda url: str(url).split("#", 1)[0])
    monkeypatch.setattr(browser_actions_mod, "observe_browser_page", _fake_observer)
    monkeypatch.setitem(TOOL_REGISTRY["browser_observer"], "function", _fake_observer)
    from app.agent import graph as graph_mod

    monkeypatch.setattr(graph_mod, "record_audit_event", lambda *args, **kwargs: True)
    monkeypatch.setattr(graph_mod, "observe_browser_page", _fake_observer)
    return graph_mod


def _proposal_state(request, monkeypatch, task_id=""):
    _patch_browser_observers(monkeypatch)
    return _browser_state(request, task_id=task_id)


# ---------------------------------------------------------------------------
# Grounded proposal
# ---------------------------------------------------------------------------


def test_follow_link_is_grounded_to_first_observed_link(monkeypatch):
    request = "Open https://example.com and navigate using only a link you actually observe. Ask for approval before taking the navigation action."
    state = _proposal_state(request, monkeypatch)
    state["observation_results"] = [{"tool": "browser_observer", "status": "ok", "result": EXAMPLE_PAGE}]
    result = create_action_proposal(state)
    assert result["action_tool"] == "browser_follow_observed_link"
    assert result["action_target"] == "https://www.iana.org/domains/example"
    assert result["action_spec"]["target_url"] == "https://www.iana.org/domains/example"
    assert result["action_spec"]["observed_target"] == "https://example.com"
    assert result["approval_required"] is True
    assert result["approved"] is False
    assert result["risk_decision"]["risk_level"] in {"MEDIUM_RISK", "HIGH_RISK"}


def test_follow_proposal_fails_closed_without_observed_link(monkeypatch):
    state = _proposal_state("Navigate using an observed link.", monkeypatch)
    state["observation_results"] = [{"tool": "browser_observer", "status": "ok", "result": {**EXAMPLE_PAGE, "links": []}}]
    result = create_action_proposal(state)
    assert result["final_outcome"] == "NO_ACTION"
    assert result["action_tool"] == ""


def test_follow_proposal_fails_closed_without_successful_observation(monkeypatch):
    state = _browser_state("Navigate using an observed link.", approval_override="")
    state["browser_url"] = ""
    result = create_action_proposal(state)
    assert result["final_outcome"] == "NO_ACTION"
    assert result["action_tool"] == ""


def test_deferred_bridge_grounds_proposal_from_fresh_observation(monkeypatch):
    graph_mod = _patch_browser_observers(monkeypatch)
    state = _browser_state("Open https://example.com and click the first link you observe. Ask for approval.")
    result = create_action_proposal(state)
    assert result["action_tool"] == "browser_follow_observed_link"
    assert result["action_target"] == "https://www.iana.org/domains/example"
    assert result["observation_results"] and result["observation_results"][-1]["tool"] == "browser_observer"
    assert graph_mod.execute_selected_tools is not None


def test_read_only_explicit_url_observation_remains_read_only(monkeypatch):
    youtube = {**EXAMPLE_PAGE, "url": "https://www.youtube.com", "final_url": "https://www.youtube.com", "links": [{"url": "https://www.youtube.com/watch?v=abc", "text": "A video"}]}
    state = _proposal_state("Observe https://www.youtube.com and report what it contains. Do not modify anything.", monkeypatch)
    state["request_intent"] = "BROWSER_ACTION_REQUEST"
    state["observation_results"] = [{"tool": "browser_observer", "status": "ok", "result": youtube}]
    result = create_action_proposal(state)
    assert result["final_outcome"] == "NO_ACTION"
    assert result["action_tool"] == ""
    assert result["approval_required"] is False


# ---------------------------------------------------------------------------
# Approval boundary
# ---------------------------------------------------------------------------


def test_approval_is_required_before_any_navigation(monkeypatch):
    state = _proposal_state("Navigate using an observed link.", monkeypatch)
    state["observation_results"] = [{"tool": "browser_observer", "status": "ok", "result": EXAMPLE_PAGE}]
    proposed = create_action_proposal(state)
    decided = request_approval(proposed)
    assert decided["approved"] is False
    assert decided["final_outcome"] in {"APPROVAL_REQUIRED", "APPROVAL_PENDING"}


def test_rejected_approval_fails_closed_without_navigation_or_new_approval(tmp_path, monkeypatch):
    _patch_browser_observers(monkeypatch)
    task_id = "task-browser-reject"
    spec = {
        "action_type": "follow_observed_link",
        "element_identifier": "link:0",
        "observed_target": "https://example.com",
        "target_url": "https://www.iana.org/domains/example",
    }
    digest = proposal_hash(action_type="browser_follow_observed_link", tool_name="browser_follow_observed_link", target="https://www.iana.org/domains/example", old_code="", new_code="", action_spec=spec)
    checkpoint = create_checkpoint(task_id, current_stage="APPROVAL_PENDING", action_type="browser_follow_observed_link", action_target="https://www.iana.org/domains/example", proposal_hash=digest, risk_level="MEDIUM_RISK", approval_status="PENDING", db_path=tmp_path / "journal.db")
    approval = create_approval(task_id=task_id, checkpoint_id=checkpoint["checkpoint_id"], proposal_hash=digest, action_type="browser_follow_observed_link", tool_name="browser_follow_observed_link", target="https://www.iana.org/domains/example", risk_level="MEDIUM_RISK", db_path=tmp_path / "approvals.db")
    decide_approval(approval["approval_id"], "REJECTED", db_path=tmp_path / "approvals.db")
    create_task(
        "Follow the first observed link after a rejected approval.",
        task_id=task_id,
        current_stage="APPROVAL_PENDING",
        status="WAITING_APPROVAL",
        db_path=tmp_path / "ledger.db",
    )
    update_task_status(
        task_id,
        "WAITING_APPROVAL",
        action_lineage={"checkpoint_id": checkpoint["checkpoint_id"], "proposal_hash": digest, "action_type": "browser_follow_observed_link", "tool_name": "browser_follow_observed_link", "target": "https://www.iana.org/domains/example", "risk_level": "MEDIUM_RISK"},
        approval_lineage=approval,
        db_path=tmp_path / "ledger.db",
    )
    state = _browser_state("Open https://example.com and follow the first link you observe.", task_id=task_id)
    state["persistence_db_path"] = str(tmp_path / "ledger.db")
    state["journal_db_path"] = str(tmp_path / "journal.db")
    state["approval_db_path"] = str(tmp_path / "approvals.db")
    state["browser_url"] = "https://example.com"
    state["observation_results"] = [{"tool": "browser_observer", "status": "ok", "result": EXAMPLE_PAGE}]
    result = create_action_proposal(state)
    assert result["action_tool"] == "browser_follow_observed_link"
    assert result["final_outcome"] == "APPROVAL_REJECTED"
    assert result["approved"] is False
    assert result.get("approval_id") == ""
    from app.agent.approval_authority import list_pending_approvals

    pending = list_pending_approvals(db_path=tmp_path / "approvals.db")
    assert all(item["approval_id"] != approval["approval_id"] for item in pending)


def test_stale_or_changed_observation_blocks_execution(tmp_path, monkeypatch):
    _patch_browser_observers(monkeypatch)
    task_id = "task-browser-stale"
    spec = {
        "action_type": "follow_observed_link",
        "element_identifier": "link:0",
        "observed_target": "https://example.com",
        "target_url": "https://www.iana.org/domains/example",
    }
    digest = proposal_hash(action_type="browser_follow_observed_link", tool_name="browser_follow_observed_link", target="https://www.iana.org/domains/example", old_code="", new_code="", action_spec=spec)
    checkpoint = create_checkpoint(task_id, current_stage="APPROVAL_PENDING", action_type="browser_follow_observed_link", action_target="https://www.iana.org/domains/example", proposal_hash=digest, risk_level="MEDIUM_RISK", approval_status="PENDING", db_path=tmp_path / "journal.db")
    approval = create_approval(task_id=task_id, checkpoint_id=checkpoint["checkpoint_id"], proposal_hash=digest, action_type="browser_follow_observed_link", tool_name="browser_follow_observed_link", target="https://www.iana.org/domains/example", risk_level="MEDIUM_RISK", db_path=tmp_path / "approvals.db")
    decide_approval(approval["approval_id"], "APPROVED", db_path=tmp_path / "approvals.db")
    state = {
        "task_id": task_id,
        "journal_checkpoint_id": checkpoint["checkpoint_id"],
        "approval_id": approval["approval_id"],
        "proposal_hash": digest,
        "action_type": "browser_follow_observed_link",
        "action_tool": "browser_follow_observed_link",
        "action_target": "https://www.iana.org/domains/example",
        "action_spec": spec,
        "journal_db_path": str(tmp_path / "journal.db"),
        "approval_db_path": str(tmp_path / "approvals.db"),
        "persistence_db_path": str(tmp_path / "ledger.db"),
        "observation_results": [{"tool": "browser_observer", "status": "ok", "result": EXAMPLE_PAGE}],
        "browser_revalidator": lambda: CHANGED_PAGE,
        "capability_context": {},
        "approved": True,
        "approval_required": False,
        "audit_error": "",
        "environment_fingerprint": "workspace",
    }
    execution = execute_authorized_action(state, db_path=tmp_path / "approvals.db")
    assert execution["status"] == "VERIFICATION_FAILED"
    assert "not present" in str(execution.get("result", "")) or "changed" in str(execution.get("result", "")).lower()
    assert execution.get("post_action_observation") is None


def test_consumed_approval_blocks_resume_without_navigation(tmp_path, monkeypatch):
    _patch_browser_observers(monkeypatch)
    from app.agent.approval_authority import claim_approval, consume_approval

    task_id = "task-browser-consumed"
    spec = {
        "action_type": "follow_observed_link",
        "element_identifier": "link:0",
        "observed_target": "https://example.com",
        "target_url": "https://www.iana.org/domains/example",
    }
    digest = proposal_hash(action_type="browser_follow_observed_link", tool_name="browser_follow_observed_link", target="https://www.iana.org/domains/example", old_code="", new_code="", action_spec=spec)
    checkpoint = create_checkpoint(task_id, current_stage="APPROVAL_PENDING", action_type="browser_follow_observed_link", action_target="https://www.iana.org/domains/example", proposal_hash=digest, risk_level="MEDIUM_RISK", approval_status="PENDING", db_path=tmp_path / "journal.db")
    approval = create_approval(task_id=task_id, checkpoint_id=checkpoint["checkpoint_id"], proposal_hash=digest, action_type="browser_follow_observed_link", tool_name="browser_follow_observed_link", target="https://www.iana.org/domains/example", risk_level="MEDIUM_RISK", db_path=tmp_path / "approvals.db")
    decide_approval(approval["approval_id"], "APPROVED", db_path=tmp_path / "approvals.db")
    claim_approval(approval["approval_id"], db_path=tmp_path / "approvals.db")
    consume_approval(approval["approval_id"], db_path=tmp_path / "approvals.db")
    create_task(
        "Follow the first observed link after a consumed approval.",
        task_id=task_id,
        current_stage="APPROVAL_PENDING",
        status="WAITING_APPROVAL",
        db_path=tmp_path / "ledger.db",
    )
    update_task_status(
        task_id,
        "WAITING_APPROVAL",
        action_lineage={"checkpoint_id": checkpoint["checkpoint_id"], "proposal_hash": digest, "action_type": "browser_follow_observed_link", "tool_name": "browser_follow_observed_link", "target": "https://www.iana.org/domains/example", "risk_level": "MEDIUM_RISK"},
        approval_lineage=approval,
        db_path=tmp_path / "ledger.db",
    )
    state = _browser_state("Open https://example.com and go to the link you observe.", task_id=task_id)
    state["persistence_db_path"] = str(tmp_path / "ledger.db")
    state["journal_db_path"] = str(tmp_path / "journal.db")
    state["approval_db_path"] = str(tmp_path / "approvals.db")
    state["browser_url"] = "https://example.com"
    state["observation_results"] = [{"tool": "browser_observer", "status": "ok", "result": EXAMPLE_PAGE}]
    result = create_action_proposal(state)
    assert result["final_outcome"] == "BLOCKED"
    assert result["approved"] is False


# ---------------------------------------------------------------------------
# Approved execution + durable result
# ---------------------------------------------------------------------------


def test_approved_follow_executes_and_persists_followed_page(tmp_path, monkeypatch):
    _patch_browser_observers(monkeypatch)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runner = TaskRunner(workspace_root=str(workspace), db_path=tmp_path / "runner.db")
    request = "Open https://example.com and navigate using only a link you actually observe. Ask for approval before taking the navigation action."
    result = runner.start_task(request, current_state={"approval_override": "APPROVED"})
    assert result["status"] == "COMPLETED"
    assert result["final_outcome"] == "SUCCESS"
    task = get_task(result["task_id"], db_path=tmp_path / "runner.db")
    assert task["task_answer"]
    assert "reserved" in task["task_answer"].lower() or "iana" in task["task_answer"].lower()


def test_task_answer_prefers_followed_page_over_later_reobservation():
    state = {
        "browser_action_result": {
            "source": "browser_action",
            "status": "COMPLETED",
            "approved": True,
            "post_action_observation": {**IANA_PAGE, "status": "OK"},
        },
        "observation_results": [{"tool": "browser_observer", "status": "ok", "result": EXAMPLE_PAGE}],
    }
    answer = _build_task_answer(state)
    assert "reserved" in answer.lower()
    assert "iana.org" in answer
    assert "example" not in answer.lower() or "reserved" in answer.lower()


def test_followed_page_secrets_are_redacted():
    leaky = {**IANA_PAGE, "visible_text": "Login at https://x with Authorization: Bearer supersecrettoken123 now."}
    state = {
        "browser_action_result": {
            "source": "browser_action",
            "status": "COMPLETED",
            "post_action_observation": {**leaky, "status": "OK"},
        }
    }
    answer = _build_task_answer(state)
    assert "supersecrettoken123" not in answer
    assert REDACTION_MARKER in answer


# ---------------------------------------------------------------------------
# Preserved behavior
# ---------------------------------------------------------------------------


def test_open_youtube_still_requires_explicit_target(tmp_path, monkeypatch):
    _patch_browser_observers(monkeypatch)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runner = TaskRunner(workspace_root=str(workspace), db_path=tmp_path / "runner.db")
    result = runner.start_task("Open YouTube")
    assert result["final_outcome"] in {"BLOCKED", "HUMAN_REQUIRED"}
    assert "explicit public HTTP(S) target" in (result.get("task_answer") or "")


def test_no_arbitrary_execution_endpoint_and_ssrf_protections(tmp_path, monkeypatch):
    _patch_browser_observers(monkeypatch)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runner = TaskRunner(workspace_root=str(workspace), db_path=tmp_path / "cp.db")
    cp = ControlPlane(workspace_root=str(workspace), db_path=tmp_path / "cp.db", task_runner=runner)
    cp.lifecycle("START")
    denied = cp.submit("Run the following shell command: rm -rf /")
    assert denied["accepted"] is False
    assert "arbitrary" in denied["reason"].lower() or "execute" in denied["reason"].lower()
    assert "browser_action" not in TOOL_REGISTRY
    assert "shell" not in TOOL_REGISTRY
    assert "execute_command" not in TOOL_REGISTRY
    for blocked_url in ("http://169.254.169.254/latest/meta-data", "http://localhost:8000", "http://10.0.0.1/"):
        with pytest.raises(ValueError):
            validate_browser_url(blocked_url)