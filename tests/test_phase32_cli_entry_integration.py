from __future__ import annotations

import subprocess
import sys
import uuid
from pathlib import Path

from app.agent.graph import nexus_graph


def test_phase32_browser_observer_invokes_and_drives_outcome(monkeypatch):
    calls = []

    def fake_execute_selected_tools(tool_names, **kwargs):
        calls.append({"tools": list(tool_names), "url": kwargs.get("url", "")})
        return [{
            "tool": "browser_observer",
            "status": "ok",
            "result": {"source": "browser", "status": "OK", "url": kwargs.get("url", "https://example.com"), "title": "Example Domain", "visible_text": "Example Domain page"},
        }]

    monkeypatch.setattr("app.agent.graph.execute_selected_tools", fake_execute_selected_tools)

    state = {
        "user_request": "Inspect https://example.com and report what is on the page.",
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
        "monitoring_active": False,
        "risk_decision": {},
        "audit_error": "",
        "browser_url": "",
        "normalized_evidence": [],
        "evidence_correlations": [],
        "evidence_conflicts": [],
        "reasoning_context": "",
        "decision_stage": "REQUEST",
        "decision_reason": "",
        "final_outcome": "",
        "user_constraints": {},
        "request_intent": "",
        "evidence_scope": "",
        "goal_plan": [],
        "goal_error": "",
        "task_id": f"task-browser-{uuid.uuid4().hex[:12]}",
        "task_status": "RUNNING",
        "task_resume_requested": False,
        "task_resume_reason": "",
        "task_context": "",
        "persistence_db_path": "data/test_phase32_cli_entry_integration.db",
        "journal_db_path": "data/test_phase32_cli_entry_integration.db",
        "approval_db_path": "data/test_phase32_cli_entry_integration.db",
        "environment_fingerprint": "phase32-browser-test",
        "autonomous_execution_enabled": True,
    }

    result = nexus_graph.invoke(state)

    assert calls and calls[0]["tools"] == ["browser_observer"]
    assert calls[0]["url"] == "https://example.com"
    assert any(item["tool"] == "browser_observer" for item in result.get("observation_results", []))
    assert result.get("final_outcome") != "NO_ACTION"
    assert "Example Domain" in str(result.get("reasoning_context") or "") or "Example Domain" in str(result.get("observation_results") or "")


def test_phase32_workspace_readonly_tool_invokes_and_captures_evidence(monkeypatch):
    calls = []

    def fake_execute_selected_tools(tool_names, **kwargs):
        calls.append(list(tool_names))
        return [{
            "tool": "workspace_inspector",
            "status": "ok",
            "result": "Workspace summary: 7 Python files detected.",
        }]

    monkeypatch.setattr("app.agent.graph.execute_selected_tools", fake_execute_selected_tools)

    state = {
        "user_request": "Inspect my workspace and summarize the Python files.",
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
        "monitoring_active": False,
        "risk_decision": {},
        "audit_error": "",
        "browser_url": "",
        "normalized_evidence": [],
        "evidence_correlations": [],
        "evidence_conflicts": [],
        "reasoning_context": "",
        "decision_stage": "REQUEST",
        "decision_reason": "",
        "final_outcome": "",
        "user_constraints": {},
        "request_intent": "",
        "evidence_scope": "",
        "goal_plan": [],
        "goal_error": "",
        "task_id": f"task-workspace-{uuid.uuid4().hex[:12]}",
        "task_status": "RUNNING",
        "task_resume_requested": False,
        "task_resume_reason": "",
        "task_context": "",
        "persistence_db_path": "data/test_phase32_cli_entry_integration.db",
        "journal_db_path": "data/test_phase32_cli_entry_integration.db",
        "approval_db_path": "data/test_phase32_cli_entry_integration.db",
        "environment_fingerprint": "phase32-workspace-test",
        "autonomous_execution_enabled": True,
    }

    result = nexus_graph.invoke(state)

    assert calls and calls[0] == ["workspace_inspector"]
    assert any(item["tool"] == "workspace_inspector" for item in result.get("observation_results", []))
    assert "Workspace summary" in str(result.get("reasoning_context") or "")


def test_phase32_main_uses_durable_task_runner_entry_path():
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [sys.executable, "main.py"],
        input="open youtube in chrome\n",
        text=True,
        capture_output=True,
        cwd=root,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    output = completed.stdout
    assert '"task_id": "task-' in output
    assert '"current_stage"' in output
    assert '"final_outcome"' in output
    assert '"current_sub_goal"' in output
    assert "Selected Tool:" not in output
    assert "workspace_inspector" not in output.lower()


def test_phase32_workspace_git_request_executes_git_subgoal():
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [sys.executable, "main.py"],
        input="Inspect my workspace, check Git status, and prepare a short submission-readiness summary.\n",
        text=True,
        capture_output=True,
        cwd=root,
        timeout=120,
    )

    assert completed.returncode == 0, completed.stderr
    output = completed.stdout
    assert "Phase 32 subgoal: inspect_workspace" in output
    assert "Phase 32 subgoal: inspect_git_status" in output
    assert "Phase 32 selected tools: ['git_inspector']" in output
    assert "Phase 32 verification: SUCCESS" in output
    assert '"status": "COMPLETED"' in output
    assert '"final_outcome": "READ_ONLY"' in output
