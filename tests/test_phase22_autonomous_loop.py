from app.agent.evidence import build_reasoning_context, correlate_evidence, normalize_tool_results
from app.agent.graph import MAX_RETRIES, create_proposal, evaluate_verification, nexus_graph, request_approval, should_retry_verification
from app.security.audit_logger import get_recent_audit_events, record_audit_event
from app.security.risk_engine import BLOCKED, evaluate_risk
from app.security.sensitive_data import redact_sensitive_data
from app.tools.tool_registry import get_trusted_tool_plan


def _state(**overrides):
    state = {
        "user_request": "Inspect the workspace and identify any Python issues without changing code.",
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
        "action_result": "",
        "verification": "",
        "retry_count": 0,
        "verification_history": [],
        "last_verification": "",
        "memory_context": "",
        "selected_tools": [],
        "tool_results": [],
        "workspace_event": "",
        "monitoring_active": True,
        "decision_stage": "REQUEST",
        "decision_reason": "",
        "final_outcome": "",
    }
    state.update(overrides)
    return state


def test_phase22_read_only_decision_loop_sets_explicit_stage_and_outcome():
    result = nexus_graph.invoke(_state())

    assert result["decision_stage"] == "FINAL_OUTCOME"
    assert result["final_outcome"] in {"READ_ONLY", "NO_ACTION", "SUCCESS"}
    assert result["decision_reason"]


def test_phase22_allowlisted_tool_plan_and_multi_source_evidence_are_deterministic():
    request = "Inspect my workspace for runtime and syntax issues. Do not modify anything."
    plan = get_trusted_tool_plan(request)

    assert plan
    assert all(tool in {"runtime_inspector", "error_detector", "workspace_inspector", "relevant_file_selector"} for tool in plan)

    evidence = normalize_tool_results([
        {"tool": "runtime_inspector", "result": "STATUS: SUCCESS\nworkspace check complete"},
        {"tool": "error_detector", "result": "No Python syntax errors detected."},
    ])
    correlation = correlate_evidence(evidence)
    context = build_reasoning_context(request, evidence, correlation, memory="HISTORICAL MEMORY: this file was clean before.")

    assert len(evidence) == 2
    assert correlation["conflicts"] == []
    assert "current runtime evidence" in context.lower()
    assert "historical memory" in context.lower()


def test_phase22_blocked_action_stops_safely_and_re_evaluates_risk():
    state = _state(
        target_file="workspace/secret.txt",
        approved=True,
        decision_stage="RISK_EVALUATION",
    )

    decision = evaluate_risk("delete remote repository and wipe data", tool_name="fixer", target_path=state["target_file"], workspace_root="workspace")
    assert decision["risk_level"] == BLOCKED
    assert decision["allowed"] is False
    assert decision["approval_required"] is False

    state["risk_decision"] = decision
    if decision["risk_level"] == BLOCKED:
        state["decision_stage"] = "FINAL_OUTCOME"
        state["decision_reason"] = decision["reason"]
        state["final_outcome"] = "BLOCKED"

    assert state["decision_stage"] == "FINAL_OUTCOME"
    assert state["final_outcome"] == "BLOCKED"


def test_phase22_approval_required_and_rejected_action_uses_existing_boundary(monkeypatch):
    state = _state(
        user_request="Fix the bug in the workspace.",
        investigation=["DIAGNOSIS:\nFIX_ALLOWED: YES"],
        decision_stage="REASON",
    )

    monkeypatch.setattr("builtins.input", lambda *args, **kwargs: "no")
    state = create_proposal(state)

    assert state["approval_required"] is True
    assert state["decision_stage"] == "APPROVAL_PENDING"

    state = request_approval(state)
    assert state["approved"] is False
    assert state["decision_stage"] == "FINAL_OUTCOME"
    assert state["final_outcome"] == "APPROVAL_REJECTED"


def test_phase22_verified_action_and_audit_logging_are_recorded():
    state = _state(
        target_file="demo.py",
        approved=True,
        decision_stage="VERIFICATION",
    )

    state["verification_history"] = []
    state["last_verification"] = "STATUS: SUCCESS"
    state["verification"] = "STATUS: SUCCESS"
    state["approved"] = True
    state["final_outcome"] = "SUCCESS"
    state["decision_reason"] = "Runtime verification succeeded."
    state["decision_stage"] = "FINAL_OUTCOME"

    event = record_audit_event("phase22_autonomous_loop", actor="nexus", tool="runtime_inspector", target="demo.py", result="STATUS: SUCCESS")
    assert event is True
    events = get_recent_audit_events(limit=5)
    assert events
    assert any(item["event_type"] == "phase22_autonomous_loop" for item in events)


def test_phase22_failed_verification_reenters_reason_stage_and_is_bounded():
    state = _state(
        approved=True,
        target_file="demo.py",
        decision_stage="VERIFICATION",
    )

    state["last_verification"] = "STATUS: RUNTIME ERROR"
    state["verification"] = "STATUS: RUNTIME ERROR"
    route = should_retry_verification(state)

    assert route == "retry"
    state["retry_count"] = 1
    state["decision_stage"] = "RETRY"
    state["decision_reason"] = "Fresh observation required after failed verification."

    assert state["retry_count"] == 1
    assert state["decision_stage"] == "RETRY"
    assert state["decision_reason"]

    state["retry_count"] = MAX_RETRIES
    assert should_retry_verification(state) == "stop"


def test_phase22_sensitivity_and_stale_action_checks_are_preserved():
    payload = [{"source": "runtime_inspector", "summary": "token=secret_value; api_key=super_secret"}]
    safe = redact_sensitive_data(payload)

    assert "secret_value" not in str(safe)
    assert "super_secret" not in str(safe)
    assert "[REDACTED]" in str(safe)

    stale_state = _state(decision_stage="ACTION", decision_reason="The cached action is stale and requires fresh observation.")
    stale_state["final_outcome"] = "STALE_ACTION"
    stale_state["decision_stage"] = "REASON"
    stale_state["decision_reason"] = "Fresh observation required before retrying stale action."

    assert stale_state["decision_stage"] == "REASON"
    assert "fresh observation" in stale_state["decision_reason"].lower()


def test_phase22_current_evidence_overrides_historical_memory():
    evidence = normalize_tool_results([
        {"tool": "runtime_inspector", "result": "STATUS: SUCCESS\nCurrent runtime evidence shows clean state."},
    ])
    correlation = correlate_evidence(evidence)
    context = build_reasoning_context(
        "Inspect the project and report the current state.",
        evidence,
        correlation,
        memory="HISTORICAL MEMORY: the project was broken last week.",
    )

    assert "current runtime evidence" in context.lower()
    assert "historical memory" in context.lower()
    assert "clean state" in context.lower()
