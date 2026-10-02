from app.security.risk_engine import (
    BLOCKED,
    HIGH_RISK,
    LOW_RISK,
    MEDIUM_RISK,
    READ_ONLY,
    classify_action,
    evaluate_risk,
)
from app.security.sensitive_data import REDACTION_MARKER, redact_sensitive_data
from app.tools.tool_registry import (
    TOOL_REGISTRY,
    execute_selected_tools,
    get_tool_risk,
    validate_tool_plan,
)


def test_read_only_classification():
    decision = evaluate_risk("inspect Git status and read application logs")

    assert decision["risk_level"] == READ_ONLY
    assert decision["allowed"] is True
    assert decision["approval_required"] is False


def test_file_modification_requires_approval(tmp_path):
    decision = evaluate_risk(
        "apply approved code fix",
        tool_name="fixer",
        target_path="source.py",
        workspace_root=tmp_path,
    )

    assert decision["risk_level"] == MEDIUM_RISK
    assert decision["allowed"] is True
    assert decision["approval_required"] is True


def test_low_risk_local_preparation():
    decision = classify_action("create a temporary analysis artifact")

    assert decision["risk_level"] == LOW_RISK
    assert decision["allowed"] is True


def test_high_risk_action_requires_approval():
    decision = evaluate_risk("send external communication")

    assert decision["risk_level"] == HIGH_RISK
    assert decision["allowed"] is True
    assert decision["approval_required"] is True


def test_unauthorized_path_is_blocked(tmp_path):
    decision = evaluate_risk(
        "modify source file",
        target_path=tmp_path.parent / "outside.py",
        workspace_root=tmp_path,
    )

    assert decision["risk_level"] == BLOCKED
    assert decision["allowed"] is False
    assert decision["approval_required"] is False


def test_restricted_path_is_blocked(tmp_path):
    decision = evaluate_risk(
        "read source",
        target_path=".env",
        workspace_root=tmp_path,
    )

    assert decision["risk_level"] == BLOCKED
    assert decision["allowed"] is False


def test_arbitrary_command_is_blocked():
    decision = evaluate_risk("execute arbitrary shell command")

    assert decision["risk_level"] == BLOCKED
    assert decision["allowed"] is False


def test_destructive_git_is_blocked_but_git_read_is_read_only():
    destructive = evaluate_risk("git push changes to remote")
    read_only = evaluate_risk("inspect git diff")

    assert destructive["risk_level"] == BLOCKED
    assert destructive["allowed"] is False
    assert read_only["risk_level"] == READ_ONLY
    assert read_only["allowed"] is True


def test_approval_cannot_override_blocked_action():
    decision = evaluate_risk("git reset --hard HEAD")

    assert decision["risk_level"] == BLOCKED
    assert decision["approval_required"] is False
    assert decision["allowed"] is False


def test_planner_supplied_risk_cannot_lower_deterministic_result(tmp_path):
    decision = evaluate_risk(
        "modify source file risk=LOW",
        target_path="main.py",
        workspace_root=tmp_path,
    )

    assert decision["risk_level"] == MEDIUM_RISK
    assert decision["approval_required"] is True


def test_registered_read_only_tools_remain_functional(tmp_path):
    decision = get_tool_risk("workspace_inspector", workspace_root=tmp_path)
    results = execute_selected_tools(["workspace_inspector"], workspace_path=str(tmp_path))

    assert decision["risk_level"] == READ_ONLY
    assert results[0]["status"] == "ok"
    assert TOOL_REGISTRY["workspace_inspector"]["read_only"] is True


def test_modification_tool_is_not_planner_selectable_but_has_risk():
    assert "fixer" not in validate_tool_plan(["fixer"])
    assert get_tool_risk("fixer")["risk_level"] == MEDIUM_RISK


def test_final_action_gate_rejects_approved_workspace_escape(monkeypatch):
    from app.agent import graph

    called = []

    def fake_fix(*args, **kwargs):
        called.append(True)
        return "unexpected"

    monkeypatch.setattr(graph, "fix_python_logic", fake_fix)
    state = {
        "approved": True,
        "target_file": "../outside.py",
        "old_code": "old",
        "new_code": "new",
        "action_result": "",
    }

    result = graph.execute_action(state)

    assert result["risk_decision"]["risk_level"] == BLOCKED
    assert called == []
    assert "risk engine" in result["action_result"]


def test_sensitive_data_protection_remains_intact():
    protected = redact_sensitive_data("api_key=synthetic_phase9_secret")

    assert REDACTION_MARKER in protected
    assert "synthetic_phase9_secret" not in protected
