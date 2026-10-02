from app.tools.tool_registry import (
    MAX_TOOLS_PER_PLAN,
    TOOL_REGISTRY,
    execute_selected_tools,
    get_trusted_tool_plan,
    validate_tool_plan,
)


def test_single_tool_selection():
    request = "Find syntax errors in my Python project."
    plan = get_trusted_tool_plan(request)

    assert "error_detector" in plan
    assert len(plan) == 1


def test_multiple_tool_selection():
    request = "Why does my Python application crash when I run it?"
    plan = get_trusted_tool_plan(request)

    assert "relevant_file_selector" in plan
    assert "error_detector" in plan
    assert "runtime_inspector" in plan
    assert len(plan) <= MAX_TOOLS_PER_PLAN


def test_unknown_tool_rejection():
    plan = validate_tool_plan(["unknown_tool", "error_detector"])

    assert plan == ["error_detector"]


def test_modification_tool_protection():
    plan = validate_tool_plan(["fixer", "error_detector"])

    assert plan == ["error_detector"]
    assert "fixer" not in plan


def test_tool_limit_and_deduplication():
    raw_plan = [
        "error_detector",
        "error_detector",
        "runtime_inspector",
        "logic_inspector",
        "relevant_file_selector",
        "workspace_inspector",
        "unknown_tool",
    ]

    plan = validate_tool_plan(raw_plan)

    assert len(plan) <= MAX_TOOLS_PER_PLAN
    assert plan.count("error_detector") == 1
    assert "unknown_tool" not in plan


def test_tool_execution_uses_registry(monkeypatch):
    called = []

    def fake_runtime_inspector(workspace_path, file_name, timeout_seconds=10):
        called.append((workspace_path, file_name, timeout_seconds))
        return "STATUS: SUCCESS"

    monkeypatch.setitem(TOOL_REGISTRY, "runtime_inspector", {
        "function": fake_runtime_inspector,
        "description": "run python file",
        "read_only": True,
        "requires_approval": False,
        "allowed": True,
    })

    result = execute_selected_tools(["runtime_inspector"], workspace_path="workspace", file_name="shop_project.py")

    assert result[0]["status"] == "ok"
    assert called
