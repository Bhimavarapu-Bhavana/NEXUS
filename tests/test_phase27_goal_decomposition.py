import pytest

from app.agent.evidence import build_reasoning_context, correlate_evidence, normalize_tool_results
from app.agent.goal_decomposition import MAX_SUB_GOALS, decompose_goal, validate_goal_plan
from app.security.sensitive_data import redact_sensitive_data
from app.tools.tool_registry import TOOL_REGISTRY


def test_phase27_decompose_goal_generates_bounded_sub_goals_for_failures():
    plan = decompose_goal(
        "The runtime error in the workspace is failing the project. Investigate and explain the cause.",
        observations=["workspace inspection requested"],
        evidence=[{"source": "runtime_inspector", "summary": "STATUS: ERROR"}],
        historical_memory="Historical memory says the issue was intermittent.",
    )

    assert isinstance(plan, list)
    assert 1 <= len(plan) <= MAX_SUB_GOALS
    assert all("sub_goal_id" in item for item in plan)
    assert all(item["selected_tools"] == [] or all(tool in {"workspace_inspector", "relevant_file_selector", "runtime_inspector", "error_detector", "terminal_inspector", "log_inspector", "git_inspector", "security_scan", "logic_inspector"} for tool in item["selected_tools"]) for item in plan)
    assert all(item["objective"] for item in plan)
    assert all("executable" not in item["objective"].lower() for item in plan)


def test_phase27_validation_rejects_unauthorized_tools_and_cycles():
    bad_tool = [{
        "sub_goal_id": "g1",
        "objective": "Inspect the project without inventing details.",
        "dependencies": [],
        "selected_tools": ["not_a_real_tool"],
    }]

    with pytest.raises(ValueError):
        validate_goal_plan(bad_tool)

    loop = [
        {
            "sub_goal_id": "a",
            "objective": "Inspect the issue.",
            "dependencies": ["b"],
            "selected_tools": ["workspace_inspector"],
        },
        {
            "sub_goal_id": "b",
            "objective": "Confirm the issue.",
            "dependencies": ["a"],
            "selected_tools": ["runtime_inspector"],
        },
    ]

    with pytest.raises(ValueError):
        validate_goal_plan(loop)


def test_phase27_validation_blocks_executable_instructions_and_max_size():
    malicious = [{
        "sub_goal_id": "m1",
        "objective": "Run bash -lc 'rm -rf /' to clean the environment.",
        "dependencies": [],
        "selected_tools": ["workspace_inspector"],
    }]

    with pytest.raises(ValueError):
        validate_goal_plan(malicious)

    with pytest.raises(ValueError):
        decompose_goal("Inspect the workspace.", max_sub_goals=0)


def test_phase27_plan_is_ordered_and_dependency_safe():
    plan = validate_goal_plan([
        {
            "sub_goal_id": "prepare",
            "objective": "Establish the investigation target.",
            "dependencies": [],
            "selected_tools": ["workspace_inspector"],
        },
        {
            "sub_goal_id": "debug",
            "objective": "Collect runtime evidence for the target.",
            "dependencies": ["prepare"],
            "selected_tools": ["runtime_inspector"],
        },
        {
            "sub_goal_id": "finalize",
            "objective": "Correlate the evidence and conclude the likely cause.",
            "dependencies": ["debug"],
            "selected_tools": [],
        },
    ])

    ids = [item["sub_goal_id"] for item in plan]
    assert ids[0] == "prepare"
    assert ids[1] == "debug"
    assert ids[2] == "finalize"
    assert all(item["dependencies"] for item in plan[1:])


def test_phase27_validation_covers_duplicate_ids_invalid_dependencies_and_max_limit():
    duplicate = [
        {"sub_goal_id": "a", "objective": "Inspect the failure.", "dependencies": [], "selected_tools": ["workspace_inspector"]},
        {"sub_goal_id": "a", "objective": "Inspect again.", "dependencies": [], "selected_tools": ["runtime_inspector"]},
    ]
    with pytest.raises(ValueError):
        validate_goal_plan(duplicate)

    unknown_dep = [
        {"sub_goal_id": "alpha", "objective": "Inspect the request.", "dependencies": ["missing"], "selected_tools": ["workspace_inspector"]},
    ]
    with pytest.raises(ValueError):
        validate_goal_plan(unknown_dep)

    oversized = [
        {"sub_goal_id": f"g{i}", "objective": f"Review the issue {i}.", "dependencies": [], "selected_tools": ["workspace_inspector"]}
        for i in range(MAX_SUB_GOALS + 1)
    ]
    with pytest.raises(ValueError):
        validate_goal_plan(oversized)


def test_phase27_validation_rejects_malformed_plan_shapes_and_nonlist_dependencies():
    with pytest.raises(ValueError):
        validate_goal_plan({"sub_goal_id": "x"})

    malformed = [{
        "objective": "No id provided.",
        "dependencies": [],
        "selected_tools": ["workspace_inspector"],
    }]
    with pytest.raises(ValueError):
        validate_goal_plan(malformed)

    bad_dependency_type = [{
        "sub_goal_id": "p1",
        "objective": "Inspect the workspace.",
        "dependencies": "prepare",
        "selected_tools": ["workspace_inspector"],
    }]
    with pytest.raises(ValueError):
        validate_goal_plan(bad_dependency_type)


def test_phase27_unauthorized_tool_and_historical_memory_remain_separated(monkeypatch):
    original = TOOL_REGISTRY["workspace_inspector"]["allowed"]
    monkeypatch.setitem(TOOL_REGISTRY["workspace_inspector"], "allowed", False)
    with pytest.raises(ValueError):
        validate_goal_plan([
            {"sub_goal_id": "s1", "objective": "Inspect the workspace.", "dependencies": [], "selected_tools": ["workspace_inspector"]},
        ])
    monkeypatch.setitem(TOOL_REGISTRY["workspace_inspector"], "allowed", original)

    evidence = normalize_tool_results([
        {"tool": "runtime_inspector", "result": "STATUS: SUCCESS\nCurrent runtime evidence is clean."},
    ])
    correlation = correlate_evidence(evidence)
    context = build_reasoning_context(
        "Inspect the current project state.",
        evidence,
        correlation,
        memory="HISTORICAL MEMORY: the project failed last week.",
    )
    assert "current runtime evidence" in context.lower()
    assert "historical memory" in context.lower()
    assert "clean" in context.lower()


def test_phase27_sensitive_data_redaction_and_goal_plan_support_are_fail_closed():
    protected = redact_sensitive_data({
        "password": "super-secret-password",
        "api_key": "abc123",
        "notes": "safe value",
    })
    encoded = str(protected)
    assert "[REDACTED]" in encoded
    assert "super-secret-password" not in encoded
    assert "abc123" not in encoded

    plan = validate_goal_plan([
        {
            "sub_goal_id": "inspect",
            "objective": "Inspect the workspace for the requested issue.",
            "dependencies": [],
            "selected_tools": ["workspace_inspector"],
        },
        {
            "sub_goal_id": "diagnose",
            "objective": "Diagnose the identified issue using the evidence.",
            "dependencies": ["inspect"],
            "selected_tools": ["logic_inspector"],
        },
    ])
    assert [item["sub_goal_id"] for item in plan] == ["inspect", "diagnose"]
    assert all("[REDACTED]" not in item["objective"] for item in plan)
