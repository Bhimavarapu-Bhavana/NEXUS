from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import re
from typing import Any

from app.security.sensitive_data import redact_text
from app.tools.tool_registry import TOOL_REGISTRY

MAX_SUB_GOALS = 12
PROHIBITED_COMMAND_PATTERNS = (
    "powershell",
    "cmd.exe",
    "bash -lc",
    "python -c",
    "subprocess",
    "curl ",
    "wget ",
    "os.system",
    "eval(",
    "exec(",
    "delete ",
    "rm -rf",
    "del /s",
    "run_shell",
)


def _safe_text(value: Any) -> str:
    return redact_text(str(value or ""))


def _authorization_valid(tool_name: str) -> bool:
    name = str(tool_name or "").strip()
    if not name:
        return False
    if name not in TOOL_REGISTRY:
        return False
    metadata = TOOL_REGISTRY.get(name, {})
    if not metadata.get("allowed", False):
        return False
    return True


def _contains_executable_instruction(value: str) -> bool:
    text = str(value or "").lower()
    if not text:
        return False
    return any(pattern in text for pattern in PROHIBITED_COMMAND_PATTERNS)


def _make_sub_goal(
    sub_goal_id: str,
    objective: str,
    *,
    dependencies: list[str] | None = None,
    evidence_refs: list[str] | None = None,
    selected_tools: list[str] | None = None,
    action_required: bool = False,
    verification_required: bool = False,
    completion_reason: str = "",
    status: str = "PLANNED",
    application_id: str = "workspace",
    capability_id: str = "inspect",
    target_requirements: list[str] | None = None,
    input_evidence_refs: list[str] | None = None,
    expected_output_evidence: list[str] | None = None,
) -> dict[str, Any]:
    clean_objective = _safe_text(objective)
    if not clean_objective:
        raise ValueError("Sub-goals require a non-empty objective.")
    if _contains_executable_instruction(clean_objective):
        raise ValueError("Planning output must not contain executable commands or instructions.")

    normalized_dependencies = []
    for dep in dependencies or []:
        dep_text = str(dep).strip()
        if dep_text:
            normalized_dependencies.append(dep_text)

    normalized_refs = []
    for ref in evidence_refs or []:
        ref_text = str(ref).strip()
        if ref_text:
            normalized_refs.append(ref_text)

    normalized_tools = []
    for tool in selected_tools or []:
        tool_name = str(tool).strip()
        if not tool_name:
            continue
        if not _authorization_valid(tool_name):
            raise ValueError(f"Unauthorized or unknown tool in decomposition: {tool_name}")
        normalized_tools.append(tool_name)

    return {
        "sub_goal_id": str(sub_goal_id).strip(),
        "objective": clean_objective,
        "status": str(status or "PLANNED").upper(),
        "dependencies": normalized_dependencies,
        "evidence_refs": normalized_refs,
        "selected_tools": normalized_tools,
        "action_required": bool(action_required),
        "verification_required": bool(verification_required),
        "completion_reason": _safe_text(completion_reason or "Evidence is required before completion."),
        "application_id": str(application_id or "workspace"),
        "capability_id": str(capability_id or "inspect"),
        "target_requirements": [str(item).strip() for item in (target_requirements or []) if str(item).strip()],
        "input_evidence_refs": [str(item).strip() for item in (input_evidence_refs or []) if str(item).strip()],
        "expected_output_evidence": [str(item).strip() for item in (expected_output_evidence or evidence_refs or []) if str(item).strip()],
        "execution_class": "CONSEQUENTIAL" if action_required else "READ_ONLY",
    }


def validate_goal_plan(plan: list[dict[str, Any]], *, max_sub_goals: int | None = None) -> list[dict[str, Any]]:
    """Validate a decomposition plan and fail closed on malformed or unsafe output."""
    if not isinstance(plan, list):
        raise ValueError("Goal plans must be provided as a list of sub-goal dictionaries.")
    if not plan:
        raise ValueError("Goal decomposition cannot be empty.")

    limit = max_sub_goals if max_sub_goals is not None else MAX_SUB_GOALS
    if len(plan) > limit:
        raise ValueError(f"Goal plans cannot exceed {limit} sub-goals.")

    seen_ids: set[str] = set()
    by_id: dict[str, dict[str, Any]] = {}
    for item in plan:
        if not isinstance(item, dict):
            raise ValueError("Each sub-goal must be a dictionary.")
        subgoal_id = str(item.get("sub_goal_id") or "").strip()
        if not subgoal_id:
            raise ValueError("Each sub-goal requires a non-empty sub_goal_id.")
        if subgoal_id in seen_ids:
            raise ValueError(f"Duplicate sub-goal ID: {subgoal_id}")
        seen_ids.add(subgoal_id)
        objective = str(item.get("objective") or "").strip()
        if not objective:
            raise ValueError(f"Sub-goal {subgoal_id} is missing an objective.")
        if _contains_executable_instruction(objective):
            raise ValueError(f"Sub-goal {subgoal_id} contains executable instructions.")

        normalized = {
            "sub_goal_id": subgoal_id,
            "objective": _safe_text(objective),
            "status": str(item.get("status") or "PLANNED").upper(),
            "dependencies": [],
            "evidence_refs": [],
            "selected_tools": [],
            "action_required": bool(item.get("action_required", False)),
            "verification_required": bool(item.get("verification_required", False)),
            "completion_reason": _safe_text(item.get("completion_reason") or "Evidence is required before completion."),
            "application_id": _safe_text(item.get("application_id") or "workspace"),
            "capability_id": _safe_text(item.get("capability_id") or "inspect"),
            "target_requirements": [],
            "input_evidence_refs": [],
            "expected_output_evidence": [],
            "execution_class": "CONSEQUENTIAL" if bool(item.get("action_required", False)) else "READ_ONLY",
        }

        dependencies = item.get("dependencies") or []
        if not isinstance(dependencies, list):
            raise ValueError(f"Sub-goal {subgoal_id} dependencies must be a list.")
        for dep in dependencies:
            dep_id = str(dep).strip()
            if not dep_id:
                raise ValueError(f"Sub-goal {subgoal_id} contains an empty dependency.")
            normalized["dependencies"].append(dep_id)

        refs = item.get("evidence_refs") or []
        if not isinstance(refs, list):
            raise ValueError(f"Sub-goal {subgoal_id} evidence_refs must be a list.")
        normalized["evidence_refs"] = [str(ref).strip() for ref in refs if str(ref).strip()]
        for field_name in ("target_requirements", "input_evidence_refs", "expected_output_evidence"):
            values = item.get(field_name) or []
            if not isinstance(values, list):
                raise ValueError(f"Sub-goal {subgoal_id} {field_name} must be a list.")
            normalized[field_name] = [str(value).strip() for value in values if str(value).strip()]

        tools = item.get("selected_tools") or []
        if not isinstance(tools, list):
            raise ValueError(f"Sub-goal {subgoal_id} selected_tools must be a list.")
        for tool in tools:
            tool_name = str(tool).strip()
            if not tool_name:
                continue
            if not _authorization_valid(tool_name):
                raise ValueError(f"Sub-goal {subgoal_id} contains an unknown or unauthorized tool: {tool_name}")
            normalized["selected_tools"].append(tool_name)

        by_id[subgoal_id] = normalized

    all_ids = set(by_id)
    for subgoal_id, subgoal in by_id.items():
        for dep in subgoal["dependencies"]:
            if dep not in all_ids:
                raise ValueError(f"Sub-goal {subgoal_id} references an unknown dependency: {dep}")

    def walk(node: str, stack: set[str], visited: set[str]) -> None:
        if node in stack:
            raise ValueError(f"Dependency cycle detected involving sub-goal {node}.")
        if node in visited:
            return
        stack.add(node)
        for dep in by_id[node]["dependencies"]:
            walk(dep, stack, visited)
        stack.remove(node)
        visited.add(node)

    for subgoal_id in list(by_id):
        walk(subgoal_id, set(), set())

    ordered = []
    remaining = {key: value for key, value in by_id.items()}
    indegree = {key: 0 for key in by_id}
    reverse: dict[str, list[str]] = defaultdict(list)
    for key, subgoal in by_id.items():
        for dep in subgoal["dependencies"]:
            indegree[key] += 1
            reverse[dep].append(key)

    ready = sorted([node for node, degree in indegree.items() if degree == 0])
    while ready:
        node = ready.pop(0)
        ordered.append(remaining.pop(node))
        for dependent in sorted(reverse.get(node, [])):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                ready.append(dependent)
                ready.sort()
    if remaining:
        raise ValueError("Dependency graph for sub-goals is invalid or cyclic.")

    return ordered


def decompose_goal(
    request: str,
    *,
    observations: list[str] | None = None,
    evidence: list[dict[str, Any]] | None = None,
    historical_memory: str = "",
    max_sub_goals: int = MAX_SUB_GOALS,
) -> list[dict[str, Any]]:
    """Create a bounded, ordered decomposition for a user request without creating executable behavior."""
    if max_sub_goals <= 0:
        raise ValueError("max_sub_goals must be positive.")

    text = _safe_text(request)
    if not text:
        raise ValueError("Goal decomposition requires a non-empty user request.")

    lower = text.lower()
    has_failure_signal = any(term in lower for term in ("fail", "error", "broken", "failing", "bug", "issue", "why"))
    attention_requested = any(
        term in lower
        for term in (
            "attention",
            "what needs my attention",
            "what should i do",
            "what should i prioritize",
            "anything urgent",
            "anything important",
            "what's on my plate",
            "attention summary",
            "what's overdue",
            "any overdue",
            "what's due",
            "any deadlines",
            "upcoming deadlines",
        )
    )
    git_requested = any(term in lower for term in ("git", "branch", "commit", "repository", "working tree", "changed files")) or bool(re.search(r"\brepo\b", lower))
    workspace_requested = any(term in lower for term in ("workspace", "project", "submission", "files"))

    browser_requested = "http://" in lower or "https://" in lower or any(term in lower for term in ("open youtube", "chrome", "browser", "web page", "webpage"))

    interactive_browser_requested = any(
        term in lower
        for term in (
            "real browser",
            "actual browser",
            "headless browser",
            "playwright",
            "chromium",
            "open this webpage in",
            "open the page in",
            "open the webpage in",
            "click the grounded",
            "type into the",
            "interact with the page",
            "interacting with the page",
            "navigate to the next page",
        )
    )

    scan_requested = any(term in lower for term in ("security scan", "threat scan", "malware", "antivirus"))
    if scan_requested and not browser_requested:
        plan = [
            _make_sub_goal(
                "inspect_scan_target",
                "Confirm the authorized workspace scan target and its bounded scope.",
                dependencies=[],
                evidence_refs=["scan:target"],
                selected_tools=["workspace_inspector"],
                completion_reason="The bounded scan target was established.",
            ),
            _make_sub_goal(
                "run_security_scan",
                "Run the bounded read-only security scan against the authorized target and collect the structured result as evidence.",
                dependencies=["inspect_scan_target"],
                evidence_refs=["scan:result"],
                selected_tools=["security_scan"],
                verification_required=True,
                completion_reason="The bounded scanner returned an explicit result (clean, threat, unavailable, or error).",
            ),
            _make_sub_goal(
                "report_scan_result",
                "Report the scanner result honestly without inventing remediation; a threat finding never authorizes automatic action.",
                dependencies=["run_security_scan"],
                evidence_refs=["scan:report"],
                selected_tools=[],
                completion_reason="The scan outcome was reported as evidence with no automatic remediation.",
            ),
        ]
        return validate_goal_plan(plan)

    if browser_requested and (git_requested or workspace_requested):
        plan = [
            _make_sub_goal(
                "inspect_workspace",
                "Inspect the authorized workspace and establish the files relevant to the requested report.",
                dependencies=[],
                evidence_refs=["workspace:state"],
                selected_tools=["workspace_inspector"],
                completion_reason="The bounded workspace listing was collected.",
            ),
        ]
        previous_subgoal = "inspect_workspace"
        if git_requested:
            plan.append(
                _make_sub_goal(
                    "inspect_git_status",
                    "Inspect the authorized workspace Git status and report whether repository state is available.",
                    dependencies=[previous_subgoal],
                    evidence_refs=["git:state"],
                    selected_tools=["git_inspector"],
                    verification_required=True,
                    completion_reason="Git state was observed or its bounded unavailability was recorded.",
                )
            )
            previous_subgoal = "inspect_git_status"
        plan.extend([
            _make_sub_goal(
                "observe_browser_target",
                "Observe the explicitly supplied public browser target and collect bounded page evidence.",
                dependencies=[previous_subgoal],
                evidence_refs=["browser:observation"],
                selected_tools=["browser_observer"],
                verification_required=True,
                completion_reason="The authorized browser observer returned bounded evidence from the requested target.",
                application_id="browser",
                capability_id="observe",
            ),
            _make_sub_goal(
                "submission_readiness_summary",
                "Prepare a concise report grounded only in the collected workspace, Git, and browser evidence.",
                dependencies=["observe_browser_target"],
                evidence_refs=["submission:summary"],
                selected_tools=[],
                completion_reason="The summary is grounded in current evidence without making changes.",
            ),
        ])
        return validate_goal_plan(plan)

    if browser_requested:
        explicit_url = "http://" in lower or "https://" in lower
        if interactive_browser_requested and explicit_url:
            # Interactive behavior was explicitly requested: observe first
            # (read-only evidence), then route the live-browser step through
            # the durable Action Executor approval path. Read-only tasks keep
            # the observer-only plan below; nothing here launches a browser.
            plan = [
                _make_sub_goal(
                    "observe_browser_target",
                    "Observe the explicitly supplied public browser target and collect bounded page evidence.",
                    dependencies=[],
                    evidence_refs=["browser:observation"],
                    selected_tools=["browser_observer"],
                    verification_required=True,
                    completion_reason="The authorized browser observer returned bounded evidence from the requested target.",
                ),
                _make_sub_goal(
                    "open_real_browser_page",
                    "Open the explicitly supplied public target in the real browser through the approval-gated browser controller.",
                    dependencies=["observe_browser_target"],
                    evidence_refs=["browser:real_page"],
                    selected_tools=["browser_controller"],
                    action_required=True,
                    verification_required=True,
                    completion_reason="The approval-gated browser controller opened the requested target and returned grounded evidence, or no browser was launched without approval.",
                    application_id="browser",
                    capability_id="interact",
                ),
                _make_sub_goal(
                    "report_browser_capabilities",
                    "Report what the observed page contains and which safe next observations or actions are possible without inventing missing targets.",
                    dependencies=["open_real_browser_page"],
                    evidence_refs=["browser:report"],
                    selected_tools=[],
                    completion_reason="The report is grounded in the observed page evidence and existing authorization gates.",
                ),
            ]
            return validate_goal_plan(plan)
        plan = [
            _make_sub_goal(
                "observe_browser_target",
                "Observe the explicitly supplied public browser target and collect bounded page evidence.",
                dependencies=[],
                evidence_refs=["browser:observation"],
                selected_tools=["browser_observer"],
                verification_required=True,
                completion_reason="The authorized browser observer returned bounded evidence from the requested target.",
            ),
            _make_sub_goal(
                "report_browser_capabilities",
                "Report what the observed page contains and which safe next observations or actions are possible without inventing missing targets.",
                dependencies=["observe_browser_target"],
                evidence_refs=["browser:report"],
                selected_tools=[],
                completion_reason="The report is grounded in the observed page evidence and existing authorization gates.",
            ),
        ]
        if not explicit_url:
            plan[0]["completion_reason"] = "An explicit public HTTP(S) target is required before browser observation can execute."
        return validate_goal_plan(plan)

    if git_requested:
        plan = [
            _make_sub_goal(
                "inspect_workspace",
                "Inspect the authorized workspace and establish the files relevant to submission readiness.",
                dependencies=[],
                evidence_refs=["workspace:state"],
                selected_tools=["workspace_inspector"],
                completion_reason="The bounded workspace listing was collected.",
            ),
            _make_sub_goal(
                "inspect_git_status",
                "Inspect the authorized workspace Git status and report whether repository state is available.",
                dependencies=["inspect_workspace"],
                evidence_refs=["git:state"],
                selected_tools=["git_inspector"],
                verification_required=True,
                completion_reason="Git state was observed or its bounded unavailability was recorded.",
            ),
            _make_sub_goal(
                "submission_readiness_summary",
                "Prepare a short submission-readiness summary grounded only in the collected workspace and Git evidence.",
                dependencies=["inspect_git_status"],
                evidence_refs=["submission:summary"],
                selected_tools=[],
                completion_reason="The summary is grounded in current evidence without making changes.",
            ),
        ]
        return validate_goal_plan(plan)

    if has_failure_signal:
        plan = [
            _make_sub_goal(
                "inspect_workspace",
                "Inspect the relevant workspace and identify the likely failing target.",
                dependencies=[],
                evidence_refs=["workspace:target"],
                selected_tools=["workspace_inspector", "relevant_file_selector"],
                completion_reason="Relevant files and targets are identified.",
            ),
            _make_sub_goal(
                "collect_runtime_evidence",
                "Collect direct runtime and syntax evidence relevant to the failing target.",
                dependencies=["inspect_workspace"],
                evidence_refs=["runtime:error", "syntax:error"],
                selected_tools=["runtime_inspector", "error_detector"],
                verification_required=True,
                completion_reason="Runtime or syntax evidence is captured.",
            ),
            _make_sub_goal(
                "collect_supporting_evidence",
                "Gather supporting evidence from logs, terminal output, and Git state relevant to the same target.",
                dependencies=["collect_runtime_evidence"],
                evidence_refs=["terminal:output", "log:output", "git:state"],
                selected_tools=["terminal_inspector", "log_inspector", "git_inspector"],
                completion_reason="Related evidence supports root-cause correlation.",
            ),
            _make_sub_goal(
                "correlate_evidence",
                "Correlate the current evidence and the relevant historical context around the same target.",
                dependencies=["inspect_workspace", "collect_runtime_evidence", "collect_supporting_evidence"],
                evidence_refs=["evidence:correlation"],
                selected_tools=[],
                completion_reason="Evidence is correlated and any conflicts are noted.",
            ),
            _make_sub_goal(
                "reason_root_cause",
                "Determine the most likely root cause from the correlated evidence and the user request.",
                dependencies=["correlate_evidence"],
                evidence_refs=["reasoning:root_cause"],
                selected_tools=[],
                completion_reason="Likely underlying cause is identified with evidence.",
            ),
            _make_sub_goal(
                "propose_fix",
                "Propose a bounded fix only if the evidence supports a safe, minimal change.",
                dependencies=["reason_root_cause"],
                evidence_refs=["proposal:fix"],
                selected_tools=["logic_inspector"],
                action_required=False,
                completion_reason="A bounded, evidence-backed fix proposal is ready.",
            ),
            _make_sub_goal(
                "evaluate_risk",
                "Evaluate the proposed change against the existing risk and authorization gates.",
                dependencies=["propose_fix"],
                evidence_refs=["risk:evaluation"],
                selected_tools=["security_scan"],
                action_required=False,
                completion_reason="Risk evaluation is complete before any approval or action.",
            ),
            _make_sub_goal(
                "approval_boundary",
                "Hold the action behind the existing approval and revalidation boundary when required.",
                dependencies=["evaluate_risk"],
                evidence_refs=["approval:binding"],
                selected_tools=[],
                action_required=False,
                completion_reason="Approval conditions are preserved without bypassing safeguards.",
            ),
            _make_sub_goal(
                "apply_approved_change",
                "Apply only an already-approved change through the existing bounded tools.",
                dependencies=["approval_boundary"],
                evidence_refs=["action:approved"],
                selected_tools=[],
                action_required=True,
                completion_reason="Approved change is applied through the existing tool pipeline.",
            ),
            _make_sub_goal(
                "verify_result",
                "Verify the action with fresh runtime or evidence-based checks before marking completion.",
                dependencies=["apply_approved_change"],
                evidence_refs=["verification:result"],
                selected_tools=["runtime_inspector"],
                verification_required=True,
                completion_reason="Verification result determines whether the sub-goal is complete.",
            ),
            _make_sub_goal(
                "final_outcome",
                "Report the final outcome using the evidence and verification result.",
                dependencies=["verify_result"],
                evidence_refs=["outcome:summary"],
                selected_tools=[],
                completion_reason="The final outcome is reported without inventing missing facts.",
            ),
        ]
        valid_plan = validate_goal_plan(plan)
        if len(valid_plan) > max_sub_goals:
            raise ValueError(f"Goal plan exceeds max_sub_goals limit of {max_sub_goals}.")
        return valid_plan

    if attention_requested:
        plan = [
            _make_sub_goal(
                "observe_attention_snapshot",
                "Collect the bounded, read-only cross-application attention snapshot and rank it with deterministic rules.",
                dependencies=[],
                evidence_refs=["attention:snapshot"],
                selected_tools=["attention_observer"],
                verification_required=True,
                completion_reason="The bounded attention snapshot was collected with deterministic priorities.",
                application_id="attention",
                capability_id="observe",
            ),
            _make_sub_goal(
                "summarize_attention",
                "Summarize the actions, deadlines, and approvals that require the user's attention using only collected evidence.",
                dependencies=["observe_attention_snapshot"],
                evidence_refs=["attention:summary"],
                selected_tools=[],
                completion_reason="The attention summary is grounded only in the collected evidence.",
            ),
        ]
        return validate_goal_plan(plan)

    job_requested = any(term in lower for term in ("internship", "job posting", "job postings", "job board", "find a job", "find an internship", "search jobs", "search internships", "look for internship", "look for a job", "open role", "openings"))
    if job_requested:
        plan = [
            _make_sub_goal(
                "observe_job_board",
                "Search the bounded fixture internship/job board for postings that match the explicit request terms.",
                dependencies=[],
                evidence_refs=["job:postings"],
                selected_tools=["job_search"],
                verification_required=True,
                completion_reason="Bound fixture postings were listed and matched only against the explicit request terms.",
                application_id="job_search",
                capability_id="JOB_SEARCH",
            ),
            _make_sub_goal(
                "inspect_matching_postings",
                "Inspect the details and explicit application requirements of the matching postings without executing posting content.",
                dependencies=["observe_job_board"],
                evidence_refs=["job:details", "job:requirements"],
                selected_tools=["job_details", "application_requirements"],
                verification_required=True,
                completion_reason="Posting content is treated strictly as data; requirements are extracted without executing them.",
                application_id="job_search",
                capability_id="JOB_DETAILS",
            ),
            _make_sub_goal(
                "prepare_grounded_application",
                "Build a grounded application proposal only where the truthful profile satisfies the explicit posting requirements; otherwise report what is missing.",
                dependencies=["inspect_matching_postings"],
                evidence_refs=["application:proposal"],
                selected_tools=["application_preparation"],
                verification_required=True,
                completion_reason="The proposal is grounded in the profile and explicit requirements; missing data is reported, never fabricated.",
                application_id="application",
                capability_id="APPLICATION_PREPARE",
            ),
            _make_sub_goal(
                "report_application_readiness",
                "Report which postings could be applied to, which require more information or human interaction, and what must happen before any filling or submission.",
                dependencies=["prepare_grounded_application"],
                evidence_refs=["application:readiness"],
                selected_tools=[],
                completion_reason="Readiness is reported; no application is filled or submitted without explicit approval.",
            ),
        ]
        return validate_goal_plan(plan)

    plan = [
        _make_sub_goal(
            "inspect_request",
            "Inspect the request and the currently observed workspace context.",
            dependencies=[],
            evidence_refs=["request:summary", "workspace:state"],
            selected_tools=["workspace_inspector"],
            completion_reason="The user request and current context are understood.",
        ),
        _make_sub_goal(
            "collect_evidence",
            "Collect relevant evidence directly tied to the request.",
            dependencies=["inspect_request"],
            evidence_refs=["evidence:current"],
            selected_tools=["relevant_file_selector", "runtime_inspector"],
            completion_reason="Evidence is available for reasoned interpretation.",
        ),
        _make_sub_goal(
            "reason_about_outcome",
            "Reason over the evidence and historical context without inventing missing facts.",
            dependencies=["collect_evidence"],
            evidence_refs=["reasoning:summary"],
            selected_tools=[],
            completion_reason="Probable outcome or next decision is identified.",
        ),
    ]
    valid_plan = validate_goal_plan(plan)
    if len(valid_plan) > max_sub_goals:
        raise ValueError(f"Goal plan exceeds max_sub_goals limit of {max_sub_goals}.")
    return valid_plan


__all__ = [
    "MAX_SUB_GOALS",
    "decompose_goal",
    "validate_goal_plan",
    "_make_sub_goal",
]
