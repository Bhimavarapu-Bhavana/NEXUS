"""Phase 47: genuine end-to-end proof of real browser/network execution.

This module proves that the existing NEXUS architecture -- task submission ->
TaskRunner -> StateGraph -> goal/subgoal decomposition -> trusted Tool Registry ->
browser_observer -> verification -> durable persistence -- performs a REAL
network fetch of a REAL public webpage and reports genuinely observed evidence.

Deliberate design constraints (the audit finding this phase exists to correct):

* No ``graph_runner`` stub is supplied. The real compiled ``nexus_graph`` runs.
* No ``browser_evidence`` payload is injected into any graph state.
* No monkeypatching of ``observe_browser_page``, ``_fetch_page``, or the
  ``fetcher`` seam of ``observe_browser_page``.
* Nothing is written outside pytest temporary directories except the agent's own
  intentional audit/memory persistence.

These tests require live outbound HTTPS to ``https://example.com``. If the
network is unavailable the tests fail loudly with an explicit runtime
requirement. They are never skipped and never fall back to fixture evidence.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.request import Request, urlopen

import pytest

from app.agent.execution_journal import load_checkpoint
from app.agent.graph import nexus_graph
from app.agent.task_runner import TaskRunner
from app.memory.task_ledger import get_task
from app.tools import browser_observer as browser_observer_module
from app.tools.browser_observer import observe_browser_page
from app.tools.tool_registry import TOOL_REGISTRY

TARGET_URL = "https://example.com"
SAFE_TASK = (
    "Open https://example.com, read the page, and tell me the page title "
    "and main text. Do not modify anything."
)
EXPECTED_TITLE = "Example Domain"
EXPECTED_TEXT_FRAGMENT = "documentation examples"
EXPECTED_HEADING = "Example Domain"

TERMINAL_STATUSES = {"COMPLETED", "FAILED", "BLOCKED", "CANCELLED"}

REPO_ROOT = Path(__file__).resolve().parents[1]

# The agent is designed to persist an audit trail and task memory while it runs.
# Those runtime databases are intentional side effects, not repository mutation,
# so they are excluded from the read-only source/workspace snapshot below.
_EXCLUDED_DIR_NAMES = {"__pycache__", ".pytest_cache", ".venv", "data", ".git"}
_EXCLUDED_SUFFIXES = {".pyc", ".db", ".db-wal", ".db-shm", ".sqlite", ".log"}


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _repository_snapshot() -> dict[str, str]:
    """Content hashes of every source and workspace file under the repository."""

    snapshot: dict[str, str] = {}
    roots = [REPO_ROOT / "app", REPO_ROOT / "tests", REPO_ROOT / "workspace"]
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if any(part in _EXCLUDED_DIR_NAMES for part in path.parts):
                continue
            if path.suffix in _EXCLUDED_SUFFIXES:
                continue
            snapshot[path.relative_to(REPO_ROOT).as_posix()] = _file_digest(path)
    for path in sorted(REPO_ROOT.iterdir()):
        if path.is_file() and path.suffix not in _EXCLUDED_SUFFIXES:
            snapshot[path.name] = _file_digest(path)
    return snapshot


def _observed_evidence(task: dict) -> dict:
    """Return the real browser evidence that verification consumed and stored."""

    for entry in task.get("verification_history") or []:
        try:
            parsed = ast.literal_eval(entry) if isinstance(entry, str) else entry
        except (ValueError, SyntaxError):
            continue
        if isinstance(parsed, dict) and parsed.get("source") == "browser":
            return parsed
    raise AssertionError(
        "No real browser observation was found in the persisted verification history."
    )


@pytest.fixture(scope="module")
def real_browser_run(tmp_path_factory):
    """Execute the safe read-only task once through the real NEXUS architecture."""

    db_path = tmp_path_factory.mktemp("phase47") / "task_ledger.db"
    workspace_root = REPO_ROOT / "workspace"

    runner = TaskRunner(workspace_root=str(workspace_root), db_path=db_path)
    # No graph_runner argument: the real compiled StateGraph must be the runner.
    assert runner.graph_runner == nexus_graph.invoke

    before = _repository_snapshot()
    started_at = datetime.now(timezone.utc)
    result = runner.start_task(SAFE_TASK)
    finished_at = datetime.now(timezone.utc)
    after = _repository_snapshot()

    task = get_task(result["task_id"], db_path=db_path) or {}
    return {
        "runner": runner,
        "result": result,
        "task": task,
        "db_path": db_path,
        "evidence": _observed_evidence(task),
        "started_at": started_at,
        "finished_at": finished_at,
        "repository_before": before,
        "repository_after": after,
    }


def test_browser_observer_is_the_real_network_tool_not_a_fixture():
    """The registered read-only browser tool is the genuine network observer."""

    spec = TOOL_REGISTRY["browser_observer"]
    assert spec["function"] is observe_browser_page
    assert spec["function"] is browser_observer_module.observe_browser_page
    assert spec["function"].__module__ == "app.tools.browser_observer"

    # The real implementation performs outbound I/O through urlopen.
    source = inspect.getsource(browser_observer_module)
    assert "from urllib.request import" in source
    assert "def _fetch_page(" in source
    assert "opener.open(request" in source

    # No test seam was used: the injectable fetcher defaults to the real one.
    signature = inspect.signature(observe_browser_page)
    assert signature.parameters["fetcher"].default is None

    # The read-only/action boundary is intact.
    assert spec["read_only"] is True
    assert spec["requires_approval"] is False


def test_safe_task_runs_through_the_real_state_graph_without_stubs(real_browser_run):
    """A: the real browser path is reached through the real StateGraph."""

    runner = real_browser_run["runner"]
    assert runner.graph_runner.__self__ is nexus_graph
    assert runner.graph_runner == nexus_graph.invoke

    plan_ids = [
        subgoal.get("sub_goal_id")
        for subgoal in real_browser_run["task"].get("goal_plan") or []
    ]
    assert "observe_browser_target" in plan_ids

    browser_subgoal = next(
        subgoal
        for subgoal in real_browser_run["task"]["goal_plan"]
        if subgoal.get("sub_goal_id") == "observe_browser_target"
    )
    assert browser_subgoal["selected_tools"] == ["browser_observer"]

    statuses = real_browser_run["task"].get("subgoal_statuses") or {}
    assert statuses.get("observe_browser_target") == "COMPLETED"
    assert "observe_browser_target:verified" in (
        real_browser_run["task"].get("completion_evidence") or []
    )


def test_real_webpage_is_observed_with_title_and_text(real_browser_run):
    """B, C, D: example.com is actually observed; title and text are obtained."""

    evidence = real_browser_run["evidence"]
    assert evidence["status"] == "OK"
    assert evidence["source"] == "browser"
    assert evidence["title"] == EXPECTED_TITLE
    assert EXPECTED_TITLE in evidence["visible_text"]
    assert EXPECTED_TEXT_FRAGMENT in evidence["visible_text"]
    assert evidence["headings"] == [EXPECTED_HEADING]
    assert evidence["page_structure"]["heading_count"] >= 1
    assert evidence["page_structure"]["link_count"] >= 1
    assert evidence["truncated"] is False

    for link in evidence["links"]:
        assert link["url"].startswith("https://")


def test_evidence_is_fresh_and_associated_with_the_requested_url(real_browser_run):
    """Evidence is tied to the requested URL and was produced live, not faked."""

    evidence = real_browser_run["evidence"]
    assert evidence["url"] == TARGET_URL
    assert evidence["final_url"].startswith("https://")

    observed_at = datetime.fromisoformat(evidence["observed_at"])
    started = real_browser_run["started_at"]
    finished = real_browser_run["finished_at"]
    assert started - timedelta(seconds=5) <= observed_at <= finished
    assert abs((finished - started).total_seconds()) < 120


def test_nexus_evidence_matches_the_live_page(real_browser_run):
    """Real-vs-fixture oracle: compare NEXUS evidence to an independent live GET."""

    request = Request(
        TARGET_URL,
        headers={"User-Agent": "NEXUS-Phase47-Independent-Oracle/1.0"},
        method="GET",
    )
    with urlopen(request, timeout=10) as response:
        live_html = response.read(250_000).decode("utf-8", errors="replace")
        live_status = response.getcode()

    assert live_status == 200
    assert "<title>Example Domain</title>" in live_html
    assert EXPECTED_TEXT_FRAGMENT in live_html

    evidence = real_browser_run["evidence"]
    assert evidence["title"] == EXPECTED_TITLE
    # The observed text must have come from this page, not a static fixture.
    for fragment in ("Avoid use in operations", "Learn more"):
        assert fragment in live_html
        assert fragment in evidence["visible_text"]


def test_evidence_reaches_verification_and_is_persisted(real_browser_run):
    """E, F: verification consumed the evidence and it was durably persisted."""

    task = real_browser_run["task"]
    history = task.get("verification_history") or []
    assert history, "Verification history must persist the real evidence."

    evidence = real_browser_run["evidence"]
    persisted = ast.literal_eval(history[0])
    assert persisted["title"] == evidence["title"]
    assert persisted["url"] == TARGET_URL

    lineage = (task.get("subgoal_lineage") or {}).get("observe_browser_target") or {}
    assert lineage.get("tool_name") == "browser_observer"
    assert lineage.get("application_id") == "browser"
    assert lineage.get("target") == TARGET_URL
    assert lineage.get("verification") == "SUCCESS"
    assert lineage.get("evidence_hash")
    assert lineage.get("status") == "VERIFIED"

    answer = task.get("task_answer") or ""
    assert f"Title: {EXPECTED_TITLE}" in answer
    assert f"URL: {TARGET_URL}" in answer
    assert EXPECTED_TEXT_FRAGMENT in answer


def test_task_reaches_terminal_state_with_verified_result(real_browser_run):
    """G: the task reaches the correct terminal state with the verified answer."""

    result = real_browser_run["result"]
    task = real_browser_run["task"]

    assert result["status"] == "COMPLETED"
    assert result["status"] in TERMINAL_STATUSES
    assert task["status"] == "COMPLETED"
    assert result["final_outcome"] == "READ_ONLY"
    assert result["current_stage"] == "FINAL_OUTCOME"
    assert "verified successfully" in result["status_reason"].lower()

    statuses = task.get("subgoal_statuses") or {}
    assert all(status == "COMPLETED" for status in statuses.values())


def test_read_only_task_creates_no_approval_and_preserves_action_gating(real_browser_run):
    """I: no approval bypass; the read-only/action boundary is unchanged."""

    task = real_browser_run["task"]
    assert task.get("approval_id") in (None, "")
    assert task.get("proposal_hash") in (None, "")
    assert task.get("action_type") in (None, "")
    assert load_checkpoint(real_browser_run["result"]["task_id"], db_path=real_browser_run["db_path"]) is None

    assert real_browser_run["result"]["status"] != "WAITING_APPROVAL"
    assert (task.get("subgoal_lineage") or {}).get("observe_browser_target", {}).get(
        "tool_name"
    ) == "browser_observer"

    # Every browser action tool remains approval-gated and non-read-only.
    for action_tool in (
        "browser_navigate_observed",
        "browser_follow_observed_link",
        "browser_controller",
    ):
        spec = TOOL_REGISTRY[action_tool]
        assert spec["read_only"] is False
        assert spec["requires_approval"] is True

    # The read-only registry view hides the action/mutation tools entirely.
    visible_names = {name for name, _ in TOOL_REGISTRY.items()}
    assert "browser_observer" in visible_names
    assert "browser_controller" not in visible_names
    assert "fixer" not in visible_names


def test_real_run_does_not_mutate_the_repository(real_browser_run):
    """H: the read-only browser task changed no source or workspace file."""

    before = real_browser_run["repository_before"]
    after = real_browser_run["repository_after"]
    assert before, "The repository snapshot must not be empty."

    changed = sorted(
        key for key in set(before) | set(after) if before.get(key) != after.get(key)
    )
    assert not changed, f"The read-only browser task mutated repository files: {changed}"
