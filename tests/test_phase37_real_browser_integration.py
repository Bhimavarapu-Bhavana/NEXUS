"""Phase 37 real-browser integration tests (focused, hermetic).

Proves that a previously unseen runtime-supplied public URL can travel the
authoritative chain:

  natural-language task -> StateGraph planning -> Risk -> Privacy ->
  Permission -> Automation Scope -> Approval Authority -> Action Executor ->
  browser_controller_entrypoint -> open_page -> _launch_page ->
  sync_playwright -> chromium.launch -> new_page -> page.goto ->
  verification -> audit

No test depends on an external website: Playwright is faked at the
``playwright.sync_api.sync_playwright`` boundary (calls are recorded so the
exact lifecycle is proven), the urllib observer is fed a stub fetcher, and all
target URLs are generated at runtime under the reserved ``.test`` TLD. No
specific public website is hardcoded anywhere in this file.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

import app.agent.action_executor as action_executor_module
import app.tools.browser_controller as browser_controller_module
from app.agent.action_executor import (
    ACTION_FUNCTIONS,
    execute_authorized_action,
    execute_browser_controller_action,
    proposal_hash,
)
from app.agent.approval_authority import (
    create_approval,
    decide_approval,
    get_approval,
)
from app.agent.capability_context import build_capability_context
from app.agent.execution_journal import create_checkpoint, load_checkpoint
from app.agent.goal_decomposition import decompose_goal
from app.agent.workflow import _infer_tool_for_sub_goal
from app.tools.browser_controller import (
    _ACTIVE_PAGES,
    browser_controller_entrypoint,
)
from app.tools.browser_observer import observe_browser_page
from app.tools.tool_registry import (
    TOOL_REGISTRY,
    execute_selected_tools,
    get_trusted_tool_plan,
)

FUTURE = (datetime.now(timezone.utc) + timedelta(seconds=600)).isoformat()

# Stand-in public address used ONLY as a hermetic DNS answer for runtime
# ``*.test`` probe hosts. No connection is ever made to it: Playwright is
# faked at the sync_playwright boundary and the urllib observer uses a stub
# fetcher. Real resolution (including loopback/SSRF cases) is delegated.
_PROBE_RESOLVED_IP = "1.1.1.1"


@pytest.fixture(autouse=True)
def hermetic_probe_dns(monkeypatch):
    import app.tools.browser_observer as observer_module

    real_resolve = observer_module._resolved_addresses

    def fake_resolve(hostname: str) -> list[str]:
        if str(hostname or "").lower().endswith(".test"):
            return [_PROBE_RESOLVED_IP]
        return real_resolve(hostname)

    monkeypatch.setattr(observer_module, "_resolved_addresses", fake_resolve)


def _runtime_url() -> str:
    """Generate a previously unseen safe public URL at runtime."""
    return f"https://probe-{uuid.uuid4().hex[:12]}.test"


# ---------------------------------------------------------------------------
# Fake Playwright boundary (records the exact lifecycle, performs no network)
# ---------------------------------------------------------------------------


class _FakeLocator:
    def __init__(self, page: "_FakePage", selector: str) -> None:
        self._page = page
        self._selector = selector

    def count(self) -> int:
        return len(self._page._elements_for(self._selector))

    def nth(self, index: int) -> "_FakeElement":
        return self._page._elements_for(self._selector)[index]

    def inner_text(self) -> str:
        if self._selector == "body":
            return "Probe page body text."
        elements = self._page._elements_for(self._selector)
        return elements[0].inner_text() if elements else ""

    def click(self) -> None:
        self._page.clicked.append(self._selector)

    def fill(self, value: str) -> None:
        self._page.filled[self._selector] = value


class _FakeElement:
    def __init__(self, text: str = "", attrs: dict[str, str] | None = None) -> None:
        self._text = text
        self._attrs = attrs or {}

    def inner_text(self) -> str:
        return self._text

    def text_content(self) -> str:
        return self._text

    def get_attribute(self, name: str) -> str:
        return self._attrs.get(name, "")


class _FakePage:
    def __init__(self) -> None:
        self.url = ""
        self.goto_calls: list[str] = []
        self.clicked: list[str] = []
        self.filled: dict[str, str] = {}

    def title(self) -> str:
        return "Probe Page"

    def locator(self, selector: str) -> _FakeLocator:
        return _FakeLocator(self, selector)

    def click(self, selector: str) -> None:
        self.clicked.append(selector)

    def fill(self, selector: str, value: str) -> None:
        self.filled[selector] = value

    def goto(self, url: str, wait_until: str | None = None, timeout: int | None = None) -> None:
        self.goto_calls.append(url)
        self.url = url

    def _elements_for(self, selector: str) -> list[_FakeElement]:
        if selector == "button":
            return [_FakeElement("Do thing")]
        if selector == "input":
            return [_FakeElement("", {"type": "text", "name": "query"})]
        return []


class _FakeBrowser:
    def __init__(self, factory: "_FakePlaywrightFactory") -> None:
        self._factory = factory
        self.closed = False

    def new_page(self, viewport: dict[str, int] | None = None) -> _FakePage:
        page = _FakePage()
        self._factory.pages.append(page)
        return page

    def close(self) -> None:
        self.closed = True


class _FakeChromium:
    def __init__(self, factory: "_FakePlaywrightFactory") -> None:
        self._factory = factory

    def launch(self, headless: bool = True) -> _FakeBrowser:
        self._factory.launches.append({"headless": headless})
        browser = _FakeBrowser(self._factory)
        self._factory.browsers.append(browser)
        return browser


class _FakePlaywright:
    def __init__(self, factory: "_FakePlaywrightFactory") -> None:
        self.chromium = _FakeChromium(factory)


class _FakeManager:
    def __init__(self, factory: "_FakePlaywrightFactory") -> None:
        self._factory = factory
        self.exited = False

    def __enter__(self) -> _FakePlaywright:
        return _FakePlaywright(self._factory)

    def __exit__(self, *args: Any) -> bool:
        self.exited = True
        return False

    def stop(self) -> None:
        self.exited = True


class _FakePlaywrightFactory:
    """Callable replacement for ``playwright.sync_api.sync_playwright``."""

    def __init__(self) -> None:
        self.calls = 0
        self.launches: list[dict[str, Any]] = []
        self.browsers: list[_FakeBrowser] = []
        self.pages: list[_FakePage] = []

    def __call__(self) -> _FakeManager:
        self.calls += 1
        return _FakeManager(self)


@pytest.fixture()
def fake_playwright(monkeypatch):
    import playwright.sync_api as sync_api

    factory = _FakePlaywrightFactory()
    monkeypatch.setattr(sync_api, "sync_playwright", factory)
    return factory


@pytest.fixture()
def captured_audits(monkeypatch):
    events: list[str] = []
    for module in (action_executor_module, browser_controller_module):
        monkeypatch.setattr(
            module,
            "record_audit_event",
            lambda event_type, **payload: events.append(event_type) or True,
        )
    return events


@pytest.fixture(autouse=True)
def clean_page_registry():
    _ACTIVE_PAGES.clear()
    yield
    for page_id in list(_ACTIVE_PAGES.keys()):
        try:
            browser_controller_module.close_page(page_id)
        except Exception:
            pass
    _ACTIVE_PAGES.clear()


def _context(task_id: str, url: str, fingerprint: str, *, tool_name: str = "browser_controller") -> dict[str, Any]:
    return build_capability_context(
        task_id=task_id,
        subgoal_id="open_real_browser_page",
        application_id="browser",
        capability_id="interact",
        tool_name=tool_name,
        target=url,
        observation_id=f"obs-{uuid.uuid4().hex[:12]}",
        evidence={"url": url},
        environment_fingerprint=fingerprint,
    )


def _controller_lineage(tmp_path, *, url: str, spec: dict[str, Any], context: dict[str, Any] | None = None):
    task_id = f"task-{uuid.uuid4().hex[:12]}"
    approvals_db = tmp_path / "approvals.db"
    journal_db = tmp_path / "journal.db"
    digest = proposal_hash(
        action_type="browser_controller",
        tool_name="browser_controller",
        target=url,
        action_spec=spec,
    )
    checkpoint = create_checkpoint(
        task_id,
        current_stage="APPROVAL_PENDING",
        action_type="browser_controller",
        action_target=url,
        proposal_hash=digest,
        risk_level="MEDIUM_RISK",
        approval_status="PENDING",
        action_payload={"action_spec": spec},
        selected_tools=["browser_controller"],
        db_path=journal_db,
    )
    evidence_hash_value = str((context or {}).get("evidence_hash", ""))
    approval = create_approval(
        task_id=task_id,
        checkpoint_id=checkpoint["checkpoint_id"],
        proposal_hash=digest,
        action_type="browser_controller",
        tool_name="browser_controller",
        target=url,
        risk_level="MEDIUM_RISK",
        capability_context=context,
        evidence_hash_value=evidence_hash_value,
        db_path=approvals_db,
    )
    decide_approval(approval["approval_id"], "APPROVED", db_path=approvals_db)
    state = {
        "task_id": task_id,
        "journal_checkpoint_id": checkpoint["checkpoint_id"],
        "approval_id": approval["approval_id"],
        "proposal_hash": digest,
        "action_type": "browser_controller",
        "action_tool": "browser_controller",
        "action_target": url,
        "action_spec": spec,
        "journal_db_path": str(journal_db),
    }
    if context is not None:
        state["capability_context"] = context
    return state, approvals_db


# ---------------------------------------------------------------------------
# A. Dynamic browser-controller routing through the authoritative executor
# ---------------------------------------------------------------------------


def test_dynamic_url_reaches_playwright_through_executor(tmp_path, fake_playwright, captured_audits):
    url = _runtime_url()
    context = _context("task-routing", url, str(tmp_path))
    spec = {"controller_action": "open_page", "url": url, "timeout_seconds": 15}
    state, approvals_db = _controller_lineage(tmp_path, url=url, spec=spec, context=context)
    result = execute_authorized_action(state, workspace_root=str(tmp_path), db_path=approvals_db)
    assert result["status"] == "COMPLETED", result
    assert result["verification"] == "SUCCESS"
    payload = result["result"]
    assert payload["source"] == "browser_controller"
    assert payload["url"] == url
    assert payload["page_id"].startswith("page:")
    # Exact Playwright lifecycle was exercised exactly once.
    assert fake_playwright.calls == 1
    assert len(fake_playwright.launches) == 1
    assert fake_playwright.launches[0]["headless"] is True
    assert len(fake_playwright.pages) == 1
    assert fake_playwright.pages[0].goto_calls == [url]
    # Approval consumed, checkpoint snapshotted, audit recorded.
    approval = get_approval(state["approval_id"], db_path=approvals_db)
    assert approval["status"] == "CONSUMED"
    checkpoint = load_checkpoint(state["task_id"], checkpoint_id=state["journal_checkpoint_id"], db_path=state["journal_db_path"])
    assert checkpoint["verification_snapshot"] == "SUCCESS"
    assert "browser_controller_opened" in captured_audits
    assert "action_execution_completed" in captured_audits


def test_controller_registered_and_gated_but_dispatched(tmp_path):
    # Registry metadata keeps the controller consequential and allowed ...
    entry = TOOL_REGISTRY["browser_controller"]
    assert entry["allowed"] is True
    assert entry["read_only"] is False
    assert entry["requires_approval"] is True
    # ... and the executor now owns an authoritative dispatch mapping ...
    assert ACTION_FUNCTIONS["browser_controller"] is execute_browser_controller_action
    # ... while the read-only registry path still refuses to run it.
    blocked = execute_selected_tools(["browser_controller"], url=_runtime_url())
    assert blocked and blocked[0]["status"] == "blocked"


# ---------------------------------------------------------------------------
# B. Multiple distinct dynamic URLs (no hardcoded site dependency)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("round_index", [0, 1])
def test_two_distinct_runtime_urls_both_route(tmp_path, fake_playwright, round_index):
    first, second = _runtime_url(), _runtime_url()
    assert first != second
    url = first if round_index == 0 else second
    context = _context("task-multi", url, str(tmp_path))
    spec = {"controller_action": "open_page", "url": url}
    state, approvals_db = _controller_lineage(tmp_path, url=url, spec=spec, context=context)
    result = execute_authorized_action(state, workspace_root=str(tmp_path), db_path=approvals_db)
    assert result["status"] == "COMPLETED", result
    assert result["result"]["url"] == url
    assert fake_playwright.pages[-1].goto_calls == [url]


def test_dynamic_planning_selects_controller_only_for_interactive(tmp_path):
    interactive_url = _runtime_url()
    plan = decompose_goal(f"Open {interactive_url} in a real browser and report what you see.")
    tools = [tool for item in plan for tool in (item.get("selected_tools") or [])]
    assert "browser_observer" in tools
    assert "browser_controller" in tools
    # Read-only observation of another runtime URL never selects the controller.
    readonly_url = _runtime_url()
    readonly_plan = decompose_goal(f"Observe {readonly_url} and summarize the page.")
    readonly_tools = [tool for item in readonly_plan for tool in (item.get("selected_tools") or [])]
    assert "browser_observer" in readonly_tools
    assert "browser_controller" not in readonly_tools
    # Trusted tool plans agree.
    assert "browser_controller" in get_trusted_tool_plan(f"Open {interactive_url} in a real browser.")
    assert "browser_controller" not in get_trusted_tool_plan(f"Observe {readonly_url} and summarize.")
    # Workflow inference agrees.
    assert _infer_tool_for_sub_goal({"selected_tools": [], "objective": "Open the page in the real browser"}) == "browser_controller"
    assert _infer_tool_for_sub_goal({"selected_tools": [], "objective": "Observe the page content"}) == "browser_observer"


# ---------------------------------------------------------------------------
# C. Approval enforcement
# ---------------------------------------------------------------------------


def test_missing_approval_blocks_before_dispatch(tmp_path, fake_playwright):
    url = _runtime_url()
    spec = {"controller_action": "open_page", "url": url}
    state, approvals_db = _controller_lineage(tmp_path, url=url, spec=spec)
    del state["approval_id"]
    result = execute_authorized_action(state, workspace_root=str(tmp_path), db_path=approvals_db)
    assert result["status"] == "BLOCKED"
    assert fake_playwright.calls == 0


def test_wrong_approval_binding_blocks_and_strands_nothing(tmp_path, fake_playwright):
    url = _runtime_url()
    other = _runtime_url()
    context = _context("task-bind", url, str(tmp_path))
    spec = {"controller_action": "open_page", "url": url}
    state, approvals_db = _controller_lineage(tmp_path, url=url, spec=spec, context=context)
    state["action_target"] = other  # drift from the approved target
    result = execute_authorized_action(state, workspace_root=str(tmp_path), db_path=approvals_db)
    assert result["status"] == "BLOCKED"
    assert fake_playwright.calls == 0


def test_modified_evidence_hash_blocks(tmp_path, fake_playwright):
    url = _runtime_url()
    context = _context("task-evidence", url, str(tmp_path))
    spec = {"controller_action": "open_page", "url": url}
    state, approvals_db = _controller_lineage(tmp_path, url=url, spec=spec, context=context)
    tampered = dict(context)
    tampered["evidence_hash"] = "0" * 64
    state["capability_context"] = tampered
    result = execute_authorized_action(state, workspace_root=str(tmp_path), db_path=approvals_db)
    assert result["status"] == "BLOCKED"
    assert fake_playwright.calls == 0


def test_unsupported_controller_action_fails_closed_after_claim(tmp_path, fake_playwright):
    url = _runtime_url()
    spec = {"controller_action": "page.evaluate('alert(1)')", "url": url}
    state, approvals_db = _controller_lineage(tmp_path, url=url, spec=spec)
    result = execute_authorized_action(state, workspace_root=str(tmp_path), db_path=approvals_db)
    assert result["status"] in {"BLOCKED", "VERIFICATION_FAILED"}
    assert fake_playwright.calls == 0


# ---------------------------------------------------------------------------
# D. Grounding enforcement
# ---------------------------------------------------------------------------


def test_stale_grounding_blocks_interaction(tmp_path):
    import time

    url = _runtime_url()
    context = _context("task-ground", url, str(tmp_path))
    _ACTIVE_PAGES["page:9"] = {
        "page_id": "page:9",
        "page": _FakePage(),
        "url": url,
        "grounded_map": {},
        "grounded_elements": [],
        "last_observed_at": time.time() - browser_controller_module.GROUNDING_TTL_SECONDS - 5,
        "task_id": "task-ground",
        "subgoal_id": "open_real_browser_page",
    }
    result = execute_browser_controller_action(
        {"controller_action": "click_element", "page_id": "page:9", "grounded_id": "button:0"},
        {},
        approved=True,
        capability_context=context,
    )
    assert result["status"] == "BLOCKED"


def test_wrong_task_binding_blocks_interaction(tmp_path):
    import time

    url = _runtime_url()
    context = _context("task-other", url, str(tmp_path))
    _ACTIVE_PAGES["page:7"] = {
        "page_id": "page:7",
        "page": _FakePage(),
        "url": url,
        "grounded_map": {},
        "grounded_elements": [],
        "last_observed_at": time.time(),
        "task_id": "task-ground",
        "subgoal_id": "open_real_browser_page",
    }
    result = execute_browser_controller_action(
        {"controller_action": "inspect_page", "page_id": "page:7"},
        {},
        approved=True,
        capability_context=context,
    )
    assert result["status"] == "BLOCKED"


def test_grounded_click_and_type_succeed_with_fresh_binding(tmp_path, fake_playwright, captured_audits):
    url = _runtime_url()
    context = _context("task-click", url, str(tmp_path))
    opened = browser_controller_entrypoint(
        "open_page", url=url, timeout_seconds=15, approved=True, capability_context=context
    )
    assert opened["status"] == "OK"
    page_id = opened["page_id"]
    clicked = browser_controller_entrypoint(
        "click_element", page_id=page_id, grounded_id="button:0",
        approved=True, action_count=0, capability_context=context,
    )
    assert clicked["status"] == "COMPLETED"
    assert clicked["verification"] == "SUCCESS"
    typed = browser_controller_entrypoint(
        "type_into_field", page_id=page_id, grounded_id="textbox:1", value="hello probe",
        approved=True, action_count=1, capability_context=context,
    )
    assert typed["status"] == "COMPLETED"
    assert "browser_controller_verification" in captured_audits


# ---------------------------------------------------------------------------
# E. SSRF / private-network protection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("target", ["http://127.0.0.1/", "http://localhost/"])
def test_private_targets_blocked_without_navigation(tmp_path, fake_playwright, target):
    spec = {"controller_action": "open_page", "url": target}
    state, approvals_db = _controller_lineage(tmp_path, url=target, spec=spec)
    result = execute_authorized_action(state, workspace_root=str(tmp_path), db_path=approvals_db)
    assert result["status"] in {"BLOCKED", "VERIFICATION_FAILED"}
    assert fake_playwright.calls == 0
    assert fake_playwright.pages == []


# ---------------------------------------------------------------------------
# F. Read-only preservation (no Playwright for observation)
# ---------------------------------------------------------------------------


def test_read_only_observation_uses_urllib_without_browser(tmp_path, fake_playwright, monkeypatch):
    url = _runtime_url()

    def stub_fetch(request_url: str, timeout: int):
        html = (
            "<html><head><title>Probe</title></head>"
            "<body><h1>Hello</h1><p>Read-only evidence.</p></body></html>"
        )
        return html, request_url, False

    monkeypatch.setattr(
        browser_controller_module, "_launch_page",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("Playwright must not launch for read-only observation")),
    )
    observed = observe_browser_page(url, timeout_seconds=10, fetcher=stub_fetch)
    assert observed["status"] == "OK"
    assert observed["url"] == url
    assert "Hello" in (observed.get("visible_text") or "")
    assert fake_playwright.calls == 0
    assert _ACTIVE_PAGES == {}


# ---------------------------------------------------------------------------
# G + H. Proposal planning, verification and audit lineage
# ---------------------------------------------------------------------------


def test_action_proposal_builds_bound_controller_plan(tmp_path, monkeypatch):
    import app.agent.graph as graph_module
    from app.agent.graph import create_action_proposal
    from app.memory.task_ledger import create_task

    events: list[str] = []
    monkeypatch.setattr(
        graph_module, "record_audit_event",
        lambda event_type, **payload: events.append(event_type) or True,
    )
    url = _runtime_url()
    task_id = f"task-{uuid.uuid4().hex[:12]}"
    tasks_db = tmp_path / "tasks.db"
    create_task(f"Open {url} in a real browser.", task_id=task_id, db_path=tasks_db)
    observed = {
        "source": "browser_observer",
        "status": "OK",
        "url": url,
        "final_url": url,
        "title": "Probe",
        "visible_text": "Probe body.",
        "links": [{"url": url, "text": "self"}],
    }
    state: dict[str, Any] = {
        "task_id": task_id,
        "user_request": f"Open {url} in a real browser and report what you see.",
        "request_intent": "BROWSER_ACTION_REQUEST",
        "observation_results": [{"tool": "browser_observer", "status": "ok", "result": observed}],
        "browser_url": url,
        "current_subgoal_id": "open_real_browser_page",
        "environment_fingerprint": str(tmp_path),
        "persistence_db_path": str(tasks_db),
        "journal_db_path": str(tmp_path / "journal.db"),
        "approval_db_path": str(tmp_path / "approvals.db"),
    }
    create_action_proposal(state)
    assert state.get("action_tool") == "browser_controller", state.get("final_outcome")
    assert state.get("action_target") == url
    assert (state.get("action_spec") or {}).get("controller_action") == "open_page"
    assert (state.get("action_spec") or {}).get("url") == url
    context = state.get("capability_context") or {}
    assert context.get("application_id") == "browser"
    assert context.get("tool_name") == "browser_controller"
    assert context.get("target") == url
    assert context.get("task_id") == task_id
    assert state.get("approval_required") is True
    assert "action_proposed" in events


def test_read_only_proposal_never_selects_controller(tmp_path, monkeypatch):
    import app.agent.graph as graph_module
    from app.agent.graph import create_action_proposal
    from app.memory.task_ledger import create_task

    monkeypatch.setattr(
        graph_module, "record_audit_event", lambda event_type, **payload: True,
    )
    url = _runtime_url()
    task_id = f"task-{uuid.uuid4().hex[:12]}"
    tasks_db = tmp_path / "tasks.db"
    create_task(f"Observe {url}.", task_id=task_id, db_path=tasks_db)
    observed = {
        "source": "browser_observer",
        "status": "OK",
        "url": url,
        "final_url": url,
        "title": "Probe",
        "visible_text": "Probe body.",
        "links": [],
    }
    state: dict[str, Any] = {
        "task_id": task_id,
        "user_request": f"Observe {url} and summarize the page.",
        "request_intent": "BROWSER_ACTION_REQUEST",
        "observation_results": [{"tool": "browser_observer", "status": "ok", "result": observed}],
        "browser_url": url,
        "persistence_db_path": str(tasks_db),
        "journal_db_path": str(tmp_path / "journal.db"),
        "approval_db_path": str(tmp_path / "approvals.db"),
    }
    create_action_proposal(state)
    assert state.get("action_tool") != "browser_controller"
