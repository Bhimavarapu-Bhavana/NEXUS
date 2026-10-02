"""STEP 7: browser security integration — gap-fill only (no production changes).

MOCKED PLAYWRIGHT — ROUTING/GOVERNANCE PROOF.

Fake Playwright at the ``playwright.sync_api.sync_playwright`` boundary;
runtime ``*.test`` URLs (hermetic DNS stub); no external network; no hardcoded
site. Proves requirements not already covered by
``test_phase37_real_browser_integration.py``:

  5. missing URL never fabricates navigation
  8. wrong subgoal binding blocks
  14. credential/OTP/payment-sensitive interaction blocked
  16. failed verification never becomes success (approval invalidated, not consumed)
  17. page lifecycle bounded (MAX_ACTIVE_PAGES + close_page idempotent)
  18. action-count bounded (MAX_CONTROLLER_ACTIONS)

All other STEP 7 requirements (1-4,6,7,9-13,15,19,20) are already proven by
the existing Phase 37 suite and are referenced, not duplicated, here.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import app.tools.browser_controller as browser_controller_module
from app.agent.action_executor import execute_authorized_action, proposal_hash
from app.agent.approval_authority import create_approval, decide_approval, get_approval
from app.agent.capability_context import build_capability_context
from app.agent.execution_journal import create_checkpoint
from app.tools.browser_controller import (
    _ACTIVE_PAGES,
    MAX_ACTIVE_PAGES,
    MAX_CONTROLLER_ACTIONS,
    browser_controller_entrypoint,
    close_page,
)
from app.tools.tool_registry import TOOL_REGISTRY


_PROBE_IP = "1.1.1.1"


def _runtime_url() -> str:
    return f"https://probe-{uuid.uuid4().hex[:12]}.test"


def test_tool_registry_browser_metadata_unchanged():
    assert TOOL_REGISTRY["browser_observer"]["read_only"] is True
    assert TOOL_REGISTRY["browser_observer"]["requires_approval"] is False
    assert TOOL_REGISTRY["browser_controller"]["read_only"] is False
    assert TOOL_REGISTRY["browser_controller"]["requires_approval"] is True
    assert TOOL_REGISTRY["browser_controller"]["allowed"] is True


import pytest


@pytest.fixture(autouse=True)
def hermetic_probe_dns(monkeypatch):
    import app.tools.browser_observer as observer_module

    real_resolve = observer_module._resolved_addresses

    def fake_resolve(hostname: str) -> list[str]:
        if str(hostname or "").lower().endswith(".test"):
            return [_PROBE_IP]
        return real_resolve(hostname)

    monkeypatch.setattr(observer_module, "_resolved_addresses", fake_resolve)


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

    def __enter__(self) -> _FakePlaywright:
        return _FakePlaywright(self._factory)

    def __exit__(self, *args: Any) -> bool:
        return False

    def stop(self) -> None:
        pass


class _FakePlaywrightFactory:
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


def _context(task_id: str, url: str, fingerprint: str, *, subgoal_id: str = "open_real_browser_page") -> dict[str, Any]:
    return build_capability_context(
        task_id=task_id,
        subgoal_id=subgoal_id,
        application_id="browser",
        capability_id="interact",
        tool_name="browser_controller",
        target=url,
        observation_id=f"obs-{uuid.uuid4().hex[:12]}",
        evidence={"url": url},
        environment_fingerprint=fingerprint,
    )


def _lineage(tmp_path, *, url: str, spec: dict[str, Any], context: dict[str, Any] | None = None):
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


def test_05_missing_url_never_fabricates_navigation(tmp_path, fake_playwright):
    """Req 5: empty/missing target fails closed with zero Playwright launch."""
    url = ""
    spec: dict[str, Any] = {"controller_action": "open_page", "url": ""}
    # Approval authority itself refuses to bind an empty target: no fabrication.
    with pytest.raises(ValueError):
        _lineage(tmp_path, url=url, spec=spec)
    assert fake_playwright.calls == 0
    assert fake_playwright.pages == []
    # Direct controller entrypoint with no URL also fails closed.
    direct = browser_controller_entrypoint("open_page", url="", timeout_seconds=15, approved=True)
    assert direct["status"] == "BLOCKED"
    assert fake_playwright.calls == 0


def test_08_wrong_subgoal_binding_blocks(tmp_path, fake_playwright):
    """Req 8: correct task but wrong subgoal fails closed with zero launch."""
    url = _runtime_url()
    _ACTIVE_PAGES["page:sub"] = {
        "page_id": "page:sub",
        "page": _FakePage(),
        "url": url,
        "grounded_map": {},
        "grounded_elements": [],
        "last_observed_at": time.time(),
        "task_id": "task-same",
        "subgoal_id": "open_real_browser_page",
    }
    context = _context("task-same", url, str(tmp_path), subgoal_id="different_subgoal")
    from app.agent.action_executor import execute_browser_controller_action

    result = execute_browser_controller_action(
        {"controller_action": "inspect_page", "page_id": "page:sub"},
        {},
        approved=True,
        capability_context=context,
    )
    assert result["status"] == "BLOCKED"
    assert fake_playwright.calls == 0


def test_14_credential_otp_payment_values_blocked(tmp_path, fake_playwright):
    """Req 14: sensitive typed values never reach the page."""
    url = _runtime_url()
    context = _context("task-sensitive", url, str(tmp_path))
    opened = browser_controller_entrypoint(
        "open_page", url=url, timeout_seconds=15, approved=True, capability_context=context
    )
    assert opened["status"] == "OK"
    page_id = opened["page_id"]
    assert fake_playwright.calls == 1
    for sensitive in ("my password is hunter2", "api secret token abc", "otp 123456", "credit card 4111"):
        blocked = browser_controller_entrypoint(
            "type_into_field",
            page_id=page_id,
            grounded_id="textbox:1",
            value=sensitive,
            approved=True,
            action_count=1,
            capability_context=context,
        )
        assert blocked["status"] == "BLOCKED", sensitive
    # No sensitive fill ever reached the fake page.
    page = browser_controller_module._ACTIVE_PAGES[page_id]["page"]
    assert page.filled == {}
    assert fake_playwright.calls == 1  # only the initial open_page launch


def test_16_failed_verification_invalidates_without_success(tmp_path, fake_playwright):
    """Req 16: unsupported action fails closed; approval never CONSUMED."""
    url = _runtime_url()
    spec = {"controller_action": "page.evaluate('alert(1)')", "url": url}
    state, approvals_db = _lineage(tmp_path, url=url, spec=spec)
    result = execute_authorized_action(state, workspace_root=str(tmp_path), db_path=approvals_db)
    assert result["status"] in {"BLOCKED", "VERIFICATION_FAILED"}
    assert result.get("verification") != "SUCCESS"
    assert fake_playwright.calls == 0
    approval = get_approval(state["approval_id"], db_path=approvals_db)
    assert approval["status"] != "CONSUMED"


def test_17_page_lifecycle_bounded(tmp_path, fake_playwright):
    """Req 17: registry evicts at capacity; close_page idempotent."""
    assert MAX_ACTIVE_PAGES >= 2
    opened_ids: list[str] = []
    for _ in range(MAX_ACTIVE_PAGES + 2):
        url = _runtime_url()
        context = _context(f"task-{uuid.uuid4().hex[:8]}", url, str(tmp_path))
        opened = browser_controller_entrypoint(
            "open_page", url=url, timeout_seconds=15, approved=True, capability_context=context
        )
        assert opened["status"] == "OK"
        opened_ids.append(opened["page_id"])
    assert len(_ACTIVE_PAGES) <= MAX_ACTIVE_PAGES
    assert fake_playwright.calls == MAX_ACTIVE_PAGES + 2
    # Evicted browsers were closed.
    assert any(browser.closed for browser in fake_playwright.browsers)
    survivor = next(iter(_ACTIVE_PAGES.keys()))
    assert close_page(survivor) is True
    assert close_page(survivor) is False
    assert close_page("page:does-not-exist") is False


def test_18_action_count_bounded(tmp_path, fake_playwright):
    """Req 18: action_count at limit blocks before any page interaction."""
    url = _runtime_url()
    context = _context("task-count", url, str(tmp_path))
    opened = browser_controller_entrypoint(
        "open_page", url=url, timeout_seconds=15, approved=True, capability_context=context
    )
    assert opened["status"] == "OK"
    page_id = opened["page_id"]
    page = browser_controller_module._ACTIVE_PAGES[page_id]["page"]
    assert page.clicked == []
    blocked = browser_controller_entrypoint(
        "click_element",
        page_id=page_id,
        grounded_id="button:0",
        approved=True,
        action_count=int(MAX_CONTROLLER_ACTIONS),
        capability_context=context,
    )
    assert blocked["status"] == "BLOCKED"
    assert page.clicked == []
    assert fake_playwright.calls == 1
