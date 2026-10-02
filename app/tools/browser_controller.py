from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

from app.security.audit_logger import record_audit_event
from app.security.risk_engine import BLOCKED, MEDIUM_RISK, READ_ONLY, evaluate_risk
from app.security.sensitive_data import redact_sensitive_data, redact_text
from app.agent.capability_context import validate_capability_context, context_is_fresh
from app.tools.browser_observer import MAX_TEXT_CHARS, MAX_URL_CHARS, validate_browser_url

MAX_CONTROLLER_TEXT_CHARS = 12_000
MAX_INTERACTIVE_ELEMENTS = 25
MAX_CONTROLLER_ACTIONS = 3
GROUNDING_TTL_SECONDS = 60
MAX_TYPED_VALUE_CHARS = 2000
MAX_ACTIVE_PAGES = 10
_INTERACTIVE_SELECTORS = (
    "button",
    "a",
    "input",
    "textarea",
    "select",
    '[role="button"]',
    '[role="textbox"]',
)

_ACTIVE_PAGES: dict[str, dict[str, Any]] = {}

_BLOCKED_FIELD_TERMS = (
    "password",
    "passphrase",
    "secret",
    "token",
    "api key",
    "authorization",
    "private key",
    "otp",
    "one-time code",
    "payment",
    "credit card",
    "cvv",
)


def _audit(event_type: str, **payload: Any) -> bool:
    return record_audit_event(event_type, **payload)


def _blocked(reason: str, *, risk_decision: dict[str, Any] | None = None) -> dict[str, Any]:
    decision = risk_decision or {
        "risk_level": BLOCKED,
        "allowed": False,
        "approval_required": False,
        "reason": reason,
        "category": "BROWSER_CONTROLLER",
    }
    return redact_sensitive_data({
        "source": "browser_controller",
        "status": "BLOCKED",
        "risk_decision": decision,
        "approved": False,
        "action_result": reason,
        "verification": "NOT_RUN",
    })


def _looks_sensitive(value: str) -> bool:
    lowered = str(value or "").lower()
    if not lowered:
        return False
    return any(term in lowered for term in _BLOCKED_FIELD_TERMS)


def _bounded_text(value: Any, limit: int = MAX_CONTROLLER_TEXT_CHARS) -> str:
    text = redact_text(value)
    return text if len(text) <= limit else text[:limit] + "\n... [TRUNCATED]"


def _build_grounded_item(index: int, *, role: str, label: str, kind: str, selector: str, field_type: str = "") -> dict[str, Any]:
    label_text = (label or "").strip()
    identifier = f"{kind}:{index}"
    return {
        "grounded_id": identifier,
        "role": role,
        "label": _bounded_text(label_text, 500),
        "kind": kind,
        "field_type": field_type,
        "selector": selector,
        "stable_reference": identifier,
        "element_index": index,
    }


def _extract_candidate_attribute(element: Any, attribute_name: str) -> str:
    if isinstance(element, dict):
        if attribute_name in element:
            return str(element.get(attribute_name) or "")
        attributes = element.get("attributes") or {}
        if isinstance(attributes, dict):
            return str(attributes.get(attribute_name) or "")
        return ""
    getter = getattr(element, "get_attribute", None)
    if callable(getter):
        value = getter(attribute_name)
        return str(value or "")
    return ""


def _element_label(element: Any, *, selector: str) -> str:
    if isinstance(element, dict):
        for key in ("label", "text", "placeholder", "name", "aria-label"):
            value = str(element.get(key) or "").strip()
            if value:
                return value
        return ""

    for method_name in ("inner_text", "text_content"):
        method = getattr(element, method_name, None)
        if callable(method):
            value = str(method() or "").strip()
            if value:
                return value
    for attribute_name in ("aria-label", "placeholder", "name"):
        value = _extract_candidate_attribute(element, attribute_name)
        if value:
            return value
    return ""


def _element_field_type(element: Any, *, selector: str, fallback: str = "") -> str:
    if isinstance(element, dict):
        declared = str(element.get("field_type") or element.get("type") or fallback or "").strip().lower()
        if declared:
            return declared
        declared = str(element.get("attributes", {}).get("type") or "").strip().lower()
        if declared:
            return declared
    raw = _extract_candidate_attribute(element, "type").strip().lower()
    if raw:
        return raw
    if selector == "textarea":
        return "textarea"
    if selector == "select":
        return "select"
    return fallback.lower()


def _discover_grounded_elements(page: Any) -> list[dict[str, Any]]:
    if not hasattr(page, "locator"):
        return []

    discovered: list[dict[str, Any]] = []
    seen: set[str] = set()
    for selector in _INTERACTIVE_SELECTORS:
        try:
            locator = page.locator(selector)
            count = int(getattr(locator, "count", lambda: 1)())
        except Exception:
            continue
        for index in range(min(max(count, 0), MAX_INTERACTIVE_ELEMENTS)):
            try:
                item = locator.nth(index) if hasattr(locator, "nth") else locator
            except Exception:
                continue
            label = _element_label(item, selector=selector)
            field_type = _element_field_type(item, selector=selector)
            lowered_label = str(label or "").lower()
            if field_type in {"hidden", "submit", "button", "reset"}:
                continue
            if field_type in {"password", "email", "tel"} or any(term in lowered_label for term in _BLOCKED_FIELD_TERMS):
                continue
            role = "button" if selector in {"button", '[role="button"]'} else "link" if selector == "a" else "textbox" if selector in {"input", "textarea", '[role="textbox"]'} else "field"
            kind = selector.strip("[]\"").split("=")[0].strip() if selector.startswith("[") else selector
            if selector == "textarea":
                kind = "textarea"
            if selector == "select":
                kind = "select"
            if selector in {"input", "textarea", '[role="textbox"]'}:
                kind = "textbox" if field_type not in {"password"} else "password"
            if selector == "a":
                kind = "link"
            if selector == "button":
                kind = "button"
            if selector.startswith("[") and 'role="button"' in selector:
                kind = "button"
            if selector.startswith("[") and 'role="textbox"' in selector:
                kind = "textbox"
            if field_type == "password":
                kind = "password"
            if selector == "input" and field_type in {"hidden", "submit", "button"}:
                continue
            item_data = _build_grounded_item(index, role=role, label=label, kind=kind, selector=selector, field_type=field_type)
            stable = item_data["stable_reference"]
            if stable in seen:
                continue
            seen.add(stable)
            discovered.append(item_data)
            if len(discovered) >= MAX_INTERACTIVE_ELEMENTS:
                return discovered
    return discovered


def _snapshot_page(page: Any) -> dict[str, Any]:
    if isinstance(page, dict):
        snapshot = dict(page)
    else:
        visible_text = ""
        if hasattr(page, "locator"):
            try:
                visible_text = page.locator("body").inner_text() or ""
            except Exception:
                visible_text = ""

        title_value = getattr(page, "title", "")
        if callable(title_value):
            title_value = title_value() or ""

        snapshot = {
            "url": getattr(page, "url", "") or "",
            "title": str(title_value or ""),
            "visible_text": visible_text,
            "grounded_elements": _discover_grounded_elements(page),
        }

    url = str(snapshot.get("url") or "").strip()
    title = _bounded_text(snapshot.get("title") or "", 500)
    visible_text = _bounded_text(snapshot.get("visible_text") or "", MAX_CONTROLLER_TEXT_CHARS)

    grounded_elements = snapshot.get("grounded_elements") or []
    if not isinstance(grounded_elements, list):
        grounded_elements = []

    cleaned: list[dict[str, Any]] = []
    for index, element in enumerate(grounded_elements[:MAX_INTERACTIVE_ELEMENTS]):
        if not isinstance(element, dict):
            continue
        role = str(element.get("role") or element.get("tag") or "unknown").strip() or "unknown"
        label = str(element.get("label") or element.get("text") or element.get("placeholder") or "").strip()
        kind = str(element.get("kind") or role).strip() or "unknown"
        selector = str(element.get("selector") or element.get("stable_reference") or f"{role}:{index}").strip()
        field_type = str(element.get("field_type") or "").strip().lower()
        cleaned.append(_build_grounded_item(index, role=role, label=label, kind=kind, selector=selector, field_type=field_type))

    return {
        "url": url,
        "title": title,
        "visible_text": visible_text,
        "grounded_elements": cleaned,
    }


def close_page(page_id: str) -> bool:
    """Close one controller browser session and drop its registry record.

    Best effort and idempotent: unknown page identifiers report False.
    Bounds session lifetime so completed browser sessions do not accumulate
    Playwright browser processes.
    """
    record = _ACTIVE_PAGES.pop(str(page_id or ""), None)
    if record is None:
        return False
    for key in ("browser", "playwright_manager", "playwright"):
        handle = record.get(key)
        if handle is None:
            continue
        for method_name in ("close", "stop", "__exit__"):
            method = getattr(handle, method_name, None)
            if not callable(method):
                continue
            try:
                if method_name == "__exit__":
                    method(None, None, None)
                else:
                    method()
                break
            except Exception:
                continue
    _audit("browser_controller_closed", actor="nexus", tool="browser_controller", target=str(record.get("url") or page_id), result="Session closed.")
    return True


def _evict_oldest_page() -> None:
    """Drop stalest registry entries (closing their browsers) at capacity."""
    while len(_ACTIVE_PAGES) >= MAX_ACTIVE_PAGES:
        oldest_id = min(
            _ACTIVE_PAGES,
            key=lambda page_id: float(_ACTIVE_PAGES[page_id].get("last_observed_at") or 0),
            default=None,
        )
        if oldest_id is None:
            return
        close_page(oldest_id)


def _fresh_page_state(page_id: str) -> dict[str, Any]:
    record = _ACTIVE_PAGES.get(page_id)
    if not record:
        raise ValueError("No active browser page is registered for this page_id.")

    current_page = record.get("page")
    snapshot = _snapshot_page(current_page)
    record["url"] = snapshot["url"] or record.get("url", "")
    record["title"] = snapshot["title"]
    record["visible_text"] = snapshot["visible_text"]
    record["grounded_elements"] = snapshot["grounded_elements"]
    record["grounded_map"] = {item["grounded_id"]: item for item in record["grounded_elements"]}
    record["last_observed_at"] = time.time()
    return record


def _get_page_record(page_id: str, capability_context: dict[str, Any] | None = None) -> dict[str, Any]:
    record = _ACTIVE_PAGES.get(page_id)
    if record is None:
        raise ValueError("Page is not active or has expired.")
    if time.time() - record.get("last_observed_at", 0) > GROUNDING_TTL_SECONDS:
        raise ValueError("The browser page grounding is stale. Re-observe the page before interacting.")
    if capability_context is not None:
        safe_context = validate_capability_context(capability_context)
        if not context_is_fresh(safe_context):
            raise ValueError("The browser capability context is stale.")
        if safe_context.get("application_id") != "browser":
            raise ValueError("The capability context is not a browser context.")
        if safe_context.get("task_id") != record.get("task_id") or safe_context.get("subgoal_id") != record.get("subgoal_id"):
            raise ValueError("The browser page belongs to a different task or subgoal.")
    return record


def _validate_browser_action_target(url: str) -> str:
    normalized = validate_browser_url(url)
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local") or host.endswith(".internal"):
        raise ValueError("Private or internal browser targets are blocked.")
    return normalized


def _ensure_grounded_target(record: dict[str, Any], grounded_id: str, *, action_name: str) -> dict[str, Any]:
    if not grounded_id or not isinstance(grounded_id, str):
        raise ValueError(f"{action_name} requires a grounded element identifier from a fresh observation.")
    item = record["grounded_map"].get(grounded_id)
    if item is None:
        raise ValueError(f"{action_name} requires a currently grounded element that still exists on the page.")

    lowered = str(item.get("label") or "").lower()
    field_type = str(item.get("field_type") or "").lower()
    if field_type in {"password", "email", "tel"} or any(term in lowered for term in _BLOCKED_FIELD_TERMS):
        raise ValueError("Credential or sensitive browser fields are blocked.")
    return item


def _require_approval(action_name: str, *, risk_decision: dict[str, Any], target_url: str) -> dict[str, Any]:
    _audit(
        "browser_controller_approval_requested",
        actor="nexus",
        tool="browser_controller",
        risk_level=risk_decision["risk_level"],
        approval_required=True,
        approved=False,
        target=target_url,
        result="Approval required for grounded browser interaction.",
    )
    return redact_sensitive_data({
        "source": "browser_controller",
        "status": "APPROVAL_REQUIRED",
        "risk_decision": risk_decision,
        "approved": False,
        "action": action_name,
        "target_url": target_url,
        "verification": "NOT_RUN",
    })


def _launch_page(url: str, *, timeout_seconds: int = 15) -> tuple[Any, Any, Any, Any]:
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # pragma: no cover - exercised by installation check in tests
        raise RuntimeError("Playwright is not installed. Install with: python -m playwright install chromium") from exc

    manager = sync_playwright()
    playwright = manager.__enter__()
    browser = playwright.chromium.launch(headless=True)
    page = browser.new_page(viewport={"width": 1280, "height": 720})
    page.goto(url, wait_until="domcontentloaded", timeout=min(max(timeout_seconds, 5), 30) * 1000)
    return manager, playwright, browser, page


def open_page(url: str, *, timeout_seconds: int = 15, approved: bool = False, capability_context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Open a single authorized public HTTP(S) page and return a bounded grounded observation."""
    try:
        target_url = _validate_browser_action_target(url)
        safe_context = validate_capability_context(capability_context) if capability_context is not None else None
        if safe_context is not None and safe_context.get("application_id") != "browser":
            raise ValueError("The capability context is not a browser context.")
    except ValueError as exc:
        return _blocked(str(exc), risk_decision={"risk_level": BLOCKED, "allowed": False, "approval_required": False, "reason": str(exc), "category": "BROWSER_CONTROLLER"})
    risk_decision = evaluate_risk("observe browser page", tool_name="browser_controller", target_path=None)
    if not risk_decision["allowed"] or risk_decision["risk_level"] == BLOCKED:
        return _blocked(risk_decision["reason"], risk_decision=risk_decision)
    if not approved:
        return _require_approval("open_page", risk_decision=risk_decision, target_url=target_url)

    try:
        manager, playwright, browser, page = _launch_page(target_url, timeout_seconds=timeout_seconds)
    except RuntimeError as exc:
        return {"source": "browser_controller", "status": "ERROR", "error": redact_text(str(exc)), "grounded_elements": []}
    except Exception as exc:  # pragma: no cover - defensive guard
        return {"source": "browser_controller", "status": "ERROR", "error": redact_text(str(exc)), "grounded_elements": []}

    snapshot = _snapshot_page(page)
    snapshot["url"] = target_url

    raw_title = getattr(page, "title", "")
    if callable(raw_title):
        raw_title = raw_title() or ""
    snapshot["title"] = _bounded_text(snapshot.get("title") or str(raw_title or ""), 500)

    body_text = page.locator("body").inner_text() if hasattr(page, "locator") else ""
    snapshot["visible_text"] = _bounded_text(snapshot.get("visible_text") or body_text, MAX_CONTROLLER_TEXT_CHARS)

    grounded = []
    for index, item in enumerate(snapshot.get("grounded_elements", []) or []):
        grounded.append({**item, "selector": str(item.get("selector") or f"{item.get('role', 'element')}:{index}")})
    snapshot["grounded_elements"] = grounded
    page_handle = page
    if hasattr(page, "locator"):
        page_handle = page
    _evict_oldest_page()
    page_id = f"page:{len(_ACTIVE_PAGES) + 1}"
    _ACTIVE_PAGES[page_id] = {
        "page_id": page_id,
        "page": page_handle,
        "playwright_manager": manager,
        "playwright": playwright,
        "browser": browser,
        "url": target_url,
        "title": snapshot["title"],
        "visible_text": snapshot["visible_text"],
        "grounded_elements": snapshot["grounded_elements"],
        "grounded_map": {item["grounded_id"]: item for item in snapshot["grounded_elements"]},
        "last_observed_at": time.time(),
        "task_id": safe_context.get("task_id", "") if safe_context else "",
        "subgoal_id": safe_context.get("subgoal_id", "") if safe_context else "",
        "context_id": safe_context.get("observation_id", "") if safe_context else "",
    }
    _audit("browser_controller_opened", actor="nexus", tool="browser_controller", risk_level=risk_decision["risk_level"], approved=False, target=target_url, result="Open page succeeded.")
    return redact_sensitive_data({
        "source": "browser_controller",
        "status": "OK",
        "risk_decision": risk_decision,
        "page_id": page_id,
        "url": target_url,
        "title": snapshot["title"],
        "visible_text": snapshot["visible_text"],
        "grounded_elements": snapshot["grounded_elements"],
        "verification": "NOT_RUN",
    })


def inspect_loaded_page(page_id: str, *, capability_context: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        record = _get_page_record(page_id, capability_context)
    except ValueError as exc:
        return _blocked(str(exc))

    snapshot = _snapshot_page(record["page"])
    record["url"] = snapshot.get("url") or record.get("url", "")
    record["title"] = snapshot.get("title") or record.get("title", "")
    record["visible_text"] = snapshot.get("visible_text") or record.get("visible_text", "")
    record["grounded_elements"] = snapshot.get("grounded_elements", [])
    record["grounded_map"] = {item["grounded_id"]: item for item in record["grounded_elements"]}
    record["last_observed_at"] = time.time()
    _audit("browser_controller_inspected", actor="nexus", tool="browser_controller", risk_level=READ_ONLY, approved=False, target=record.get("url", page_id), result="Observed page refreshed.")
    return redact_sensitive_data({
        "source": "browser_controller",
        "status": "OK",
        "page_id": page_id,
        "url": record.get("url", ""),
        "title": record.get("title", ""),
        "visible_text": record.get("visible_text", ""),
        "grounded_elements": record.get("grounded_elements", []),
        "verification": "NOT_RUN",
    })


def _perform_grounded_action(
    action_name: str,
    page_id: str,
    grounded_id: str,
    *,
    approved: bool,
    action_count: int,
    value: str | None = None,
    capability_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        record = _get_page_record(page_id, capability_context)
    except ValueError as exc:
        return _blocked(str(exc))

    try:
        target = _ensure_grounded_target(record, grounded_id, action_name=action_name)
    except ValueError as exc:
        return _blocked(str(exc))

    target_url = str(record.get("url") or "").strip()
    if not target_url:
        return _blocked("The active page has no grounded URL.")

    description = f"browser controller {action_name}"
    risk_decision = evaluate_risk(description, tool_name="browser_controller")
    if not risk_decision["allowed"] or risk_decision["risk_level"] == BLOCKED:
        return _blocked(risk_decision["reason"], risk_decision=risk_decision)
    if not approved:
        return _require_approval(action_name, risk_decision=risk_decision, target_url=target_url)
    if action_count >= MAX_CONTROLLER_ACTIONS:
        return _blocked("Browser controller action count limit reached.", risk_decision=risk_decision)

    if action_name in {"click_element", "type_into_field"} and value is not None and _looks_sensitive(value):
        return _blocked("Credential or secret submission is blocked.", risk_decision=risk_decision)

    # Re-check the target still exists on the current page before execution.
    try:
        current = _fresh_page_state(page_id)
        if grounded_id not in current["grounded_map"]:
            raise ValueError("The grounded browser target no longer exists in the current page state.")
    except ValueError as exc:
        return _blocked(str(exc), risk_decision=risk_decision)

    page = record.get("page")
    if page is None:
        return _blocked("The browser controller has no page handle for the active page.", risk_decision=risk_decision)

    selector = str(target.get("selector") or "")
    if not selector or selector.startswith("page:"):
        return _blocked("The proposed browser action did not resolve to a valid grounded element selector.", risk_decision=risk_decision)

    try:
        if action_name == "click_element":
            if hasattr(page, "click"):
                page.click(selector)
            elif hasattr(page, "locator"):
                page.locator(selector).click()
        elif action_name == "type_into_field":
            if value is None:
                raise ValueError("Text input requires a non-empty value.")
            if hasattr(page, "fill"):
                page.fill(selector, str(value))
            elif hasattr(page, "locator"):
                page.locator(selector).fill(str(value))
        elif action_name == "navigate_to_url":
            target_url = _validate_browser_action_target(str(value or ""))
            if hasattr(page, "goto"):
                page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
            else:
                raise ValueError("This browser session does not support navigation.")
        else:
            raise ValueError("Unsupported controller action.")
    except Exception as exc:
        return _blocked(f"Browser controller execution failed: {redact_text(exc)}", risk_decision=risk_decision)

    _audit(
        "browser_controller_executed",
        actor="nexus",
        tool="browser_controller",
        risk_level=risk_decision["risk_level"],
        approval_required=True,
        approved=True,
        target=target_url,
        result=f"{action_name} completed.",
    )

    refreshed = inspect_loaded_page(page_id, capability_context=capability_context)
    verification = "SUCCESS" if refreshed.get("status") == "OK" else "UNCERTAIN"
    result = redact_sensitive_data({
        "source": "browser_controller",
        "status": "COMPLETED" if verification == "SUCCESS" else "UNCERTAIN",
        "risk_decision": risk_decision,
        "approved": True,
        "page_id": page_id,
        "action": action_name,
        "target_url": target_url,
        "action_result": refreshed,
        "verification": verification,
        "retry_allowed": False,
    })
    _audit(
        "browser_controller_verification",
        actor="nexus",
        tool="browser_controller",
        risk_level=risk_decision["risk_level"],
        approved=True,
        target=target_url,
        result=verification,
    )
    return result


def click_element(page_id: str, grounded_id: str, *, approved: bool = False, action_count: int = 0, capability_context: dict[str, Any] | None = None) -> dict[str, Any]:
    return _perform_grounded_action("click_element", page_id, grounded_id, approved=approved, action_count=action_count, capability_context=capability_context)


def type_into_field(page_id: str, grounded_id: str, value: str, *, approved: bool = False, action_count: int = 0, capability_context: dict[str, Any] | None = None) -> dict[str, Any]:
    return _perform_grounded_action("type_into_field", page_id, grounded_id, approved=approved, action_count=action_count, value=value, capability_context=capability_context)


def navigate_to_url(page_id: str, target_url: str, *, approved: bool = False, action_count: int = 0, capability_context: dict[str, Any] | None = None) -> dict[str, Any]:
    if not target_url or not isinstance(target_url, str):
        return _blocked("A grounded URL target is required.")
    try:
        record = _get_page_record(page_id, capability_context)
    except ValueError as exc:
        return _blocked(str(exc))
    try:
        requested = _validate_browser_action_target(target_url)
    except ValueError as exc:
        return _blocked(str(exc), risk_decision={"risk_level": BLOCKED, "allowed": False, "approval_required": False, "reason": str(exc), "category": "BROWSER_CONTROLLER"})
    description = "browser controller navigate_to_url"
    risk_decision = evaluate_risk(description, tool_name="browser_controller")
    if not risk_decision["allowed"] or risk_decision["risk_level"] == BLOCKED:
        return _blocked(risk_decision["reason"], risk_decision=risk_decision)
    if not approved:
        return _require_approval("navigate_to_url", risk_decision=risk_decision, target_url=requested)
    if action_count >= MAX_CONTROLLER_ACTIONS:
        return _blocked("Browser controller action count limit reached.", risk_decision=risk_decision)

    page = record.get("page")
    if page is None or not hasattr(page, "goto"):
        return _blocked("The page cannot navigate because it does not support goto().", risk_decision=risk_decision)

    try:
        page.goto(requested, wait_until="domcontentloaded", timeout=15000)
    except Exception as exc:
        return _blocked(f"Navigation failed: {redact_text(exc)}", risk_decision=risk_decision)

    refreshed = inspect_loaded_page(page_id, capability_context=capability_context)
    verification = "SUCCESS" if refreshed.get("status") == "OK" else "UNCERTAIN"
    result = redact_sensitive_data({
        "source": "browser_controller",
        "status": "COMPLETED" if verification == "SUCCESS" else "UNCERTAIN",
        "risk_decision": risk_decision,
        "approved": True,
        "page_id": page_id,
        "action": "navigate_to_url",
        "target_url": requested,
        "action_result": refreshed,
        "verification": verification,
        "retry_allowed": False,
    })
    _audit(
        "browser_controller_verification",
        actor="nexus",
        tool="browser_controller",
        risk_level=risk_decision["risk_level"],
        approved=True,
        target=requested,
        result=verification,
    )
    return result


def browser_controller_entrypoint(action: str, **kwargs: Any) -> dict[str, Any]:
    action_name = str(action or "").strip()
    mapping = {
        "open_page": open_page,
        "inspect_page": inspect_loaded_page,
        "click_element": click_element,
        "type_into_field": type_into_field,
        "navigate_to_url": navigate_to_url,
    }
    if action_name not in mapping:
        raise ValueError("Unsupported browser controller action.")
    callable_action = mapping[action_name]
    if action_name in {"open_page"}:
        return callable_action(kwargs.get("url", ""), timeout_seconds=int(kwargs.get("timeout_seconds", 15)), approved=bool(kwargs.get("approved", False)), capability_context=kwargs.get("capability_context"))
    if action_name == "inspect_page":
        return callable_action(str(kwargs.get("page_id", "")), capability_context=kwargs.get("capability_context"))
    if action_name == "click_element":
        return callable_action(
            str(kwargs.get("page_id", "")),
            str(kwargs.get("grounded_id", "")),
            approved=bool(kwargs.get("approved", False)),
            action_count=int(kwargs.get("action_count", 0)),
            capability_context=kwargs.get("capability_context"),
        )
    if action_name == "type_into_field":
        return callable_action(
            str(kwargs.get("page_id", "")),
            str(kwargs.get("grounded_id", "")),
            str(kwargs.get("value", "")),
            approved=bool(kwargs.get("approved", False)),
            action_count=int(kwargs.get("action_count", 0)),
            capability_context=kwargs.get("capability_context"),
        )
    return callable_action(
        str(kwargs.get("page_id", "")),
        str(kwargs.get("target_url", "")),
        approved=bool(kwargs.get("approved", False)),
        action_count=int(kwargs.get("action_count", 0)),
        capability_context=kwargs.get("capability_context"),
    )


__all__ = [
    "MAX_ACTIVE_PAGES",
    "browser_controller_entrypoint",
    "click_element",
    "close_page",
    "inspect_loaded_page",
    "navigate_to_url",
    "open_page",
    "type_into_field",
]
