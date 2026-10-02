import time

import pytest

import app.tools.browser_controller as browser_controller


class FakeElement:
    def __init__(self, selector: str, *, text: str = "", attributes: dict[str, str] | None = None):
        self.selector = selector
        self._text = text
        self._attributes = attributes or {}
        self.value = self._attributes.get("value", "")
        self.clicked = False
        self.filled = ""

    def inner_text(self):
        return self._text

    def text_content(self):
        return self._text

    def get_attribute(self, name: str):
        return self._attributes.get(name)

    def input_value(self):
        return self.value

    def click(self):
        self.clicked = True

    def fill(self, value: str):
        self.filled = value
        self.value = value


class FakeLocator:
    def __init__(self, selector: str, elements: list[FakeElement]):
        self.selector = selector
        self._elements = list(elements)

    def count(self):
        return len(self._elements)

    def nth(self, index: int):
        return self._elements[index]

    def all(self):
        return list(self._elements)

    def first(self):
        return self._elements[0] if self._elements else FakeElement(self.selector, text="")

    def __iter__(self):
        return iter(self._elements)


class FakePage:
    def __init__(self):
        self.url = "https://example.com"
        self.title = "Example Domain"
        self._button = FakeElement("button", text="Submit")
        self._link = FakeElement("a", text="Next page")
        self._text = FakeElement("input", text="", attributes={"type": "text", "name": "query"})
        self._password = FakeElement("input", text="", attributes={"type": "password", "name": "password"})
        self._token = FakeElement("input", text="", attributes={"type": "text", "name": "token"})
        self._textarea = FakeElement("textarea", text="", attributes={"name": "notes"})
        self._selector_records = {
            "button": [self._button],
            "a": [self._link],
            "input": [self._text, self._password, self._token],
            "textarea": [self._textarea],
            '[role="button"]': [self._button],
            '[role="textbox"]': [self._text, self._textarea],
        }

    def locator(self, selector: str):
        return FakeLocator(selector, self._selector_records.get(selector, []))

    def click(self, selector: str):
        for items in self._selector_records.values():
            for element in items:
                if element.selector == selector:
                    element.clicked = True
                    return
        raise ValueError(f"selector not found: {selector}")

    def fill(self, selector: str, value: str):
        for items in self._selector_records.values():
            for element in items:
                if element.selector == selector:
                    element.filled = value
                    element.value = value
                    return
        raise ValueError(f"selector not found: {selector}")

    def goto(self, url: str, *, wait_until: str, timeout: int):
        self.url = url


@pytest.fixture
def page_fixture():
    page = FakePage()
    browser_controller._ACTIVE_PAGES.clear()
    browser_controller._ACTIVE_PAGES["page:1"] = {
        "page_id": "page:1",
        "page": page,
        "url": "https://example.com",
        "title": "Example Domain",
        "visible_text": "Example Domain",
        "grounded_elements": [],
        "grounded_map": {},
        "last_observed_at": time.time(),
    }
    return page


def test_real_interactive_element_discovery_is_bounded(page_fixture):
    discovered = browser_controller._discover_grounded_elements(page_fixture)

    assert discovered
    assert len(discovered) <= browser_controller.MAX_INTERACTIVE_ELEMENTS
    assert any(item["kind"] in {"button", "link", "textbox", "textarea"} for item in discovered)
    assert all("grounded_id" in item for item in discovered)


def test_click_requires_approval(page_fixture):
    page_fixture._selector_records["button"] = [FakeElement("button", text="Submit")]
    record = browser_controller._ACTIVE_PAGES["page:1"]
    record["grounded_elements"] = browser_controller._snapshot_page(page_fixture)["grounded_elements"]
    record["grounded_map"] = {item["grounded_id"]: item for item in record["grounded_elements"]}

    result = browser_controller.click_element("page:1", record["grounded_elements"][0]["grounded_id"], approved=False)

    assert result["status"] == "APPROVAL_REQUIRED"
    assert result["risk_decision"]["approval_required"] is True


def test_type_requires_approval(page_fixture):
    record = browser_controller._ACTIVE_PAGES["page:1"]
    record["grounded_elements"] = browser_controller._snapshot_page(page_fixture)["grounded_elements"]
    record["grounded_map"] = {item["grounded_id"]: item for item in record["grounded_elements"]}

    result = browser_controller.type_into_field(
        "page:1",
        record["grounded_elements"][0]["grounded_id"],
        "hello world",
        approved=False,
    )

    assert result["status"] == "APPROVAL_REQUIRED"


def test_grounded_click_executes_and_verifies(page_fixture, monkeypatch):
    record = browser_controller._ACTIVE_PAGES["page:1"]
    record["grounded_elements"] = browser_controller._snapshot_page(page_fixture)["grounded_elements"]
    record["grounded_map"] = {item["grounded_id"]: item for item in record["grounded_elements"]}
    button_id = next(item["grounded_id"] for item in record["grounded_elements"] if item["role"] == "button")

    monkeypatch.setattr(browser_controller, "record_audit_event", lambda *args, **kwargs: True)

    result = browser_controller.click_element("page:1", button_id, approved=True)

    assert result["status"] == "COMPLETED"
    assert result["verification"] in {"SUCCESS", "UNCERTAIN"}
    assert result["action_result"]["status"] == "OK"


def test_grounded_typing_uses_observed_field_and_does_not_submit(page_fixture, monkeypatch):
    record = browser_controller._ACTIVE_PAGES["page:1"]
    record["grounded_elements"] = browser_controller._snapshot_page(page_fixture)["grounded_elements"]
    record["grounded_map"] = {item["grounded_id"]: item for item in record["grounded_elements"]}
    text_id = next(item["grounded_id"] for item in record["grounded_elements"] if item["field_type"] == "text")

    monkeypatch.setattr(browser_controller, "record_audit_event", lambda *args, **kwargs: True)

    result = browser_controller.type_into_field("page:1", text_id, "hello world", approved=True)

    assert result["status"] == "COMPLETED"
    assert result["action_result"]["status"] == "OK"
    assert page_fixture._text.value == "hello world"


def test_sensitive_field_and_sensitive_values_are_blocked(page_fixture):
    record = browser_controller._ACTIVE_PAGES["page:1"]
    record["grounded_elements"] = browser_controller._snapshot_page(page_fixture)["grounded_elements"]
    record["grounded_map"] = {item["grounded_id"]: item for item in record["grounded_elements"]}

    assert all(item["field_type"] != "password" for item in record["grounded_elements"])

    blocked_password = browser_controller.type_into_field("page:1", "password:0", "literal-password", approved=True)
    assert blocked_password["status"] == "BLOCKED"

    text_id = next(item["grounded_id"] for item in record["grounded_elements"] if item["field_type"] == "text")
    blocked_value = browser_controller.type_into_field("page:1", text_id, "password=super_secret", approved=True)
    assert blocked_value["status"] == "BLOCKED"


def test_stale_grounding_is_rejected(page_fixture):
    record = browser_controller._ACTIVE_PAGES["page:1"]
    record["grounded_elements"] = browser_controller._snapshot_page(page_fixture)["grounded_elements"]
    record["grounded_map"] = {item["grounded_id"]: item for item in record["grounded_elements"]}
    button_id = next(item["grounded_id"] for item in record["grounded_elements"] if item["role"] == "button")

    page_fixture._selector_records = {"button": [], "a": [], "input": [], "textarea": [], '[role="button"]': [], '[role="textbox"]': []}
    action = browser_controller.click_element("page:1", button_id, approved=True)

    assert action["status"] == "BLOCKED"


def test_arbitrary_selector_protection(page_fixture):
    record = browser_controller._ACTIVE_PAGES["page:1"]
    record["grounded_elements"] = browser_controller._snapshot_page(page_fixture)["grounded_elements"]
    record["grounded_map"] = {item["grounded_id"]: item for item in record["grounded_elements"]}

    arbitrary_click = browser_controller.click_element("page:1", "div:999", approved=True)
    arbitrary_type = browser_controller.type_into_field("page:1", "div:999", "hello", approved=True)

    assert arbitrary_click["status"] == "BLOCKED"
    assert arbitrary_type["status"] == "BLOCKED"


def test_post_action_verification_and_audit_record(page_fixture, monkeypatch):
    events = []
    monkeypatch.setattr(browser_controller, "record_audit_event", lambda event_type, **payload: events.append(event_type) or True)

    record = browser_controller._ACTIVE_PAGES["page:1"]
    record["grounded_elements"] = browser_controller._snapshot_page(page_fixture)["grounded_elements"]
    record["grounded_map"] = {item["grounded_id"]: item for item in record["grounded_elements"]}
    button_id = next(item["grounded_id"] for item in record["grounded_elements"] if item["role"] == "button")

    result = browser_controller.click_element("page:1", button_id, approved=True)

    assert result["verification"] in {"SUCCESS", "UNCERTAIN"}
    assert "browser_controller_executed" in events or "browser_controller_verification" in events
    assert "super_secret" not in str(result)
    assert "password" not in str(result).lower()


def test_existing_browser_observer_and_action_contract_remains_valid(page_fixture):
    decision = browser_controller.evaluate_risk("observe browser page", tool_name="browser_controller")
    assert decision["risk_level"] == browser_controller.MEDIUM_RISK
    assert decision["approval_required"] is True
    assert browser_controller._get_page_record("page:1")["page_id"] == "page:1"
