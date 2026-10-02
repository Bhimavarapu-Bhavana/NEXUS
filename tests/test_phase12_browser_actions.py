import pytest

from app.security.risk_engine import BLOCKED, MEDIUM_RISK, READ_ONLY, evaluate_risk
from app.tools import browser_actions
from app.tools.browser_actions import (
    MAX_BROWSER_ACTIONS,
    follow_observed_link,
    navigate_observed_page,
)
from app.tools.browser_observer import observe_browser_page
from app.tools.tool_registry import TOOL_REGISTRY, get_trusted_tool_plan, get_tool_risk


@pytest.fixture
def action_environment(monkeypatch):
    monkeypatch.setattr(browser_actions, "record_audit_event", lambda *args, **kwargs: True)
    monkeypatch.setattr(browser_actions, "validate_browser_url", lambda url: str(url).split("#", 1)[0])
    return {
        "status": "OK",
        "url": "https://example.com",
        "final_url": "https://example.com",
        "links": [{"text": "Next", "url": "https://example.com/next"}],
    }


def _link_action():
    return {
        "action_type": "follow_observed_link",
        "target_url": "https://example.com/next",
        "observed_target": "https://example.com",
        "element_identifier": "https://example.com/next",
        "requested_value": "",
        "justification": "follow the observed next link",
        "risk_level": "LOW_RISK",
    }


def _page_action():
    return {
        "action_type": "navigate_observed",
        "target_url": "https://example.com",
        "observed_target": "https://example.com",
        "element_identifier": "page",
        "requested_value": "",
        "justification": "re-observe the current authorized page",
        "risk_level": "LOW_RISK",
    }


def test_structured_valid_observed_target_requires_approval(action_environment):
    result = follow_observed_link(_link_action(), action_environment)

    assert result["status"] == "APPROVAL_REQUIRED"
    assert result["risk_decision"]["risk_level"] == MEDIUM_RISK
    assert result["risk_decision"]["approval_required"] is True


def test_unknown_action_is_blocked(action_environment):
    action = _link_action()
    action["action_type"] = "arbitrary_click"

    result = follow_observed_link(action, action_environment)

    assert result["status"] == "BLOCKED"
    assert result["risk_decision"]["risk_level"] == BLOCKED


def test_arbitrary_javascript_is_blocked(action_environment):
    action = _page_action()
    action["target_url"] = "javascript:alert(1)"

    result = navigate_observed_page(action, action_environment, approved=True)

    assert result["status"] == "BLOCKED"


@pytest.mark.parametrize("element_identifier", [
    "password_field",
    "credential_token",
    "payment_card_number",
    "otp_security_code",
])
def test_credentials_and_payment_targets_are_blocked(action_environment, element_identifier):
    action = _link_action()
    action["element_identifier"] = element_identifier

    result = follow_observed_link(action, action_environment, approved=True)

    assert result["status"] == "BLOCKED"


def test_destructive_and_purchase_risk_are_blocked():
    assert evaluate_risk("delete remote resource")["risk_level"] == BLOCKED
    assert evaluate_risk("purchase product")["risk_level"] == BLOCKED
    assert evaluate_risk("submit payment form")["risk_level"] == BLOCKED


def test_private_and_credential_bearing_urls_are_blocked(action_environment, monkeypatch):
    monkeypatch.setattr(browser_actions, "validate_browser_url", observe_browser_page.__globals__["validate_browser_url"])

    for target in ("http://127.0.0.1", "https://user:password@example.com"):
        action = _page_action()
        action["target_url"] = target
        result = navigate_observed_page(action, action_environment, approved=True)
        assert result["status"] == "BLOCKED"


def test_missing_observation_grounding_is_blocked(action_environment):
    action = _link_action()
    action["observed_target"] = "https://other.example"

    result = follow_observed_link(action, action_environment, approved=True)

    assert result["status"] == "BLOCKED"


def test_invented_element_target_is_blocked(action_environment):
    action = _link_action()
    action["target_url"] = "https://example.com/invented"
    action["element_identifier"] = action["target_url"]

    result = follow_observed_link(action, action_environment, approved=True)

    assert result["status"] == "BLOCKED"


def test_valid_observed_target_is_accepted_for_proposal(action_environment):
    result = follow_observed_link(_link_action(), action_environment, approved=False)

    assert result["status"] == "APPROVAL_REQUIRED"
    assert result["approved"] is False


def test_planner_text_cannot_lower_risk(action_environment):
    action = _link_action()
    action["risk_level"] = "READ_ONLY"

    result = follow_observed_link(action, action_environment, approved=False)

    assert result["risk_decision"]["risk_level"] == MEDIUM_RISK
    assert get_tool_risk("browser_follow_observed_link")["risk_level"] == MEDIUM_RISK


def test_approval_cannot_override_blocked(action_environment):
    action = _link_action()
    action["requested_value"] = "password=synthetic_secret"

    result = follow_observed_link(action, action_environment, approved=True)

    assert result["status"] == "BLOCKED"
    assert result["approved"] is False
    assert "synthetic_secret" not in str(result)


def test_revalidation_invalidates_changed_page(action_environment):
    changed_page = dict(action_environment)
    changed_page["links"] = []

    result = follow_observed_link(
        _link_action(),
        action_environment,
        approved=True,
        revalidator=lambda: changed_page,
    )

    assert result["status"] == "BLOCKED"
    assert result["verification"] == "NOT_RUN"


def test_revalidation_and_timeout_are_enforced(action_environment, monkeypatch):
    calls = []

    def fake_observer(url, timeout_seconds=0):
        calls.append((url, timeout_seconds))
        return {"status": "OK", "url": url, "final_url": url}

    monkeypatch.setattr(browser_actions, "observe_browser_page", fake_observer)
    result = navigate_observed_page(_page_action(), action_environment, approved=True)

    assert result["status"] == "COMPLETED"
    assert calls == [("https://example.com", 10)]


def test_action_count_is_bounded(action_environment):
    result = follow_observed_link(_link_action(), action_environment, approved=True, action_count=MAX_BROWSER_ACTIONS)

    assert result["status"] == "BLOCKED"
    assert "count limit" in result["action_result"]


def test_post_action_observation_and_verification_occur(action_environment):
    result = follow_observed_link(
        _link_action(),
        action_environment,
        approved=True,
        observer=lambda url: {"status": "OK", "url": url, "final_url": url, "visible_text": "next"},
    )

    assert result["status"] == "COMPLETED"
    assert result["post_action_observation"]["status"] == "OK"
    assert result["verification"] == "SUCCESS"
    assert result["retry_allowed"] is False


def test_failed_verification_does_not_retry_consequential_action(action_environment):
    calls = []

    def failed_observer(url):
        calls.append(url)
        return {"status": "ERROR", "url": url, "error": "synthetic failure"}

    result = follow_observed_link(_link_action(), action_environment, approved=True, observer=failed_observer)

    assert result["status"] == "UNCERTAIN"
    assert result["verification"] == "UNCERTAIN"
    assert result["retry_allowed"] is False
    assert len(calls) == 1


def test_audit_events_are_created(action_environment, monkeypatch):
    events = []
    monkeypatch.setattr(browser_actions, "record_audit_event", lambda event_type, **payload: events.append(event_type) or True)

    follow_observed_link(
        _link_action(),
        action_environment,
        approved=True,
        observer=lambda url: {"status": "OK", "url": url, "final_url": url},
    )

    assert "browser_action_proposed" in events
    assert "browser_action_risk_decision" in events
    assert "browser_action_approval_granted" in events
    assert "browser_action_revalidation" in events
    assert "browser_action_execution" in events
    assert "browser_post_action_observation" in events
    assert "browser_action_verification" in events


def test_audit_failure_does_not_bypass_security(action_environment, monkeypatch):
    called = []
    monkeypatch.setattr(browser_actions, "record_audit_event", lambda *args, **kwargs: False)

    result = follow_observed_link(
        _link_action(),
        action_environment,
        approved=True,
        observer=lambda url: called.append(url),
    )

    assert result["status"] == "BLOCKED"
    assert called == []


def test_registry_exposes_only_narrow_action_tools_and_phase11_remains_functional():
    assert TOOL_REGISTRY["browser_observer"]["read_only"] is True
    assert TOOL_REGISTRY["browser_navigate_observed"]["requires_approval"] is True
    assert TOOL_REGISTRY["browser_follow_observed_link"]["requires_approval"] is True
    assert get_trusted_tool_plan("Observe https://example.com") == ["browser_observer"]
    assert "browser_action" not in TOOL_REGISTRY
    assert evaluate_risk("observe browser page")["risk_level"] == READ_ONLY
