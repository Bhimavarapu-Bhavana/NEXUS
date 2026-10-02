import pytest

from app.security.risk_engine import READ_ONLY, evaluate_risk
from app.tools import browser_observer
from app.tools.browser_observer import (
    MAX_HEADINGS,
    MAX_LINKS,
    MAX_TEXT_CHARS,
    observe_browser_page,
    validate_browser_url,
)
from app.tools.tool_registry import TOOL_REGISTRY, get_trusted_tool_plan, get_tool_risk


@pytest.fixture
def public_browser_target(monkeypatch):
    monkeypatch.setattr(browser_observer, "_resolved_addresses", lambda hostname: ["93.184.216.34"])
    monkeypatch.setattr(browser_observer, "record_audit_event", lambda *args, **kwargs: True)
    return "https://example.com/page"


def test_valid_http_url_is_accepted(monkeypatch):
    monkeypatch.setattr(browser_observer, "_resolved_addresses", lambda hostname: ["93.184.216.34"])

    assert validate_browser_url("http://example.com/page") == "http://example.com/page"


def test_valid_https_url_is_accepted(monkeypatch):
    monkeypatch.setattr(browser_observer, "_resolved_addresses", lambda hostname: ["93.184.216.34"])

    assert validate_browser_url("https://example.com/page#section") == "https://example.com/page"


@pytest.mark.parametrize("url", [
    "not a url",
    "http://",
    "https://user:password@example.com",
    "file:///C:/secret.txt",
    "javascript:alert(1)",
    "data:text/html,hello",
    "vbscript:msgbox(1)",
    "ftp://example.com/file",
])
def test_malformed_or_unsupported_urls_are_rejected(url):
    with pytest.raises(ValueError):
        validate_browser_url(url)


def test_localhost_and_private_network_targets_are_rejected():
    for url in ("http://localhost:8000", "http://127.0.0.1", "http://10.0.0.1", "http://192.168.1.1"):
        with pytest.raises(ValueError):
            validate_browser_url(url)


def test_page_text_heading_and_link_extraction_is_bounded(public_browser_target):
    html = (
        "<html><head><title>Observed page</title></head><body>"
        + "".join(f"<h1>Heading {index}</h1>" for index in range(MAX_HEADINGS + 10))
        + "".join(f'<a href="https://example.com/{index}">Link {index}</a>' for index in range(MAX_LINKS + 20))
        + (" visible text" * 5000)
        + "</body></html>"
    )

    result = observe_browser_page(
        public_browser_target,
        fetcher=lambda url, timeout: (html, url, True),
    )

    assert result["status"] == "OK"
    assert result["title"] == "Observed page"
    assert len(result["visible_text"]) <= MAX_TEXT_CHARS
    assert len(result["headings"]) <= MAX_HEADINGS
    assert len(result["links"]) <= MAX_LINKS
    assert result["truncated"] is True


def test_sensitive_browser_evidence_is_redacted(public_browser_target):
    html = "<html><body>Authorization: Bearer synthetic_browser_secret</body></html>"

    result = observe_browser_page(
        public_browser_target,
        fetcher=lambda url, timeout: (html, url, False),
    )

    assert "synthetic_browser_secret" not in str(result)
    assert "[REDACTED]" in str(result)


def test_timeout_is_bounded(public_browser_target):
    observed_timeouts = []

    def timeout_fetcher(url, timeout):
        observed_timeouts.append(timeout)
        raise TimeoutError("synthetic timeout")

    result = observe_browser_page(public_browser_target, timeout_seconds=999, fetcher=timeout_fetcher)

    assert observed_timeouts == [10]
    assert result["status"] == "TIMEOUT"


def test_browser_observer_is_read_only_and_planner_cannot_select_actions():
    assert TOOL_REGISTRY["browser_observer"]["read_only"] is True
    assert TOOL_REGISTRY["browser_observer"]["requires_approval"] is False
    assert get_tool_risk("browser_observer")["risk_level"] == READ_ONLY
    assert get_trusted_tool_plan("Observe https://example.com") == ["browser_observer"]
    assert "fixer" not in get_trusted_tool_plan("Observe https://example.com")
    assert not any(name in dir(browser_observer) for name in ("click", "submit", "login", "upload", "download"))


def test_blocked_browser_observation_is_audited(monkeypatch):
    events = []
    monkeypatch.setattr(browser_observer, "record_audit_event", lambda event_type, **payload: events.append(event_type) or True)

    with pytest.raises(ValueError):
        observe_browser_page("javascript:alert(1)")

    assert "browser_observation_requested" in events
    assert "browser_observation_blocked" in events


def test_successful_browser_observation_is_audited(public_browser_target, monkeypatch):
    events = []
    monkeypatch.setattr(browser_observer, "record_audit_event", lambda event_type, **payload: events.append(event_type) or True)

    result = observe_browser_page(
        public_browser_target,
        fetcher=lambda url, timeout: ("<h1>Safe page</h1>", url, False),
    )

    assert result["status"] == "OK"
    assert "browser_observation_requested" in events
    assert "browser_observation_started" in events
    assert "browser_observation_completed" in events


def test_audit_failure_does_not_allow_observation_to_proceed(monkeypatch):
    called = []
    monkeypatch.setattr(browser_observer, "record_audit_event", lambda *args, **kwargs: False)

    def fetcher(*args):
        called.append(True)
        return "<p>unexpected</p>", args[0], False

    result = observe_browser_page("https://example.com", fetcher=fetcher)

    assert result["status"] == "ERROR"
    assert called == []


def test_browser_risk_and_phase9_path_enforcement_remain_intact(tmp_path):
    decision = evaluate_risk("observe browser page", workspace_root=tmp_path)

    assert decision["risk_level"] == READ_ONLY
    assert decision["allowed"] is True
    blocked = evaluate_risk("browser submit form")
    assert blocked["approval_required"] is True
    assert blocked["risk_level"] != READ_ONLY
