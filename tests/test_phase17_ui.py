from datetime import datetime, timedelta, timezone

from app.ui import server
from app.ui.server import PendingApprovalStore, create_app


def _app(monkeypatch):
    state = {
        "status": "COMPLETED",
        "verification": "SUCCESS",
        "investigation": {"finding": "Observed runtime failure", "historical": "old context", "detail": "api_key=synthetic_ui_secret"},
        "evidence": [{"source": "runtime", "status": "FAILED", "summary": "runtime failed"}],
        "correlations": [],
        "conflicts": [],
        "tools": [{"tool": "runtime_inspector", "status": "COMPLETED"}],
        "security": {"status": "SCANNER_UNAVAILABLE", "message": "No scanner result"},
        "browser": {"status": "OK", "url": "https://example.com"},
        "desktop": {"status": "OK", "active_window": {"title": "NEXUS"}},
    }
    store = PendingApprovalStore()
    monkeypatch.setattr(server, "get_recent_audit_events", lambda limit=50: [{"event_type": "test", "result": "safe"}])
    monkeypatch.setattr(server, "search_memory", lambda query, limit=5: "HISTORICAL MEMORY\nold context")
    monkeypatch.setattr(server, "inspect_workspace", lambda path: "Workspace: workspace\nFiles: demo.py")
    monkeypatch.setattr(server, "inspect_git_repository", lambda path: {"status": "CLEAN", "branch": "main"})
    app = create_app(state_provider=lambda: state, approval_store=store)
    app.config.update(TESTING=True)
    return app, store


def test_server_starts_local_and_serves_dashboard(monkeypatch):
    app, _ = _app(monkeypatch)
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200
    assert b"NEXUS" in response.data
    assert server.UI_HOST == "127.0.0.1"


def test_api_views_are_explicit_and_bounded(monkeypatch):
    app, _ = _app(monkeypatch)
    client = app.test_client()

    endpoints = [
        "/api/status", "/api/investigation", "/api/evidence", "/api/tools",
        "/api/security", "/api/audit", "/api/memory", "/api/workspace",
        "/api/git", "/api/browser", "/api/desktop", "/api/approvals",
    ]
    for endpoint in endpoints:
        response = client.get(endpoint)
        assert response.status_code == 200, endpoint
        assert len(response.data) < 120000


def test_secrets_never_reach_ui_response(monkeypatch):
    app, _ = _app(monkeypatch)
    client = app.test_client()

    response = client.get("/api/investigation")

    assert response.status_code == 200
    assert b"synthetic_ui_secret" not in response.data
    assert b"[REDACTED]" in response.data


def test_pending_approval_is_visible_and_decision_is_bound(monkeypatch):
    app, store = _app(monkeypatch)
    approval_id = store.register(
        action_type="FOCUS_AUTHORIZED_WINDOW",
        target="NEXUS",
        risk_level="MEDIUM_RISK",
        reason="Human approval required",
    )
    client = app.test_client()

    pending = client.get("/api/approvals")
    approved = client.post(f"/api/approvals/{approval_id}/approve", json={})
    after = client.get("/api/approvals")

    assert pending.status_code == 200
    assert approval_id.encode() in pending.data
    assert approved.status_code == 200
    assert approved.get_json()["approval"]["status"] == "APPROVED"
    assert approval_id.encode() not in after.data


def test_client_cannot_override_action_target_or_risk(monkeypatch):
    app, store = _app(monkeypatch)
    approval_id = store.register(action_type="FOCUS_AUTHORIZED_WINDOW", target="NEXUS", risk_level="MEDIUM_RISK", reason="review")
    client = app.test_client()

    response = client.post(
        f"/api/approvals/{approval_id}/approve",
        json={"action_type": "DELETE_FILE", "target": "outside", "risk_level": "LOW_RISK"},
    )

    assert response.status_code == 400
    assert store.list_pending()[0]["target"] == "NEXUS"


def test_reject_existing_and_missing_or_stale_approvals(monkeypatch):
    app, store = _app(monkeypatch)
    rejected_id = store.register(action_type="FOCUS_AUTHORIZED_WINDOW", target="NEXUS", risk_level="MEDIUM_RISK", reason="review")
    stale_id = store.register(
        action_type="FOCUS_AUTHORIZED_WINDOW",
        target="NEXUS",
        risk_level="MEDIUM_RISK",
        reason="expired",
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    client = app.test_client()

    assert client.post(f"/api/approvals/{rejected_id}/reject", json={}).status_code == 200
    assert client.post(f"/api/approvals/{stale_id}/approve", json={}).status_code == 404
    assert client.post("/api/approvals/missing/approve", json={}).status_code == 404


def test_malformed_and_oversized_approval_requests_are_rejected(monkeypatch):
    app, store = _app(monkeypatch)
    approval_id = store.register(action_type="FOCUS_AUTHORIZED_WINDOW", target="NEXUS", risk_level="MEDIUM_RISK", reason="review")
    client = app.test_client()

    malformed = client.post(f"/api/approvals/{approval_id}/approve", data="not json", content_type="application/json")
    oversized = client.post(f"/api/approvals/{approval_id}/approve", data="x" * 5000, content_type="application/json")

    assert malformed.status_code == 400
    assert oversized.status_code == 413


def test_generic_execution_and_file_routes_do_not_exist(monkeypatch):
    app, _ = _app(monkeypatch)
    client = app.test_client()

    for endpoint in ("/api/execute", "/api/shell", "/api/python", "/api/tool", "/api/files", "/api/download"):
        assert client.post(endpoint).status_code == 404
        assert client.get(endpoint).status_code == 404


def test_invalid_approval_identifier_is_rejected(monkeypatch):
    app, _ = _app(monkeypatch)
    client = app.test_client()

    assert client.post("/api/approvals/../../shell/approve", json={}).status_code in {400, 404}


def test_scanner_unavailable_and_verification_states_are_displayed(monkeypatch):
    app, _ = _app(monkeypatch)
    client = app.test_client()

    security = client.get("/api/security").get_json()
    status = client.get("/api/status").get_json()

    assert security["status"] == "SCANNER_UNAVAILABLE"
    assert status["verification"] == "SUCCESS"


def test_backend_redaction_is_not_frontend_only(monkeypatch):
    app, _ = _app(monkeypatch)
    client = app.test_client()

    response = client.get("/api/status")

    assert b"synthetic_ui_secret" not in response.data


def test_no_external_telemetry_or_debug_mode(monkeypatch):
    app, _ = _app(monkeypatch)

    assert app.debug is False
    assert server.UI_HOST == "127.0.0.1"
