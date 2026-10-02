from __future__ import annotations

from app.security.automation_scope import grant_scope
from app.security.permission_authority import create_permission
from app.security.user_dna import create_dna_record
from app.ui.server import create_app


def _app(tmp_path, monkeypatch):
    import app.ui.server as server_module

    dna_db = tmp_path / "dna.db"
    perm_db = tmp_path / "permissions.db"
    scope_db = tmp_path / "scopes.db"
    audit_db = tmp_path / "audit.db"
    create_dna_record(
        kind="PREFERENCE", key="editor", value="code",
        provenance_source="user-stated", db_path=dna_db, audit_db_path=audit_db,
    )
    create_dna_record(
        kind="AUTHORIZATION", key="data:SENSITIVE", value="granted",
        provenance_source="user-stated", db_path=dna_db, audit_db_path=audit_db,
    )
    create_permission(
        capability="ACT", action_class="EXECUTE", target_scope="workspace-only",
        task_id="task-ui", db_path=perm_db, audit_db_path=audit_db,
    )
    grant_scope(area="workspace", decision="ALLOW", task_id="task-ui", db_path=scope_db, audit_db_path=audit_db)
    monkeypatch.setattr(server_module, "search_memory", lambda query, limit=5: "HISTORICAL MEMORY\nold context")
    app = create_app(
        state_provider=lambda: {"status": "IDLE"},
        dna_db_path=dna_db,
        permission_db_path=perm_db,
        scope_db_path=scope_db,
    )
    app.config.update(TESTING=True)
    return app


def test_readonly_surfaces_serve_bounded_redacted_views(tmp_path, monkeypatch):
    client = _app(tmp_path, monkeypatch).test_client()
    for endpoint in ("/api/dna", "/api/permissions", "/api/scopes", "/api/privacy"):
        response = client.get(endpoint)
        assert response.status_code == 200, endpoint
        assert len(response.data) < 120000


def test_dna_view_lists_preferences_and_authorizations(tmp_path, monkeypatch):
    client = _app(tmp_path, monkeypatch).test_client()
    payload = client.get("/api/dna").get_json()
    keys = {item["record_key"] for item in payload["records"]}
    assert {"editor", "data:SENSITIVE"} <= keys
    filtered = client.get("/api/dna?kind=AUTHORIZATION").get_json()
    assert {item["kind"] for item in filtered["records"]} == {"AUTHORIZATION"}
    assert client.get("/api/dna?kind=BOGUS").status_code == 400


def test_permissions_and_scopes_views_list_records(tmp_path, monkeypatch):
    client = _app(tmp_path, monkeypatch).test_client()
    permissions = client.get("/api/permissions").get_json()
    assert any(item["capability"] == "ACT" for item in permissions["permissions"])
    scopes = client.get("/api/scopes").get_json()
    assert any(item["area"] == "workspace" for item in scopes["scopes"])


def test_privacy_view_describes_policy_without_mutation(tmp_path, monkeypatch):
    client = _app(tmp_path, monkeypatch).test_client()
    payload = client.get("/api/privacy").get_json()
    assert payload["policy"]["decisions"]["SECRET"]["STORE"] == "DENY"
    assert payload["policy"]["retention_days"]["CREDENTIAL"] == 0
    assert isinstance(payload["decisions"], list)


def test_readonly_surfaces_reject_mutation_and_execution(tmp_path, monkeypatch):
    client = _app(tmp_path, monkeypatch).test_client()
    for endpoint in ("/api/dna", "/api/permissions", "/api/scopes", "/api/privacy"):
        assert client.post(endpoint).status_code == 405, endpoint
        assert client.delete(endpoint).status_code == 405, endpoint
    assert client.post("/api/execute", json={"tool": "fixer"}).status_code == 404
    assert client.post("/api/shell", json={"command": "whoami"}).status_code == 404


def test_secrets_never_reach_readonly_views(tmp_path, monkeypatch):
    import app.ui.server as server_module

    dna_db = tmp_path / "dna2.db"
    monkeypatch.setattr(server_module, "search_memory", lambda query, limit=5: "")
    with __import__("pytest").raises(ValueError):
        create_dna_record(
            kind="PREFERENCE", key="api_key", value="api_key=live-secret-123",
            provenance_source="user-stated", db_path=dna_db,
        )
    app = create_app(state_provider=lambda: {"status": "IDLE", "note": "password=hunter2-live"}, dna_db_path=dna_db)
    app.config.update(TESTING=True)
    response = app.test_client().get("/api/status")
    assert response.status_code == 200
    assert b"hunter2-live" not in response.data
