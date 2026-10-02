from app.ui.server import PendingApprovalStore, create_app


def test_ui_approval_uses_durable_authority_and_resume_callback(tmp_path):
    db_path = tmp_path / "approvals.db"
    store = PendingApprovalStore(db_path=db_path)
    approval_id = store.register(action_type="apply approved code fix", tool_name="fixer", task_id="task-ui-31", checkpoint_id="cp-ui-31", proposal_hash="proposal-ui-31", target="sample.py", risk_level="MEDIUM_RISK", reason="Review change")
    resumed = []
    app = create_app(approval_store=PendingApprovalStore(db_path=db_path), approval_resume_handler=resumed.append)
    app.config.update(TESTING=True)
    client = app.test_client()

    pending = client.get("/api/approvals").get_json()["approvals"]
    assert any(item["approval_id"] == approval_id for item in pending)
    response = client.post(f"/api/approvals/{approval_id}/approve", json={})
    assert response.status_code == 200
    assert response.get_json()["approval"]["task_id"] == "task-ui-31"
    assert resumed and resumed[0]["checkpoint_id"] == "cp-ui-31"

    restarted = PendingApprovalStore(db_path=db_path)
    assert restarted.list_pending() == []
