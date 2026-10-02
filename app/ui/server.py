from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any, Callable

from flask import Flask, Response, jsonify, request, send_from_directory

from app.memory.sqlite_memory import search_memory
from app.memory.task_ledger import get_task, list_recent_tasks
from app.agent.approval_authority import create_approval, decide_approval, list_pending_approvals
from app.security.audit_logger import get_recent_audit_events
from app.security.automation_scope import list_scopes
from app.security.permission_authority import list_permissions
from app.security.privacy_policy import describe_privacy_policy
from app.security.sensitive_data import redact_sensitive_data, redact_text
from app.security.user_dna import DNA_KINDS, list_dna_records
from app.tools.git_inspector import inspect_git_repository
from app.tools.workspace_inspector import inspect_workspace

UI_HOST = "127.0.0.1"
UI_PORT = 8765
MAX_REQUEST_BYTES = 4096
MAX_RESPONSE_BYTES = 120000
MAX_APPROVALS = 50
APPROVAL_TTL_SECONDS = 300
MAX_TASK_CHARS = 2000
STATIC_DIR = Path(__file__).parent / "static"

# Natural-language task text is untrusted input: these hints indicate the
# request is trying to use the submission channel as an execution channel.
# Mirrors the control-plane guard without coupling the UI to that module.
ARBITRARY_TASK_HINTS = (
    "shell", "run-python", "run_command", "run-command", "execute-tool",
    "execute_tool", "execute-tool-anything", "os.system", "subprocess",
    "exec(", "eval(", "run python", "run code", "execute command",
    "execute_custom_command", "powershell", "cmd.exe",
)


def _looks_like_arbitrary_task(text: str) -> bool:
    # Only explicit execution-channel markers reject a submission. A bare
    # "run ..."/"execute ..." prefix is ordinary task language ("Run a
    # security scan...") and must not block legitimate requests; anything it
    # could select still passes the full backend security chain.
    lowered = (text or "").lower().strip().lstrip("!:-")
    if not lowered:
        return False
    return any(hint in lowered for hint in ARBITRARY_TASK_HINTS)


def _valid_task_id(value: str) -> bool:
    text = str(value or "")
    return bool(text) and len(text) <= 200 and all(char.isalnum() or char in "-_" for char in text)


def _task_summary(task: dict[str, Any]) -> dict[str, Any]:
    """Curated bounded projection of a durable task for display.

    The raw ledger record can exceed UI payload bounds (full plans, lineage,
    evidence); this exposes exactly the progress/security/verification fields
    the interface needs. All values pass through the standard redaction in
    _json_response.
    """
    plan = task.get("goal_plan") or []
    statuses = task.get("subgoal_statuses") or {}
    subgoals = []
    for item in plan[:50]:
        if not isinstance(item, dict):
            continue
        sid = str(item.get("sub_goal_id") or "")
        if not sid:
            continue
        subgoals.append({
            "sub_goal_id": sid[:120],
            "status": str(statuses.get(sid) or "PLANNED")[:40],
            "objective": str(item.get("objective") or "")[:300],
        })
    return {
        "task_id": str(task.get("task_id") or ""),
        "status": str(task.get("status") or ""),
        "objective": str(task.get("objective") or "")[:1000],
        "current_stage": str(task.get("current_stage") or "")[:120],
        "current_sub_goal": str(task.get("current_sub_goal") or "")[:500],
        "current_subgoal_id": str(task.get("current_subgoal_id") or "")[:120],
        "status_reason": str(task.get("status_reason") or "")[:1000],
        "resume_reason": str(task.get("resume_reason") or "")[:500],
        "final_outcome": str(task.get("final_outcome") or "")[:120],
        "verification_status": str(task.get("verification_status") or "")[:120],
        "task_answer": str(task.get("task_answer") or "")[:4000],
        "subgoals": subgoals,
        "completed_subgoals": [str(item)[:120] for item in (task.get("completed_subgoals") or [])[:50]],
        "completion_evidence": [str(item)[:200] for item in (task.get("completion_evidence") or [])[:20]],
        "recovery_attempts": int(task.get("recovery_attempts") or 0),
        "task_retry_count": int(task.get("task_retry_count") or 0),
        "plan_version": str(task.get("plan_version") or "")[:40],
        "created_at": str(task.get("created_at") or "")[:40],
        "updated_at": str(task.get("updated_at") or "")[:40],
        "event_history": [
            {
                "event_type": str(item.get("event_type") or "")[:120],
                "timestamp": str(item.get("timestamp") or "")[:40],
                "current_stage": str(item.get("current_stage") or "")[:120],
                "status": str(item.get("status") or "")[:40],
            }
            for item in (task.get("event_history") or [])[-20:]
            if isinstance(item, dict)
        ],
    }


class PendingApprovalStore:
    """Small in-process view of backend-created approvals.

    The UI can only decide an existing record. It cannot create or mutate the
    action, target, risk, authorization, or tool fields.
    """

    def __init__(self, *, db_path: str | Path | None = None) -> None:
        self._db_path = db_path
        self._lock = Lock()

    def register(
        self,
        *,
        action_type: str,
        target: str,
        risk_level: str,
        reason: str,
        expires_at: datetime | None = None,
        task_id: str = "ui-task",
        checkpoint_id: str = "ui-checkpoint",
        proposal_hash: str = "ui-proposal",
        tool_name: str | None = None,
    ) -> str:
        item = create_approval(task_id=task_id, checkpoint_id=checkpoint_id, proposal_hash=proposal_hash, action_type=action_type, tool_name=tool_name or action_type, target=target, risk_level=risk_level, reason=reason, expires_at=expires_at.isoformat(timespec="seconds") if expires_at else None, db_path=self._db_path)
        return str(item["approval_id"])

    def list_pending(self) -> list[dict[str, Any]]:
        return [{"id": item["approval_id"], **item} for item in list_pending_approvals(db_path=self._db_path)]

    def decide(self, approval_id: str, decision: str) -> dict[str, Any] | None:
        try:
            item = decide_approval(approval_id, decision, actor="ui", db_path=self._db_path)
        except ValueError:
            return None
        return {"id": item["approval_id"], **item}


class UIState:
    """Bounded presentation state supplied by the local agent integration."""

    def __init__(self) -> None:
        self._state: dict[str, Any] = {
            "status": "IDLE",
            "investigation": {},
            "evidence": [],
            "tools": [],
            "security": {"status": "SCANNER_UNAVAILABLE", "message": "No scan result is currently available."},
            "browser": {},
            "desktop": {},
        }
        self._lock = Lock()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return redact_sensitive_data(self._state.copy())

    def replace(self, state: dict[str, Any]) -> None:
        with self._lock:
            self._state = redact_sensitive_data(dict(state))


def _bounded_payload(payload: Any) -> Any:
    safe = redact_sensitive_data(payload)
    serialized = json.dumps(safe, ensure_ascii=True, default=str)
    if len(serialized) > MAX_RESPONSE_BYTES:
        return {"status": "TRUNCATED", "message": "UI response exceeded the bounded response size."}
    return safe


def _json_response(payload: Any, status: int = 200) -> Response:
    return jsonify(_bounded_payload(payload)), status


def _default_approval_resume(runner: Any, item: dict[str, Any]) -> dict[str, Any]:
    """Resume the decided approval's durable task through recover-and-validate.

    Runs the task back through TaskRunner recovery so checkpoint, approval,
    risk, permission, scope, and privacy bindings are all revalidated before
    anything executes. Never raises: resume failures are reported, and the
    approval decision itself is already durable.
    """
    try:
        task_id = str((item or {}).get("task_id") or "")
        approval_id = str((item or {}).get("approval_id") or "")
        if not task_id:
            return {"resumed": False, "reason": "Approval carries no task binding."}
        task = get_task(task_id, db_path=runner.db_path)
        if task is None:
            return {"resumed": False, "reason": "Task does not exist."}
        objective = str(task.get("objective") or "").strip()
        if not objective:
            return {"resumed": False, "reason": "Task has no objective to resume."}
        resumed = runner.recover_interrupted_task(
            task_id,
            current_state={
                "user_request": objective,
                "resume_reason": f"ui approval decision on {approval_id}",
            },
        )
        if not isinstance(resumed, dict):
            return {"resumed": False, "reason": "Resume produced no result."}
        return {
            "resumed": True,
            "task_id": resumed.get("task_id", task_id),
            "status": resumed.get("status", ""),
            "final_outcome": resumed.get("final_outcome", ""),
        }
    except Exception as exc:
        return {"resumed": False, "reason": f"Resume failed safely: {redact_text(str(exc))[:200]}"}


def create_app(
    *,
    state_provider: Callable[[], dict[str, Any]] | None = None,
    approval_store: PendingApprovalStore | None = None,
    approval_resume_handler: Callable[[dict[str, Any]], Any] | None = None,
    dna_db_path: str | Path | None = None,
    permission_db_path: str | Path | None = None,
    scope_db_path: str | Path | None = None,
    task_runner: Any | None = None,
) -> Flask:
    app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")
    app.config.update(MAX_CONTENT_LENGTH=MAX_REQUEST_BYTES, DEBUG=False, TESTING=False)
    state = UIState()
    approvals = approval_store or PendingApprovalStore()
    runner = task_runner
    if runner is not None and approval_resume_handler is None:
        approval_resume_handler = lambda item: _default_approval_resume(runner, item)

    def current_state() -> dict[str, Any]:
        return redact_sensitive_data(state_provider() if state_provider else state.snapshot())

    @app.get("/")
    def index() -> Response:
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/api/status")
    def api_status() -> Response:
        current = current_state()
        return _json_response({
            "status": current.get("status", "IDLE"),
            "local_only": True,
            "host": UI_HOST,
            "pending_approvals": len(approvals.list_pending()),
            "verification": current.get("verification", ""),
        })

    @app.get("/api/investigation")
    def api_investigation() -> Response:
        current = current_state()
        return _json_response(current.get("investigation", {}))

    @app.get("/api/evidence")
    def api_evidence() -> Response:
        current = current_state()
        return _json_response({
            "evidence": current.get("evidence", current.get("normalized_evidence", [])),
            "correlations": current.get("correlations", current.get("evidence_correlations", [])),
            "conflicts": current.get("conflicts", current.get("evidence_conflicts", [])),
        })

    @app.get("/api/tools")
    def api_tools() -> Response:
        return _json_response(current_state().get("tools", []))

    @app.get("/api/security")
    def api_security() -> Response:
        return _json_response(current_state().get("security", {"status": "SCANNER_UNAVAILABLE"}))

    @app.get("/api/audit")
    def api_audit() -> Response:
        return _json_response({"events": get_recent_audit_events(limit=50)})

    @app.get("/api/memory")
    def api_memory() -> Response:
        query = redact_text(request.args.get("q", ""))[:200]
        if not query:
            return _json_response({"label": "HISTORICAL MEMORY", "items": []})
        return _json_response({"label": "HISTORICAL MEMORY", "items": [search_memory(query, limit=5)]})

    @app.get("/api/workspace")
    def api_workspace() -> Response:
        return _json_response({"workspace": inspect_workspace("workspace")})

    @app.get("/api/git")
    def api_git() -> Response:
        return _json_response(inspect_git_repository("workspace"))

    @app.get("/api/browser")
    def api_browser() -> Response:
        return _json_response(current_state().get("browser", {}))

    @app.get("/api/desktop")
    def api_desktop() -> Response:
        return _json_response(current_state().get("desktop", {}))

    @app.get("/api/approvals")
    def api_approvals() -> Response:
        return _json_response({"approvals": approvals.list_pending()})

    @app.post("/api/tasks")
    def api_submit_task() -> Response:
        """Submit a natural-language task through the authoritative TaskRunner.

        Accepts only {"request": "<text>"}. The text selects read-only plans
        at most; tools, risk, permission, scope, approval, and verification
        decisions all remain backend responsibilities.
        """
        if runner is None:
            return _json_response({"error": "Task submission is unavailable."}, 503)
        try:
            body = request.get_json(silent=True)
        except Exception:
            return _json_response({"error": "Malformed task payload."}, 400)
        if not isinstance(body, dict):
            return _json_response({"error": "A JSON payload with a natural-language 'request' is required."}, 400)
        unknown = sorted(set(body) - {"request"})
        if unknown:
            return _json_response({"error": "Only a natural-language 'request' field is accepted."}, 400)
        if not isinstance(body.get("request"), str):
            return _json_response({"error": "A natural-language string 'request' is required."}, 400)
        text = str(body.get("request") or "").strip()
        if not text:
            return _json_response({"error": "A request is required."}, 400)
        if len(text) > MAX_TASK_CHARS:
            return _json_response({"error": "Request is too long."}, 400)
        if _looks_like_arbitrary_task(text):
            return _json_response({"error": "Arbitrary command execution is not a task; requests route through the existing StateGraph."}, 400)
        try:
            result = runner.start_task(text)
        except Exception as exc:
            return _json_response({"error": f"Task submission failed safely: {redact_text(str(exc))[:200]}"}, 500)
        if not isinstance(result, dict):
            return _json_response({"error": "Task submission failed safely."}, 500)
        return _json_response({"task": result})

    @app.get("/api/tasks")
    def api_tasks() -> Response:
        if runner is None:
            return _json_response({"tasks": []})
        try:
            from app.memory.task_ledger import list_recent_tasks as _list_recent

            tasks = [_task_summary(task) for task in _list_recent(limit=10, db_path=runner.db_path)]
        except (OSError, ValueError):
            return _json_response({"error": "Task history is unavailable."}, 503)
        return _json_response({"tasks": tasks})

    @app.get("/api/tasks/<task_id>")
    def api_task(task_id: str) -> Response:
        """Authoritative per-task view: ledger state, approvals, verification,
        security decisions (task-scoped audit trail), and recovery info."""
        if not _valid_task_id(task_id):
            return _json_response({"error": "Invalid task identifier."}, 400)
        db_path = getattr(runner, "db_path", None) if runner is not None else None
        task = get_task(task_id, db_path=db_path)
        if task is None:
            return _json_response({"error": "Task does not exist."}, 404)
        task_approvals = [
            item for item in approvals.list_pending()
            if str(item.get("task_id") or "") == task_id
        ]
        decisions: list[dict[str, Any]] = []
        try:
            for event in get_recent_audit_events(limit=100):
                metadata = event.get("metadata") or {}
                if isinstance(metadata, dict) and str(metadata.get("task_id") or "") == task_id:
                    decisions.append(event)
                if len(decisions) >= 20:
                    break
        except (OSError, ValueError):
            decisions = []
        return _json_response({
            "task": _task_summary(task),
            "approvals": task_approvals,
            "decisions": decisions,
        })

    @app.get("/api/dna")
    def api_dna() -> Response:
        """Read-only view of User DNA records. No creation, mutation, or execution."""
        kind = (request.args.get("kind", "") or "").strip().upper()
        if kind and kind not in DNA_KINDS:
            return _json_response({"error": "Unknown User DNA kind."}, 400)
        try:
            records = list_dna_records(kind=kind or None, limit=50, db_path=dna_db_path)
        except (OSError, ValueError):
            return _json_response({"error": "User DNA store is unavailable."}, 503)
        return _json_response({"records": records})

    @app.get("/api/permissions")
    def api_permissions() -> Response:
        """Read-only view of permission records. Grants and revocations happen out of band."""
        try:
            records = list_permissions(db_path=permission_db_path)[:50]
        except (OSError, ValueError):
            return _json_response({"error": "Permission store is unavailable."}, 503)
        return _json_response({"permissions": records})

    @app.get("/api/scopes")
    def api_scopes() -> Response:
        """Read-only view of automation scopes. Grants and revocations happen out of band."""
        try:
            records = list_scopes(limit=50, db_path=scope_db_path)
        except (OSError, ValueError):
            return _json_response({"error": "Automation scope store is unavailable."}, 503)
        return _json_response({"scopes": records})

    @app.get("/api/privacy")
    def api_privacy() -> Response:
        """Read-only privacy policy table plus recent privacy/authorization audit decisions."""
        policy = describe_privacy_policy()
        watched = {"privacy_denied", "dna_created", "dna_revoked", "permission_checked", "scope_checked", "privacy_checked"}
        try:
            decisions = [event for event in get_recent_audit_events(limit=100) if event.get("event_type") in watched][:20]
        except (OSError, ValueError):
            decisions = []
        return _json_response({"policy": policy, "decisions": decisions})

    def approval_decision(approval_id: str, decision: str) -> Response:
        if not approval_id or len(approval_id) > 100 or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for char in approval_id):
            return _json_response({"error": "Invalid approval identifier."}, 400)
        if request.content_length and request.content_length > MAX_REQUEST_BYTES:
            return _json_response({"error": "Request is too large."}, 413)
        if request.data:
            try:
                body = request.get_json(silent=False)
            except Exception:
                return _json_response({"error": "Malformed approval payload."}, 400)
            if body not in ({}, None):
                return _json_response({"error": "Approval payload may not contain action data."}, 400)
        item = approvals.decide(approval_id, decision)
        if item is None:
            return _json_response({"error": "Approval does not exist, is stale, or is already decided."}, 404)
        resume: Any = None
        if item and approval_resume_handler is not None:
            try:
                resume = approval_resume_handler(item)
            except Exception as exc:
                resume = {"resumed": False, "reason": f"Resume handler failed safely: {redact_text(str(exc))[:200]}"}
        payload: dict[str, Any] = {"approval": item}
        if isinstance(resume, dict):
            payload["resume"] = resume
        return _json_response(payload)

    @app.post("/api/approvals/<approval_id>/approve")
    def api_approve(approval_id: str) -> Response:
        return approval_decision(approval_id, "APPROVED")

    @app.post("/api/approvals/<approval_id>/reject")
    def api_reject(approval_id: str) -> Response:
        return approval_decision(approval_id, "REJECTED")

    @app.errorhandler(413)
    def request_too_large(_error: Any) -> Response:
        return _json_response({"error": "Request is too large."}, 413)

    return app


def run_server(host: str = UI_HOST, port: int = UI_PORT) -> None:
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("NEXUS UI only binds to localhost.")
    from app.agent.task_runner import TaskRunner
    from app.security.automation_scope import DEFAULT_DB_PATH as SCOPES_DB_PATH
    from app.security.permission_authority import DEFAULT_DB_PATH as PERMISSIONS_DB_PATH
    from app.security.user_dna import DEFAULT_DB_PATH as DNA_DB_PATH

    runner = TaskRunner(
        workspace_root="workspace",
        permission_db_path=PERMISSIONS_DB_PATH,
        scope_db_path=SCOPES_DB_PATH,
        dna_db_path=DNA_DB_PATH,
    )
    app = create_app(
        task_runner=runner,
        dna_db_path=DNA_DB_PATH,
        permission_db_path=PERMISSIONS_DB_PATH,
        scope_db_path=SCOPES_DB_PATH,
    )
    app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    run_server()
