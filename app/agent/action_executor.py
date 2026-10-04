from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from app.agent.approval_authority import claim_approval, consume_approval, invalidate_approval, validate_approval
from app.agent.execution_journal import load_checkpoint, update_checkpoint
from app.security.audit_logger import record_audit_event
from app.security.automation_scope import check_scope, scope_area_for_tool
from app.security.permission_authority import check_permission_before_execution
from app.security.privacy_policy import evaluate_privacy
from app.security.risk_engine import BLOCKED, evaluate_risk
from app.security.sensitive_data import redact_sensitive_data, redact_text
from app.security.user_dna import check_authorization
from app.agent.personal_capabilities import classify_data
from app.tools.browser_actions import follow_observed_link, navigate_observed_page
from app.tools.browser_controller import browser_controller_entrypoint
from app.tools.desktop_actions import focus_authorized_window, minimize_authorized_window, restore_authorized_window
from app.tools.fixer import fix_python_logic
from app.tools.tool_registry import TOOL_REGISTRY, resolve_tool_permission
from app.calendar.actions import calendar_event_action
from app.email.actions import email_send_action
from app.comms.actions import comms_send_action
from app.adapters.action_bridge import execute_adapter_action

ACTION_FUNCTIONS = {
    "browser_follow_observed_link": follow_observed_link,
    "browser_navigate_observed": navigate_observed_page,
    "browser_controller": None,  # bound to execute_browser_controller_action below
    "desktop_focus_authorized_window": focus_authorized_window,
    "desktop_minimize_authorized_window": minimize_authorized_window,
    "desktop_restore_authorized_window": restore_authorized_window,
    "calendar_event_action": calendar_event_action,
    "email_send_action": email_send_action,
    "comms_send_action": comms_send_action,
    "job_application_fill_action": execute_adapter_action,
    "job_application_submit_action": execute_adapter_action,
    "fixer": fix_python_logic,
}


_BROWSER_CONTROLLER_ACTIONS = frozenset({"open_page", "inspect_page", "click_element", "type_into_field", "navigate_to_url"})
_MAX_CONTROLLER_TIMEOUT_SECONDS = 30
_MIN_CONTROLLER_TIMEOUT_SECONDS = 5


def _controller_blocked(reason: str) -> dict[str, Any]:
    return {
        "source": "browser_controller",
        "status": "BLOCKED",
        "approved": False,
        "action_result": redact_text(reason),
        "verification": "NOT_RUN",
    }


def execute_browser_controller_action(
    action_spec: dict[str, Any] | None,
    observed: dict[str, Any] | None,
    approved: bool = True,
    action_count: int = 0,
    revalidator: Any = None,
    capability_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Authoritative Action Executor dispatch for the existing browser_controller.

    Invokes only the existing ``browser_controller_entrypoint`` with a strictly
    validated subset of its actions. No arbitrary browser commands, selectors,
    JavaScript, or shell execution are exposed: every field comes from the
    approval-bound action_spec (or the executor-owned capability_context) and
    anything unexpected fails closed before any browser is launched.
    """
    del revalidator  # Grounding freshness is enforced inside the controller itself.
    spec = action_spec if isinstance(action_spec, dict) else {}
    controller_action = str(spec.get("controller_action") or spec.get("action") or "open_page").strip()
    if controller_action not in _BROWSER_CONTROLLER_ACTIONS:
        return _controller_blocked(f"Unsupported browser controller action: {controller_action or '<empty>'}.")
    context = capability_context if isinstance(capability_context, dict) else None
    context_page_id = str((context or {}).get("page_id") or "").strip()
    observed_url = ""
    if isinstance(observed, dict):
        observed_url = str(observed.get("final_url") or observed.get("url") or "").strip()
    try:
        safe_count = int(action_count)
    except (TypeError, ValueError):
        return _controller_blocked("Browser controller action count is invalid.")
    if controller_action == "open_page":
        url = str(spec.get("url") or spec.get("target_url") or spec.get("observed_target") or observed_url).strip()
        if not url:
            return _controller_blocked("Browser controller open_page requires an explicit URL; no target was supplied.")
        try:
            timeout = int(spec.get("timeout_seconds", 15))
        except (TypeError, ValueError):
            return _controller_blocked("Browser controller timeout is invalid.")
        timeout = min(max(timeout, _MIN_CONTROLLER_TIMEOUT_SECONDS), _MAX_CONTROLLER_TIMEOUT_SECONDS)
        result = browser_controller_entrypoint(
            "open_page",
            url=url,
            timeout_seconds=timeout,
            approved=bool(approved),
            capability_context=context,
        )
    elif controller_action == "inspect_page":
        page_id = str(spec.get("page_id") or context_page_id).strip()
        if not page_id:
            return _controller_blocked("Browser controller inspect_page requires a grounded page_id.")
        result = browser_controller_entrypoint(
            "inspect_page",
            page_id=page_id,
            capability_context=context,
        )
    elif controller_action in {"click_element", "type_into_field"}:
        page_id = str(spec.get("page_id") or context_page_id).strip()
        grounded_id = str(spec.get("grounded_id") or "").strip()
        if not page_id or not grounded_id:
            return _controller_blocked(f"Browser controller {controller_action} requires a grounded page_id and grounded_id.")
        if controller_action == "type_into_field":
            value = spec.get("value", "")
            if not isinstance(value, str) or not value:
                return _controller_blocked("Browser controller type_into_field requires a non-empty value.")
            result = browser_controller_entrypoint(
                "type_into_field",
                page_id=page_id,
                grounded_id=grounded_id,
                value=value,
                approved=bool(approved),
                action_count=safe_count,
                capability_context=context,
            )
        else:
            result = browser_controller_entrypoint(
                "click_element",
                page_id=page_id,
                grounded_id=grounded_id,
                approved=bool(approved),
                action_count=safe_count,
                capability_context=context,
            )
    else:  # navigate_to_url
        page_id = str(spec.get("page_id") or context_page_id).strip()
        target_url = str(spec.get("target_url") or spec.get("url") or "").strip()
        if not page_id or not target_url:
            return _controller_blocked("Browser controller navigate_to_url requires a grounded page_id and target_url.")
        result = browser_controller_entrypoint(
            "navigate_to_url",
            page_id=page_id,
            target_url=target_url,
            approved=bool(approved),
            action_count=safe_count,
            capability_context=context,
        )
    if not isinstance(result, dict):
        return _controller_blocked("Browser controller returned an unusable result.")
    safe_result = dict(result)
    # An opened/inspected page that yields a bounded grounded snapshot is verified
    # evidence: normalize the controller's OK into the executor's COMPLETED/SUCCESS
    # vocabulary. BLOCKED/ERROR/UNCERTAIN results pass through untouched so the
    # executor's verification gate still fails closed on them.
    if safe_result.get("status") == "OK" and safe_result.get("source") == "browser_controller":
        safe_result["status"] = "COMPLETED"
        safe_result["verification"] = "SUCCESS"
    return safe_result


ACTION_FUNCTIONS["browser_controller"] = execute_browser_controller_action


def proposal_hash(*, action_type: str, tool_name: str, target: str, old_code: str = "", new_code: str = "", action_spec: dict[str, Any] | None = None) -> str:
    payload = {"action_type": action_type, "tool_name": tool_name, "target": target, "old_code": old_code, "new_code": new_code, "action_spec": action_spec or {}}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=True, default=str).encode("utf-8")).hexdigest()


def _audit(event_type: str, *, task_id: str, tool: str, target: str, result: str, reason: str = "", **metadata: Any) -> None:
    record_audit_event(event_type, actor="action_executor", tool=tool, target=target, result=result, reason=reason, metadata={"task_id": task_id, **metadata}, mirror_central=True)


def _risk(tool_name: str, target: str, workspace_root: str) -> dict[str, Any]:
    return evaluate_risk(f"execute {tool_name}", tool_name=tool_name, target_path=target if tool_name == "fixer" else None, workspace_root=workspace_root)


def execute_authorized_action(state: dict[str, Any], *, workspace_root: str = "workspace", db_path: str | Path | None = None) -> dict[str, Any]:
    task_id = str(state.get("task_id") or "")
    checkpoint_id = str(state.get("journal_checkpoint_id") or "")
    approval_id = str(state.get("approval_id") or "")
    tool_name = str(state.get("action_tool") or "fixer")
    target = str(state.get("action_target") or state.get("target_file") or "")
    current_hash = str(state.get("proposal_hash") or "")
    if not task_id or not checkpoint_id or not approval_id or not current_hash or not target:
        return {"status": "BLOCKED", "error": "Execution requires durable task, checkpoint, approval, proposal, and target bindings."}
    if tool_name not in TOOL_REGISTRY or not TOOL_REGISTRY[tool_name].get("allowed"):
        return {"status": "BLOCKED", "error": "Action tool is not authorized by the Tool Registry."}
    if tool_name not in ACTION_FUNCTIONS or ACTION_FUNCTIONS[tool_name] is None:
        # Any future registry-only tool without an authoritative dispatch mapping
        # fails closed before any approval claim so no approval can strand on a
        # nonexistent mapping.
        _audit("action_blocked", task_id=task_id, tool=tool_name, target=target, result="BLOCKED", reason="Action tool has no authoritative executor dispatch mapping.", approval_id=approval_id)
        return {"status": "BLOCKED", "error": "Action tool has no authoritative executor dispatch mapping."}
    journal_db_path = state.get("journal_db_path") or None
    checkpoint = load_checkpoint(task_id, checkpoint_id=checkpoint_id, db_path=journal_db_path)
    if not checkpoint or checkpoint.get("is_valid") == 0:
        return {"status": "BLOCKED", "error": "Execution checkpoint is missing or invalid."}
    if checkpoint.get("proposal_hash") != current_hash or checkpoint.get("action_target") != target:
        return {"status": "BLOCKED", "error": "Execution proposal or target drifted from the checkpoint."}
    risk = _risk(tool_name, target, workspace_root)
    if not risk.get("allowed") or risk.get("risk_level") == BLOCKED:
        _audit("action_blocked", task_id=task_id, tool=tool_name, target=target, result="BLOCKED", reason=risk.get("reason", "Risk blocked action."))
        return {"status": "BLOCKED", "risk_decision": risk, "error": risk.get("reason", "Risk blocked action.")}
    if tool_name == "fixer" and (not str(state.get("old_code") or "") or not str(state.get("new_code") or "")):
        # A code patch without exact content would execute vacuously (empty
        # strings match everywhere). Fail closed before any approval claim.
        _audit("action_blocked", task_id=task_id, tool=tool_name, target=target, result="BLOCKED", reason="Fixer requires exact old and new code; vacuous execution refused.", approval_id=approval_id)
        return {"status": "BLOCKED", "risk_decision": risk, "error": "Fixer requires exact old and new code; vacuous execution refused."}
    # Final fresh Privacy Policy check immediately before dispatch.
    # SECRET and CREDENTIAL data are denied unconditionally. SENSITIVE data
    # requires an explicit AUTHORIZATION record when a DNA store is bound;
    # otherwise the requirement is advisory and legacy behavior is preserved.
    # Runs before the approval claim so denied executions never consume it.
    try:
        privacy_category = classify_data(target=target)
    except ValueError as exc:
        _audit("action_blocked", task_id=task_id, tool=tool_name, target=target, result="DENIED", reason=str(exc), approval_id=approval_id)
        return {"status": "BLOCKED", "risk_decision": risk, "error": redact_text(exc)}
    dna_db_path = str(state.get("dna_db_path") or "").strip()
    privacy_authorized = False
    if dna_db_path and privacy_category == "SENSITIVE":
        try:
            privacy_authorized = check_authorization("data:SENSITIVE", db_path=dna_db_path)
        except (OSError, ValueError):
            privacy_authorized = False
    privacy_decision = evaluate_privacy(privacy_category, operation="OBSERVE", authorization_present=privacy_authorized)
    if str(privacy_decision.get("decision") or "") == "DENY" or (
        str(privacy_decision.get("decision") or "") == "REQUIRES_AUTHORIZATION" and dna_db_path
    ):
        _audit("action_blocked", task_id=task_id, tool=tool_name, target=target, result=str(privacy_decision.get("decision") or "DENIED"), reason=str(privacy_decision.get("reason") or "Privacy denied."), approval_id=approval_id)
        return {"status": "BLOCKED", "risk_decision": risk, "privacy_decision": privacy_decision, "error": redact_text(privacy_decision.get("reason") or "Privacy denied.")}
    # Final fresh Permission Authority check immediately before dispatch.
    # Never trusts an earlier cached permission decision: a permission that
    # was revoked or expired after planning or approval stops execution here.
    # Active only when a permission store is explicitly bound in the state;
    # unwired callers keep the legacy risk + approval behavior unchanged.
    # Runs before the approval claim so denied executions never consume it.
    permission_db_path = str(state.get("permission_db_path") or "").strip()
    permission_decision: dict[str, Any] | None = None
    permission_id = ""
    if permission_db_path:
        try:
            binding = resolve_tool_permission(tool_name)
        except ValueError as exc:
            _audit("action_blocked", task_id=task_id, tool=tool_name, target=target, result="DENIED", reason=str(exc), approval_id=approval_id)
            return {"status": "BLOCKED", "risk_decision": risk, "error": redact_text(exc)}
        permission_decision = check_permission_before_execution(
            capability=binding["capability"],
            action_class=binding["action_class"],
            target=target,
            task_id=task_id,
            risk_level=str(risk.get("risk_level") or ""),
            db_path=permission_db_path,
        )
        permission_id = str((permission_decision.get("metadata") or {}).get("permission_id") or "")
        if permission_decision.get("outcome") not in {"ALLOWED", "APPROVAL_REQUIRED"}:
            _audit("action_blocked", task_id=task_id, tool=tool_name, target=target, result=str(permission_decision.get("outcome") or "DENIED"), reason=str(permission_decision.get("reason") or "Permission denied."), approval_id=approval_id, permission_id=permission_id)
            return {"status": "BLOCKED", "risk_decision": risk, "permission_decision": permission_decision, "privacy_decision": privacy_decision, "error": redact_text(permission_decision.get("reason") or "Permission denied.")}
    # Final fresh Automation Scope check immediately before dispatch.
    # Never trusts an earlier cached scope decision: a scope that was revoked
    # or expired after planning or approval stops execution here. Active only
    # when a scope store is explicitly bound; unwired callers are unchanged.
    # Runs before the approval claim so denied executions never consume it.
    scope_db_path = str(state.get("scope_db_path") or "").strip()
    scope_decision: dict[str, Any] | None = None
    if scope_db_path:
        try:
            scope_area = scope_area_for_tool(tool_name)
        except ValueError as exc:
            _audit("action_blocked", task_id=task_id, tool=tool_name, target=target, result="DENIED", reason=str(exc), approval_id=approval_id)
            return {"status": "BLOCKED", "risk_decision": risk, "privacy_decision": privacy_decision, "error": redact_text(exc)}
        scope_decision = check_scope(
            area=scope_area,
            target=target,
            task_id=task_id,
            db_path=scope_db_path,
        )
        if not scope_decision.get("allowed"):
            _audit("action_blocked", task_id=task_id, tool=tool_name, target=target, result=str(scope_decision.get("outcome") or "DENIED"), reason=str(scope_decision.get("reason") or "Automation scope denied."), approval_id=approval_id, scope_id=str(scope_decision.get("scope_id") or ""))
            return {"status": "BLOCKED", "risk_decision": risk, "privacy_decision": privacy_decision, "scope_decision": scope_decision, "error": redact_text(scope_decision.get("reason") or "Automation scope denied.")}
    try:
        approval = validate_approval(approval_id, task_id=task_id, checkpoint_id=checkpoint_id, proposal_hash=current_hash, action_type=str(state.get("action_type") or tool_name), tool_name=tool_name, target=target, risk_level=risk.get("risk_level", ""), capability_context=state.get("capability_context") or None, target_hash=str(checkpoint.get("target_hash") or ""), evidence_hash_value=str((state.get("capability_context") or {}).get("evidence_hash", "")), db_path=db_path)
    except ValueError as exc:
        _audit("action_blocked", task_id=task_id, tool=tool_name, target=target, result="BLOCKED", reason=str(exc), approval_id=approval_id)
        return {"status": "BLOCKED", "risk_decision": risk, "error": redact_text(exc)}
    claimed = claim_approval(
        approval_id,
        task_id=task_id,
        checkpoint_id=checkpoint_id,
        proposal_hash=current_hash,
        action_type=str(state.get("action_type") or tool_name),
        tool_name=tool_name,
        target=target,
        risk_level=str(risk.get("risk_level", "")),
        capability_context=state.get("capability_context") or None,
        target_hash=str(checkpoint.get("target_hash") or ""),
        evidence_hash_value=str((state.get("capability_context") or {}).get("evidence_hash", "")),
        db_path=db_path,
    )
    if not claimed or claimed.get("status") != "EXECUTING":
        _audit("action_blocked", task_id=task_id, tool=tool_name, target=target, result="BLOCKED", reason="Approval was already claimed, consumed, expired, or invalid.", approval_id=approval_id)
        return {"status": "BLOCKED", "risk_decision": risk, "error": "Approval execution claim was not available."}
    context = {"task_id": task_id, "checkpoint_id": checkpoint_id, "approval_id": approval_id, "proposal_hash": current_hash, "risk_level": risk.get("risk_level"), "target": target}
    execution_id = f"execution-{uuid.uuid4().hex[:16]}"
    _audit("action_execution_started", task_id=task_id, tool=tool_name, target=target, result="STARTED", approval_id=approval_id, checkpoint_id=checkpoint_id)
    try:
        if tool_name == "fixer":
            result = fix_python_logic(workspace_root, str(state.get("target_file") or target), str(state.get("old_code") or ""), str(state.get("new_code") or ""), execution_context=context)
            changed_path = Path(workspace_root) / str(state.get("target_file") or target)
            verified = False
            try:
                verified = changed_path.is_file() and str(state.get("new_code") or "") in changed_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                verified = False
            result_payload: Any = {"action_result": result, "verification": "SUCCESS" if verified else "FAILED"}
        elif tool_name == "browser_controller":
            function = ACTION_FUNCTIONS[tool_name]
            observed = state.get("observed_page") or next((item.get("result") for item in state.get("observation_results", []) if item.get("tool") == "browser_observer"), {})
            result_payload = function(
                state.get("action_spec") or {},
                observed,
                approved=state.get("approval_id") is not None,
                action_count=0,
                revalidator=state.get("browser_revalidator"),
                capability_context=state.get("capability_context"),
            )
        elif tool_name.startswith("browser_"):
            function = ACTION_FUNCTIONS[tool_name]
            observed = state.get("observed_page") or next((item.get("result") for item in state.get("observation_results", []) if item.get("tool") == "browser_observer"), {})
            result_payload = function(state.get("action_spec") or {}, observed, approved=state.get("approval_id") is not None, action_count=0, revalidator=state.get("browser_revalidator"))
        elif tool_name.startswith("desktop_"):
            function = ACTION_FUNCTIONS[tool_name]
            observed = state.get("observed_desktop") or next((item.get("result") for item in state.get("observation_results", []) if item.get("tool") == "desktop_observer"), {})
            result_payload = function(state.get("action_spec") or {}, observed, approved=True, action_count=0)
        elif tool_name == "calendar_event_action":
            calendar_state = state.get("calendar_action_state") or None
            result_payload = calendar_event_action(state.get("action_spec") or {}, approved=True, provider=str(state.get("calendar_provider") or "fixture"), task_id=task_id, actor="action_executor", calendar_state=calendar_state)
        elif tool_name == "email_send_action":
            email_state = state.get("email_action_state") or None
            result_payload = email_send_action(state.get("action_spec") or {}, approved=True, provider=str(state.get("email_provider") or "fixture"), task_id=task_id, actor="action_executor", email_state=email_state)
        elif tool_name == "comms_send_action":
            comms_state = state.get("comms_action_state") or None
            result_payload = comms_send_action(state.get("action_spec") or {}, approved=True, provider=str(state.get("comms_provider") or "comms"), task_id=task_id, actor="action_executor", comms_state=comms_state)
        elif tool_name in {"job_application_fill_action", "job_application_submit_action"}:
            result_payload = execute_adapter_action(tool_name, state.get("capability_context"), state.get("action_spec") or {}, approved=True)
        else:
            invalidate_approval(approval_id, "Approved action has no authoritative executor dispatch mapping.", db_path=db_path)
            _audit("action_blocked", task_id=task_id, tool=tool_name, target=target, result="BLOCKED", reason="Unknown consequential action.", approval_id=approval_id)
            return {"status": "BLOCKED", "error": "Unknown consequential action."}
    except Exception as exc:
        invalidate_approval(approval_id, f"Authorized execution failed: {redact_text(exc)[:200]}", db_path=db_path)
        _audit("action_execution_failed", task_id=task_id, tool=tool_name, target=target, result="FAILED", reason=str(exc), approval_id=approval_id)
        return {"status": "EXECUTION_FAILED", "execution_id": execution_id, "error": redact_text(exc), "risk_decision": risk}
    safe_result = redact_sensitive_data(result_payload)
    verification = "SUCCESS" if (isinstance(safe_result, dict) and (safe_result.get("verification") == "SUCCESS" or safe_result.get("status") in {"COMPLETED", "SUCCESS"})) or (isinstance(safe_result, str) and "STATUS: SUCCESS" in safe_result.upper()) else "FAILED"
    if verification == "SUCCESS":
        consumed = consume_approval(approval_id, db_path=db_path)
        if not consumed or consumed.get("status") != "CONSUMED":
            invalidate_approval(approval_id, "Approval could not be consumed after verified execution.", db_path=db_path)
            return {"status": "VERIFICATION_FAILED", "execution_id": execution_id, "result": safe_result, "verification": "FAILED", "risk_decision": risk, "approval_id": approval_id, "checkpoint_id": checkpoint_id}
        update_checkpoint(checkpoint_id, approval_status="CONSUMED", verification_snapshot=verification, db_path=journal_db_path)
    else:
        invalidate_approval(approval_id, "Post-action verification failed; the approval cannot be reused.", db_path=db_path)
    _audit("action_execution_completed", task_id=task_id, tool=tool_name, target=target, result="COMPLETED" if verification == "SUCCESS" else "FAILED", approval_id=approval_id, checkpoint_id=checkpoint_id, verification=verification)
    completed = {"status": "COMPLETED" if verification == "SUCCESS" else "VERIFICATION_FAILED", "execution_id": execution_id, "result": safe_result, "verification": verification, "risk_decision": risk, "approval_id": approval_id, "checkpoint_id": checkpoint_id}
    completed["privacy_decision"] = privacy_decision
    if permission_decision is not None:
        completed["permission_decision"] = permission_decision
        completed["permission_id"] = permission_id
    if scope_decision is not None:
        completed["scope_decision"] = scope_decision
        completed["scope_id"] = str(scope_decision.get("scope_id") or "")
    return completed


__all__ = ["execute_authorized_action", "proposal_hash"]
