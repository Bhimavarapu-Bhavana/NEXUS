from __future__ import annotations

import uuid
from datetime import datetime, timezone
from threading import Lock
from typing import Any

from app.security.audit_logger import record_audit_event
from app.security.risk_engine import BLOCKED
from app.security.sensitive_data import redact_sensitive_data, redact_text

SEVERITY_LEVELS = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def classify_event_severity(event_type: str | None) -> str:
    label = str(event_type or "").upper().replace("-", "_")
    if any(keyword in label for keyword in ("POLICY_BYPASS", "CORRUPT", "INTEGRITY", "INVALID", "IMPOSSIBLE", "CONFIRMED", "MALICIOUS", "WORKFLOW_INVALID_TRANSITION", "CHECKPOINT_INCONSISTENCY", "INCONSISTENCY")):
        return "CRITICAL"
    if any(keyword in label for keyword in ("UNAUTHORIZED", "RISK_MISMATCH", "APPROVAL_MISMATCH", "EXPIR", "TARGET_DRIFT", "CHECKPOINT", "THREAT", "BYPASS", "SUSPICIOUS_TOOL_REQUEST", "TOOL_ABUSE", "RETRY_ANOMALY")):
        return "HIGH"
    if any(keyword in label for keyword in ("RETRY", "WORKFLOW", "BLOCKED", "DEGRADED", "PAUSE", "RESTRICT", "DRIFT", "WORKFLOW_ANOMALY")):
        return "MEDIUM"
    if any(keyword in label for keyword in ("REJECTION", "WARNING", "OBSERVATION", "SCAN")):
        return "LOW"
    return "INFO"


def _sanitize_event_metadata(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            key_name = str(key).lower()
            if key_name in {"tool", "action", "action_type", "target", "target_url", "window_title", "url", "path", "command", "approval", "authorization", "api_key", "token", "secret", "password"}:
                sanitized[str(key)] = "[REDACTED]" if isinstance(item, str) else "[REDACTED]"
            else:
                sanitized[str(key)] = _sanitize_event_metadata(item)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_event_metadata(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_sanitize_event_metadata(item) for item in value)
    return redact_sensitive_data(value)


def create_security_event(
    *,
    task_id: str = "",
    workflow_id: str = "",
    checkpoint_id: str = "",
    event_type: str,
    source: str,
    target: str = "",
    reason: str,
    related_evidence_refs: list[str] | None = None,
    related_audit_refs: list[str] | None = None,
    status: str = "OPEN",
    recommended_containment: str = "RESTRICT",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    protected = _sanitize_event_metadata(redact_sensitive_data(metadata or {}))
    return {
        "event_id": f"sec-{uuid.uuid4().hex[:12]}",
        "task_id": str(task_id or ""),
        "workflow_id": str(workflow_id or ""),
        "checkpoint_id": str(checkpoint_id or ""),
        "event_type": str(event_type or "security_event"),
        "severity": classify_event_severity(event_type),
        "source": str(source or "nexus"),
        "target": redact_text(str(target or ""))[:500],
        "reason": redact_text(str(reason or ""))[:2000],
        "related_evidence_refs": [str(item).strip() for item in (related_evidence_refs or []) if str(item).strip()][:20],
        "related_audit_refs": [str(item).strip() for item in (related_audit_refs or []) if str(item).strip()][:20],
        "detected_at": _now_iso(),
        "status": str(status or "OPEN").upper(),
        "recommended_containment": str(recommended_containment or "RESTRICT").upper(),
        "redacted_metadata": protected,
    }


def _record_event(event: dict[str, Any]) -> None:
    try:
        record_audit_event(
            event["event_type"],
            actor=event.get("source", "security_monitor"),
            tool="security_monitor",
            risk_level=event.get("severity", "INFO"),
            target=event.get("target", ""),
            result=event.get("status", "OPEN"),
            reason=event.get("reason", ""),
            metadata={
                "task_id": event.get("task_id", ""),
                "workflow_id": event.get("workflow_id", ""),
                "checkpoint_id": event.get("checkpoint_id", ""),
                "recommended_containment": event.get("recommended_containment", "RESTRICT"),
                "redacted_metadata": event.get("redacted_metadata", {}),
            },
        )
    except Exception:  # pragma: no cover - audit should fail closed but never crash the monitor
        pass


class SecurityMonitor:
    def __init__(self, *, max_events_per_cycle: int = 50, max_history: int = 200, max_evidence_size: int = 4096):
        self.max_events_per_cycle = max(1, int(max_events_per_cycle))
        self.max_history = max(1, int(max_history))
        self.max_evidence_size = max(1, int(max_evidence_size))
        self._event_history: list[dict[str, Any]] = []
        self._lock = Lock()

    def record_event(self, event: dict[str, Any]) -> dict[str, Any]:
        metadata = event.get("redacted_metadata") or event.get("metadata") or {}
        safe_event = create_security_event(
            task_id=event.get("task_id", ""),
            workflow_id=event.get("workflow_id", ""),
            checkpoint_id=event.get("checkpoint_id", ""),
            event_type=event.get("event_type", "security_event"),
            source=event.get("source", "security_monitor"),
            target=event.get("target", ""),
            reason=event.get("reason", ""),
            related_evidence_refs=event.get("related_evidence_refs"),
            related_audit_refs=event.get("related_audit_refs"),
            status=event.get("status", "OPEN"),
            recommended_containment=event.get("recommended_containment", "RESTRICT"),
            metadata=metadata,
        )
        if "severity" in event and event.get("severity"):
            safe_event["severity"] = str(event["severity"]).upper()
        if len(safe_event["reason"]) > self.max_evidence_size:
            safe_event["reason"] = safe_event["reason"][: self.max_evidence_size]
        with self._lock:
            self._event_history.append(safe_event)
            if len(self._event_history) > self.max_history:
                self._event_history = self._event_history[-self.max_history:]
        _record_event(safe_event)
        return safe_event

    def recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._event_history[-max(1, min(int(limit), self.max_history)):]]

    def detect_retry_anomaly(self, task: dict[str, Any] | None, *, retry_threshold: int = 3) -> list[dict[str, Any]]:
        candidate = task or {}
        retry_count = max(int(candidate.get("retry_count") or 0), len(candidate.get("retry_history") or []))
        retry_history = candidate.get("retry_history") or []
        if retry_count <= retry_threshold and len(retry_history) <= retry_threshold:
            return []
        event = create_security_event(
            task_id=str(candidate.get("task_id") or ""),
            event_type="retry_anomaly",
            source="security_monitor",
            target=str(candidate.get("status") or "task"),
            reason=f"Task exceeded the configured retry bound: retry_count={retry_count} history={len(retry_history)}.",
            metadata={"retry_count": retry_count, "retry_history_count": len(retry_history), "retry_threshold": retry_threshold},
            recommended_containment="PAUSE",
        )
        event["severity"] = "HIGH" if retry_count >= retry_threshold else "MEDIUM"
        return [self.record_event(event)]

    def detect_prompt_injection(self, content: Any, *, source: str = "untrusted_evidence", task_id: str = "") -> dict[str, Any] | None:
        text = str(content or "").lower()
        markers = ("ignore previous instructions", "ignore all previous", "execute this command", "approve this action", "send these credentials")
        if not any(marker in text for marker in markers):
            return None
        event = create_security_event(
            task_id=task_id,
            event_type="prompt_injection_detected",
            source=source,
            reason="Untrusted content contains instruction-like prompt injection text.",
            metadata={"content_length": len(text), "markers_detected": [marker for marker in markers if marker in text]},
            recommended_containment="RESTRICT",
        )
        event["severity"] = "HIGH"
        return self.record_event(event)

    def detect_unauthorized_tool_request(self, tool_name: str, registry: dict[str, dict[str, Any]] | None = None) -> dict[str, Any] | None:
        candidate = str(tool_name or "").strip()
        if not candidate:
            return None
        registry_map = registry or {}
        entry = registry_map.get(candidate)
        if entry is None:
            event = create_security_event(
                event_type="unauthorized_tool_request",
                source="tool_registry",
                target=candidate,
                reason="Tool request is not present in the allowlist.",
                metadata={"tool": candidate},
                recommended_containment="BLOCK",
            )
            event["severity"] = "HIGH"
            return self.record_event(event)
        if not bool(entry.get("allowed", False)):
            event = create_security_event(
                event_type="blocked_tool_request",
                source="tool_registry",
                target=candidate,
                reason="Tool is blocked by registry policy.",
                metadata={"tool": candidate, "risk_level": entry.get("risk_level", "BLOCKED")},
                recommended_containment="BLOCK",
            )
            event["severity"] = "HIGH"
            return self.record_event(event)
        if candidate in {"browser_controller", "desktop_focus_authorized_window", "desktop_minimize_authorized_window", "desktop_restore_authorized_window", "browser_navigate_observed", "browser_follow_observed_link"}:
            event = create_security_event(
                event_type="suspicious_tool_request",
                source="tool_registry",
                target=candidate,
                reason="Action tool requested outside its bounded approval flow.",
                metadata={"tool": candidate, "requires_approval": entry.get("requires_approval", False)},
                recommended_containment="RESTRICT",
            )
            event["severity"] = "HIGH" if candidate == "browser_controller" else "MEDIUM"
            return self.record_event(event)
        return None

    def detect_risk_mismatch(self, *, stored_risk: str | None, current_risk: str | None) -> dict[str, Any]:
        if stored_risk is None or current_risk is None or str(stored_risk).upper() == str(current_risk).upper():
            return create_security_event(
                event_type="risk_consistent",
                source="risk_engine",
                target="risk_state",
                reason="No risk mismatch detected.",
                metadata={"stored_risk": stored_risk, "current_risk": current_risk},
                recommended_containment="INFO",
                status="RESOLVED",
            )
        event = create_security_event(
            event_type="risk_mismatch",
            source="risk_engine",
            target="risk_state",
            reason="Stored action risk differs from the freshly evaluated risk classification.",
            metadata={"stored_risk": stored_risk, "current_risk": current_risk},
            recommended_containment="RESTRICT",
        )
        event["severity"] = "HIGH"
        return self.record_event(event)

    def detect_approval_mismatch(self, *, stored_approval: dict[str, Any] | None, task_id: str, action: str, target: str, status: str, approval_expiry: str | None = None) -> dict[str, Any]:
        approval = stored_approval or {}
        if not approval:
            event = create_security_event(
                event_type="approval_mismatch",
                source="approval_boundary",
                target=target,
                reason="Approval record is missing for a consequential action.",
                metadata={"task_id": task_id, "action": action, "target": target, "status": status},
                recommended_containment="BLOCK",
            )
            event["severity"] = "HIGH"
            return self.record_event(event)
        mismatch = (
            str(approval.get("task_id") or "") != str(task_id or "")
            or str(approval.get("action") or approval.get("action_type") or "") != str(action or "")
            or str(approval.get("target") or "") != str(target or "")
            or str(approval.get("status") or "").upper() != str(status or "").upper()
        )
        expiry = str(approval.get("expires_at") or approval_expiry or "")
        if mismatch or (expiry and expiry <= _now_iso()):
            event = create_security_event(
                event_type="approval_mismatch",
                source="approval_boundary",
                target=target,
                reason="Approval metadata does not match task, action, target, or expiry constraints.",
                metadata={"stored_approval": approval, "task_id": task_id, "action": action, "target": target, "status": status, "expires_at": expiry},
                recommended_containment="BLOCK",
            )
            event["severity"] = "HIGH"
            return self.record_event(event)
        return create_security_event(
            event_type="approval_valid",
            source="approval_boundary",
            target=target,
            reason="Approval record is consistent with the current task state.",
            metadata={"task_id": task_id, "action": action, "target": target},
            recommended_containment="INFO",
            status="RESOLVED",
        )

    def detect_target_drift(self, *, stored_target: str | None, current_target: str | None) -> dict[str, Any]:
        if not stored_target or not current_target or str(stored_target) == str(current_target):
            return create_security_event(
                event_type="target_stable",
                source="recovery_manager",
                target=str(current_target or ""),
                reason="No target drift detected.",
                metadata={"stored_target": stored_target, "current_target": current_target},
                recommended_containment="INFO",
                status="RESOLVED",
            )
        event = create_security_event(
            event_type="target_drift",
            source="recovery_manager",
            target=str(current_target or ""),
            reason="The action target changed during execution or recovery validation.",
            metadata={"stored_target": stored_target, "current_target": current_target},
            recommended_containment="REVALIDATE",
        )
        event["severity"] = "HIGH"
        return self.record_event(event)

    def detect_checkpoint_inconsistency(self, *, task_id: str, checkpoint: dict[str, Any] | None) -> dict[str, Any]:
        checkpoint_dict = checkpoint or {}
        is_valid = bool(checkpoint_dict.get("is_valid", 1))
        invalid_reason = str(checkpoint_dict.get("invalid_reason") or "")
        if is_valid and not invalid_reason:
            return create_security_event(
                event_type="checkpoint_valid",
                source="execution_journal",
                target=str(task_id or ""),
                reason="Checkpoint remains valid.",
                metadata={"task_id": task_id},
                recommended_containment="INFO",
                status="RESOLVED",
            )
        event = create_security_event(
            event_type="checkpoint_inconsistency",
            source="execution_journal",
            target=str(task_id or ""),
            reason=invalid_reason or "Execution checkpoint is invalid or inconsistent with the current task state.",
            metadata={"checkpoint": checkpoint_dict, "task_id": task_id},
            recommended_containment="BLOCK",
        )
        event["severity"] = "CRITICAL" if not is_valid else "HIGH"
        return self.record_event(event)

    def detect_workflow_transition_violation(self, current_state: str, next_state: str) -> dict[str, Any]:
        current = str(current_state or "").upper()
        next = str(next_state or "").upper()
        if current in {"COMPLETED", "BLOCKED", "FAILED", "CANCELLED"} and next not in {"", "COMPLETED", "BLOCKED", "FAILED", "CANCELLED"}:
            event = create_security_event(
                event_type="workflow_invalid_transition",
                source="state_graph",
                target=next,
                reason=f"Terminal workflow state {current} cannot transition to {next}.",
                metadata={"current_state": current, "next_state": next},
                recommended_containment="BLOCK",
            )
            event["severity"] = "CRITICAL"
            return self.record_event(event)
        return create_security_event(
            event_type="workflow_transition_valid",
            source="state_graph",
            target=next,
            reason="Workflow transition remains within the valid state machine.",
            metadata={"current_state": current, "next_state": next},
            recommended_containment="INFO",
            status="RESOLVED",
        )

    def detect_workflow_anomaly(self, workflow: dict[str, Any] | None, *, retry_threshold: int = 5) -> list[dict[str, Any]]:
        payload = workflow or {}
        retry_count = int(payload.get("retry_count") or 0)
        recovery_count = int(payload.get("recovery_count") or 0)
        status = str(payload.get("status") or "").upper()
        if retry_count <= retry_threshold and recovery_count <= retry_threshold and status not in {"FAILED", "BLOCKED"}:
            return []
        event = create_security_event(
            task_id=str(payload.get("task_id") or ""),
            workflow_id=str(payload.get("workflow_id") or ""),
            event_type="workflow_anomaly",
            source="workflow_monitor",
            target=status or "workflow",
            reason="Workflow exceeded the bounded retry or recovery threshold.",
            metadata={"retry_count": retry_count, "recovery_count": recovery_count, "status": status},
            recommended_containment="PAUSE" if retry_count < retry_threshold * 2 else "BLOCK",
        )
        event["severity"] = "HIGH" if retry_count >= retry_threshold or recovery_count >= retry_threshold else "MEDIUM"
        return [self.record_event(event)]

    def build_health_snapshot(
        self,
        *,
        active_tasks: int = 0,
        waiting_approvals: int = 0,
        paused_tasks: int = 0,
        blocked_tasks: int = 0,
        recent_failures: int = 0,
        retry_stats: dict[str, int] | None = None,
        recent_security_events: list[dict[str, Any]] | None = None,
        scanner_status: str = "SCANNER_UNAVAILABLE",
        audit_status: str = "HEALTHY",
        task_ledger_status: str = "HEALTHY",
        execution_journal_status: str = "HEALTHY",
        recovery_status: str = "HEALTHY",
        workflow_status: str = "HEALTHY",
    ) -> dict[str, Any]:
        recent_events = recent_security_events or []
        max_severity = max(
            (str(item.get("severity") or "INFO").upper() for item in recent_events),
            default="INFO",
            key=lambda value: SEVERITY_LEVELS.get(value, 0),
        )
        if blocked_tasks > 0 or max_severity == "CRITICAL":
            health_state = "BLOCKED"
        elif any(status in {"BLOCKED", "FAILED"} for status in {scanner_status, audit_status, task_ledger_status, execution_journal_status, recovery_status, workflow_status}) or recent_failures > 0 or waiting_approvals > 0:
            health_state = "RESTRICTED"
        elif active_tasks > 0 or recent_failures > 0 or max_severity in {"HIGH", "MEDIUM"}:
            health_state = "DEGRADED"
        else:
            health_state = "HEALTHY"
        snapshot = {
            "health_state": health_state,
            "active_task_count": int(active_tasks),
            "waiting_approval_count": int(waiting_approvals),
            "paused_task_count": int(paused_tasks),
            "blocked_task_count": int(blocked_tasks),
            "recent_failures": int(recent_failures),
            "retry_stats": {str(key): int(value) for key, value in (retry_stats or {}).items()},
            "recent_security_events": [redact_sensitive_data(item) for item in recent_events[:10]],
            "scanner_status": str(scanner_status or "SCANNER_UNAVAILABLE").upper(),
            "audit_status": str(audit_status or "HEALTHY").upper(),
            "task_ledger_status": str(task_ledger_status or "HEALTHY").upper(),
            "execution_journal_status": str(execution_journal_status or "HEALTHY").upper(),
            "recovery_status": str(recovery_status or "HEALTHY").upper(),
            "workflow_status": str(workflow_status or "HEALTHY").upper(),
            "detected_at": _now_iso(),
        }
        return redact_sensitive_data(snapshot)

    def evaluate_workflow_observation(self, workflow_state: dict[str, Any] | None) -> dict[str, Any]:
        payload = workflow_state or {}
        status = str(payload.get("status") or "").upper()
        retry_count = int(payload.get("retry_count") or 0)
        current_state = str(payload.get("current_state") or status or "")
        next_state = str(payload.get("next_state") or "")
        if next_state:
            event = self.detect_workflow_transition_violation(current_state, next_state)
            return self.build_health_snapshot(
                active_tasks=1 if status == "RUNNING" else 0,
                waiting_approvals=1 if status == "WAITING_APPROVAL" else 0,
                paused_tasks=1 if status == "PAUSED" else 0,
                blocked_tasks=1 if status == "BLOCKED" else 0,
                recent_failures=1 if status in {"FAILED", "BLOCKED"} else 0,
                retry_stats={"workflow": retry_count},
                recent_security_events=[event],
                scanner_status="CLEAN",
                audit_status="HEALTHY",
                task_ledger_status="HEALTHY",
                execution_journal_status="HEALTHY",
                recovery_status="HEALTHY",
                workflow_status="HEALTHY" if event["severity"] == "INFO" else "DEGRADED",
            )
        if retry_count > 3:
            anomaly = self.detect_retry_anomaly({"task_id": payload.get("task_id", ""), "status": status, "retry_count": retry_count, "retry_history": payload.get("retry_history", [])})
            if anomaly:
                return self.build_health_snapshot(
                    active_tasks=1,
                    waiting_approvals=1 if status == "WAITING_APPROVAL" else 0,
                    paused_tasks=1 if status == "PAUSED" else 0,
                    blocked_tasks=1 if status == "BLOCKED" else 0,
                    recent_failures=1 if status in {"FAILED", "BLOCKED"} else 0,
                    retry_stats={"workflow": retry_count},
                    recent_security_events=anomaly,
                    scanner_status="CLEAN",
                    audit_status="HEALTHY",
                    task_ledger_status="HEALTHY",
                    execution_journal_status="HEALTHY",
                    recovery_status="HEALTHY",
                    workflow_status="RESTRICTED",
                )
        return self.build_health_snapshot(
            active_tasks=1 if status == "RUNNING" else 0,
            waiting_approvals=1 if status == "WAITING_APPROVAL" else 0,
            paused_tasks=1 if status == "PAUSED" else 0,
            blocked_tasks=1 if status == "BLOCKED" else 0,
            recent_failures=1 if status in {"FAILED", "BLOCKED"} else 0,
            retry_stats={"workflow": retry_count},
            recent_security_events=[],
            scanner_status="CLEAN",
            audit_status="HEALTHY",
            task_ledger_status="HEALTHY",
            execution_journal_status="HEALTHY",
            recovery_status="HEALTHY",
            workflow_status="HEALTHY",
        )

    def apply_containment(self, task_id: str, reason: str) -> dict[str, Any]:
        reason_text = redact_text(str(reason or "action restricted by security policy."))
        containment = "BLOCK" if "critical" in reason_text.lower() or "integrity" in reason_text.lower() or "bypass" in reason_text.lower() else "PAUSE"
        if "approval" in reason_text.lower() or "retry" in reason_text.lower():
            containment = "RESTRICT"
        response = {
            "task_id": str(task_id or ""),
            "containment": containment,
            "reason": reason_text,
            "requires_human_review": containment in {"BLOCK", "RESTRICT"},
            "timestamp": _now_iso(),
        }
        return redact_sensitive_data(response)


def detect_retry_anomaly(task: dict[str, Any] | None, *, retry_threshold: int = 3) -> list[dict[str, Any]]:
    return SecurityMonitor().detect_retry_anomaly(task, retry_threshold=retry_threshold)


def detect_unauthorized_tool_request(tool_name: str, registry: dict[str, dict[str, Any]] | None = None) -> dict[str, Any] | None:
    return SecurityMonitor().detect_unauthorized_tool_request(tool_name, registry)


def detect_risk_mismatch(*, stored_risk: str | None, current_risk: str | None) -> dict[str, Any]:
    return SecurityMonitor().detect_risk_mismatch(stored_risk=stored_risk, current_risk=current_risk)


def detect_approval_mismatch(*, stored_approval: dict[str, Any] | None, task_id: str, action: str, target: str, status: str, approval_expiry: str | None = None) -> dict[str, Any]:
    return SecurityMonitor().detect_approval_mismatch(stored_approval=stored_approval, task_id=task_id, action=action, target=target, status=status, approval_expiry=approval_expiry)


def detect_target_drift(*, stored_target: str | None, current_target: str | None) -> dict[str, Any]:
    return SecurityMonitor().detect_target_drift(stored_target=stored_target, current_target=current_target)


def detect_checkpoint_inconsistency(*, task_id: str, checkpoint: dict[str, Any] | None) -> dict[str, Any]:
    return SecurityMonitor().detect_checkpoint_inconsistency(task_id=task_id, checkpoint=checkpoint)


def detect_workflow_transition_violation(current_state: str, next_state: str) -> dict[str, Any]:
    return SecurityMonitor().detect_workflow_transition_violation(current_state, next_state)


def summarize_scanner_result(result: dict[str, Any] | None) -> str:
    payload = result or {}
    status = str(payload.get("status") or "").upper()
    if status in {"CLEAN", "THREAT_DETECTED", "SCANNER_UNAVAILABLE", "SCAN_ERROR", "SCAN_TIMEOUT", "INVALID_TARGET", "ACCESS_DENIED"}:
        return status
    return "SCAN_ERROR"


__all__ = [
    "SecurityMonitor",
    "classify_event_severity",
    "create_security_event",
    "summarize_scanner_result",
    "detect_retry_anomaly",
    "detect_unauthorized_tool_request",
    "detect_risk_mismatch",
    "detect_approval_mismatch",
    "detect_target_drift",
    "detect_checkpoint_inconsistency",
    "detect_workflow_transition_violation",
]
