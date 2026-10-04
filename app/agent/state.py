from typing import Any, TypedDict


class NexusState(TypedDict):
    user_request: str

    observations: list[str]

    priority: str

    selected_tool: str

    investigation: list[str]

    plan: list[str]

    target_file: str
    old_code: str
    new_code: str

    approval_required: bool
    approved: bool
    approval_override: str

    action_result: str

    verification: str
    retry_count: int
    verification_history: list[str]
    last_verification: str
    memory_context: str
    selected_tools: list[str]
    selected_files: list[str]
    observation_results: list[dict[str, Any]]
    action_tool: str
    action_spec: dict[str, Any]
    action_target: str
    action_type: str
    approval_id: str
    journal_checkpoint_id: str
    proposal_hash: str
    execution_id: str
    tool_results: list[str]
    workspace_event: str
    monitoring_active: bool
    risk_decision: dict[str, Any]
    audit_error: str
    browser_url: str
    browser_action_executed: bool
    browser_action_result: dict[str, Any]
    browser_revalidator: Any
    normalized_evidence: list[dict[str, Any]]
    evidence_correlations: list[dict[str, Any]]
    evidence_conflicts: list[dict[str, Any]]
    reasoning_context: str
    decision_stage: str
    decision_reason: str
    final_outcome: str
    user_constraints: dict[str, bool]
    request_intent: str
    evidence_scope: str
    goal_plan: list[dict[str, Any]]
    goal_error: str
    task_id: str
    task_status: str
    task_resume_requested: bool
    task_resume_reason: str
    task_context: str
    persistence_db_path: str
    journal_db_path: str
    approval_db_path: str
    permission_id: str
    permission_decision: dict[str, Any]
    permission_db_path: str
    dna_db_path: str
    dna_preferences: list[dict[str, Any]]
    scope_decision: dict[str, Any]
    scope_db_path: str
    privacy_decision: dict[str, Any]

    plan_version: str
    plan_hash: str
    plan_revisions: int
    current_subgoal_id: str
    subgoal_statuses: dict[str, str]
    completed_subgoals: list[str]
    pending_subgoals: list[str]
    blocked_subgoals: list[str]
    task_retry_count: int
    subgoal_retry_count: dict[str, int]
    failure_classifications: dict[str, str]
    adaptation_history: list[dict[str, Any]]
    completion_evidence: list[str]
    environment_fingerprint: str
    workspace_root: str
    _phase32_subgoal_success: bool
    _phase32_subgoal_outcome: str
    phase32_loop_steps: int
    autonomous_execution_enabled: bool
    capability_context: dict[str, Any]
    subgoal_contexts: dict[str, dict[str, Any]]
    subgoal_lineage: dict[str, dict[str, Any]]
    execution_ids: dict[str, str]
    consumed_execution_ids: list[str]
    plan_history: list[dict[str, Any]]
    recovery_history: list[dict[str, Any]]
    recovery_attempts: int
    replan_attempts: int
    subgoal_plan_hash: dict[str, str]
    context_validity: dict[str, str]
    recovery_decision: dict[str, Any]
    recovery_phase: str
    attention_snapshot: dict[str, Any]