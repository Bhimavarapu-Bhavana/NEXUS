from __future__ import annotations

from app.adapters.action_bridge import (
    ADAPTER_ACTION_TYPES,
    adapter_declared_risk,
    execute_adapter_action,
)
from app.adapters.application_context import (
    ADAPTER_APPLICATIONS,
    build_application_context,
    operation_authorized_in_context,
    validate_application_context,
)
from app.adapters.catalog import ensure_adapters_registered
from app.adapters.jobs import (
    fill_application,
    get_application_requirements,
    get_job_details,
    prepare_application,
    search_jobs,
    submit_application,
)
from app.adapters.model import (
    AuthorizationState,
    Capability,
    OperationSchema,
    OutcomeKind,
    ProviderDescriptor,
    ProviderKind,
    operation_risk,
)
from app.adapters.registry import (
    ADAPTER_REGISTRY,
    AdapterRegistry,
    register_provider,
    registered_providers,
    reset_adapter_registry,
    resolve_authorization,
)
from app.adapters.secure_boundary import SECURE_BOUNDARY, SecureCredentialBoundary

ensure_adapters_registered()

__all__ = [
    "ADAPTER_ACTION_TYPES",
    "ADAPTER_APPLICATIONS",
    "ADAPTER_REGISTRY",
    "AuthorizationState",
    "AdapterRegistry",
    "Capability",
    "OperationSchema",
    "OutcomeKind",
    "ProviderDescriptor",
    "ProviderKind",
    "SECURE_BOUNDARY",
    "SecureCredentialBoundary",
    "adapter_declared_risk",
    "build_application_context",
    "ensure_adapters_registered",
    "execute_adapter_action",
    "fill_application",
    "get_application_requirements",
    "get_job_details",
    "operation_authorized_in_context",
    "operation_risk",
    "prepare_application",
    "register_provider",
    "registered_providers",
    "reset_adapter_registry",
    "resolve_authorization",
    "search_jobs",
    "submit_application",
    "validate_application_context",
]