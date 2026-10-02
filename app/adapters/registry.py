from __future__ import annotations

from typing import Any

from app.adapters.model import (
    AuthorizationState,
    Capability,
    OperationSchema,
    ProviderDescriptor,
    ProviderKind,
)
from app.security.sensitive_data import redact_sensitive_data, redact_text

MAX_REGISTERED_PROVIDERS = 64
MAX_FILTER_RESULTS = 50

_PERMITTED_STATES = {
    AuthorizationState.OPERATION_PERMITTED,
    AuthorizationState.OPERATION_REQUIRES_APPROVAL,
}


def _bounded_key(value: str, *, limit: int = 120) -> str:
    text = redact_text(value)
    if not text:
        raise ValueError("Provider identifiers must be non-empty.")
    return text if len(text) <= limit else text[:limit]


def operation_for(provider: ProviderDescriptor, capability_id: str, operation_name: str) -> OperationSchema | None:
    capability = provider.capability(capability_id)
    if capability is None:
        return None
    return capability.operation(operation_name)


def resolve_authorization(
    provider: ProviderDescriptor,
    capability_id: str,
    operation_name: str,
) -> AuthorizationState:
    """Resolve the authorization state for one operation with fail-closed logic.

    "The provider exists" is never treated as authorization. The state ladder
    ascends only through configuration, authentication, an explicit capability
    grant, and a bounded operation. Unknown/unavailable states fail closed.
    """
    if not isinstance(provider, ProviderDescriptor):
        raise ValueError("resolve_authorization requires a ProviderDescriptor.")
    capability_key = _bounded_key(capability_id)
    if provider.kind == ProviderKind.UNAVAILABLE_PROVIDER or not provider.configured:
        return AuthorizationState.NOT_CONFIGURED
    if not provider.authenticated:
        return AuthorizationState.CONFIGURED
    capability = provider.capability(capability_key)
    if capability is None:
        return AuthorizationState.OPERATION_UNAVAILABLE
    if capability_key not in provider.capability_grants:
        return AuthorizationState.AUTHENTICATED
    if not operation_name:
        return AuthorizationState.CAPABILITY_AUTHORIZED
    operation_name_key = _bounded_key(operation_name)
    if capability.operation(operation_name_key) is None:
        return AuthorizationState.OPERATION_UNAVAILABLE
    if operation_for(provider, capability_key, operation_name_key).requires_approval:
        return AuthorizationState.OPERATION_REQUIRES_APPROVAL
    return AuthorizationState.OPERATION_PERMITTED


def _fail_closed_reason(state: AuthorizationState) -> str:
    if state == AuthorizationState.NOT_CONFIGURED:
        return "Provider is not configured; configuration requires explicit user authorization."
    if state == AuthorizationState.CONFIGURED:
        return "Provider is configured but not authenticated; authentication is required."
    if state == AuthorizationState.AUTHENTICATED:
        return "Provider is authenticated but the requested capability is not authorized."
    return "Capability or operation is unavailable for this provider."


class AdapterRegistry:
    """Single, bounded registry of provider descriptors for all adapter applications.

    There is intentionally no competing registry: the Tool Registry continues to
    own tool allowlisting and execution; this registry owns provider/capability
    authorization metadata. Selection always fails closed.
    """

    def __init__(self) -> None:
        self._providers: dict[str, ProviderDescriptor] = {}

    def register(self, provider: ProviderDescriptor) -> None:
        if not isinstance(provider, ProviderDescriptor):
            raise ValueError("Only ProviderDescriptor instances can be registered.")
        if provider.provider_id in self._providers:
            raise ValueError(f"Provider {provider.provider_id} is already registered.")
        if len(self._providers) >= MAX_REGISTERED_PROVIDERS:
            raise ValueError("The adapter registry has reached its bounded provider limit.")
        self._providers[provider.provider_id] = provider

    def provider(self, provider_id: str) -> ProviderDescriptor | None:
        key = _bounded_key(provider_id)
        return self._providers.get(key)

    def exists(self, provider_id: str) -> bool:
        key = _bounded_key(provider_id)
        return key in self._providers

    def discover(self, *, application_id: str = "", kind: str = "", max_results: int = MAX_FILTER_RESULTS) -> list[dict[str, Any]]:
        """Return bounded, deterministic, authorization-safe discovery results."""
        limit = max(1, min(int(max_results or 0), MAX_FILTER_RESULTS))
        results: list[ProviderDescriptor] = []
        for provider in sorted(self._providers.values(), key=lambda item: (item.application_id, item.provider_id)):
            if application_id and provider.application_id != application_id:
                continue
            if kind and provider.kind.value != kind:
                continue
            results.append(provider)
            if len(results) >= limit:
                break
        return [redact_sensitive_data(provider.snapshot()) for provider in results]

    def inspect(self, provider_id: str) -> dict[str, Any] | None:
        provider = self.provider(provider_id)
        if provider is None:
            return None
        capability_keys = [
            {
                "capability_id": capability.capability_id,
                "application_id": capability.application_id,
                "operations": [
                    {
                        "name": operation.name,
                        "read_only": bool(operation.read_only),
                        "requires_approval": bool(operation.requires_approval),
                        "requires_verification": bool(operation.requires_verification),
                        "risk_level": operation.risk_level,
                        "target_type": operation.target_type,
                        "required_fields": list(operation.required_fields),
                        "prohibited_fields": list(operation.prohibited_fields),
                    }
                    for operation in capability.operations
                ],
            }
            for capability in provider.capabilities
        ]
        snapshot = dict(provider.snapshot())
        snapshot["capability_details"] = capability_keys
        if not provider.authenticated:
            snapshot["authorization_state"] = AuthorizationState.NOT_CONFIGURED.value if not provider.configured else AuthorizationState.CONFIGURED.value
        elif provider.capabilities:
            snapshot["authorization_state"] = AuthorizationState.CAPABILITY_AUTHORIZED.value
        else:
            snapshot["authorization_state"] = AuthorizationState.NOT_CONFIGURED.value
        return redact_sensitive_data(snapshot)

    def check_auth(self, provider_id: str, capability_id: str, operation_name: str) -> dict[str, Any]:
        """Authorization check for one operation. Automatically fails closed."""
        provider = self.provider(provider_id)
        if provider is None:
            return redact_sensitive_data({
                "provider_id": _bounded_key(provider_id),
                "capability_id": _bounded_key(capability_id),
                "operation_name": _bounded_key(operation_name),
                "authorized": False,
                "requires_approval": False,
                "state": AuthorizationState.NOT_CONFIGURED.value,
                "reason": "Provider is not registered.",
            })
        state = resolve_authorization(provider, capability_id, operation_name)
        permitted = state in _PERMITTED_STATES
        if state == AuthorizationState.OPERATION_REQUIRES_APPROVAL:
            reason = "Operation is authorized but requires explicit human approval through the Approval Authority."
        elif state == AuthorizationState.OPERATION_PERMITTED:
            reason = "Operation is authorized for this provider and capability."
        else:
            reason = _fail_closed_reason(state)
        return redact_sensitive_data({
            "provider_id": provider.provider_id,
            "application_id": provider.application_id,
            "kind": provider.kind.value,
            "capability_id": _bounded_key(capability_id),
            "operation_name": _bounded_key(operation_name),
            "authorized": bool(permitted),
            "requires_approval": state == AuthorizationState.OPERATION_REQUIRES_APPROVAL,
            "state": state.value,
            "reason": reason,
        })

    def select(self, *, application_id: str, capability_id: str, operation_name: str, max_results: int = MAX_FILTER_RESULTS) -> list[dict[str, Any]]:
        """Select compatible, authorization-eligible providers for one operation."""
        limit = max(1, min(int(max_results or 0), MAX_FILTER_RESULTS))
        matches: list[dict[str, Any]] = []
        for provider in sorted(self._providers.values(), key=lambda item: (item.application_id, item.provider_id)):
            if provider.application_id != application_id:
                continue
            if provider.kind == ProviderKind.UNAVAILABLE_PROVIDER:
                continue
            if resolve_authorization(provider, capability_id, operation_name) not in _PERMITTED_STATES:
                continue
            matches.append(self.check_auth(provider.provider_id, capability_id, operation_name))
            if len(matches) >= limit:
                break
        return matches

    def reject_unavailable(self, provider_id: str, reason: str = "Provider is not configured and cannot be used.") -> dict[str, Any]:
        return redact_sensitive_data({
            "provider_id": _bounded_key(provider_id),
            "authorized": False,
            "state": AuthorizationState.OPERATION_UNAVAILABLE.value,
            "reason": redact_text(reason),
        })


ADAPTER_REGISTRY = AdapterRegistry()


def register_provider(provider: ProviderDescriptor) -> None:
    ADAPTER_REGISTRY.register(provider)


def reset_adapter_registry() -> None:
    ADAPTER_REGISTRY._providers.clear()


__all__ = [
    "ADAPTER_REGISTRY",
    "AdapterRegistry",
    "MAX_FILTER_RESULTS",
    "MAX_REGISTERED_PROVIDERS",
    "operation_for",
    "register_provider",
    "registered_providers",
    "reset_adapter_registry",
    "resolve_authorization",
]


def registered_providers() -> list[str]:
    return [str(item.get("provider_id") or "") for item in ADAPTER_REGISTRY.discover()]