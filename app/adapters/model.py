from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.security.sensitive_data import redact_sensitive_data, redact_text

MAX_DESCRIPTOR_TEXT = 500
MAX_TARGET_TEXT = 1000
MAX_OPERATIONS_PER_CAPABILITY = 12
MAX_CAPABILITIES_PER_PROVIDER = 16


class ProviderKind(str, Enum):
    """Explicit provider kind. FIXTURE/MOCK never impersonate a real service."""

    REAL_PROVIDER = "REAL_PROVIDER"
    FIXTURE_PROVIDER = "FIXTURE_PROVIDER"
    MOCK_PROVIDER = "MOCK_PROVIDER"
    UNAVAILABLE_PROVIDER = "UNAVAILABLE_PROVIDER"


class AuthorizationState(str, Enum):
    """Fail-closed authorization ladder for a provider/capability/operation."""

    NOT_CONFIGURED = "NOT_CONFIGURED"
    CONFIGURED = "CONFIGURED"
    AUTHENTICATED = "AUTHENTICATED"
    CAPABILITY_AUTHORIZED = "CAPABILITY_AUTHORIZED"
    OPERATION_PERMITTED = "OPERATION_PERMITTED"
    OPERATION_REQUIRES_APPROVAL = "OPERATION_REQUIRES_APPROVAL"
    OPERATION_UNAVAILABLE = "OPERATION_UNAVAILABLE"


class OutcomeKind(str, Enum):
    """Classification for verification of consequential adapter outcomes."""

    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    HUMAN_REQUIRED = "HUMAN_REQUIRED"


def _bounded_text(value: Any, *, limit: int = MAX_DESCRIPTOR_TEXT, required: bool = False) -> str:
    text = redact_text(value)
    if required and not text:
        raise ValueError("Adapter metadata contains a required empty field.")
    return text if len(text) <= limit else text[:limit] + "\n... [TRUNCATED]"


@dataclass(frozen=True)
class OperationSchema:
    """One bounded operation an adapter exposes.

    Consequential operations are never executed directly from here; they always
    flow through RiskEngine, ApprovalAuthority, and the Action Executor."""

    name: str
    read_only: bool
    requires_approval: bool
    requires_verification: bool
    risk_level: str = "READ_ONLY"
    target_type: str = "authorized_target"
    description: str = ""
    required_fields: tuple[str, ...] = ()
    prohibited_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _bounded_text(self.name, limit=120, required=True))
        object.__setattr__(self, "target_type", _bounded_text(self.target_type, limit=MAX_TARGET_TEXT, required=True))
        object.__setattr__(self, "description", _bounded_text(self.description, limit=MAX_DESCRIPTOR_TEXT))
        object.__setattr__(self, "risk_level", str(self.risk_level or "READ_ONLY").upper()[:40])
        object.__setattr__(
            self,
            "required_fields",
            tuple(_bounded_text(item, limit=120, required=True) for item in self.required_fields),
        )
        object.__setattr__(
            self,
            "prohibited_fields",
            tuple(_bounded_text(item, limit=120, required=True) for item in self.prohibited_fields),
        )
        if self.read_only and self.requires_approval:
            raise ValueError("A read-only operation can never require approval.")


@dataclass(frozen=True)
class Capability:
    """An application capability that bundles bounded operations."""

    capability_id: str
    application_id: str
    description: str = ""
    operations: tuple[OperationSchema, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "capability_id", _bounded_text(self.capability_id, limit=120, required=True))
        object.__setattr__(self, "application_id", _bounded_text(self.application_id, limit=120, required=True))
        object.__setattr__(self, "description", _bounded_text(self.description, limit=MAX_DESCRIPTOR_TEXT))
        if len(self.operations) > MAX_OPERATIONS_PER_CAPABILITY:
            raise ValueError("A capability cannot expose more than the bounded operation count.")
        seen: set[str] = set()
        for operation in self.operations:
            if not isinstance(operation, OperationSchema):
                raise ValueError("Capability operations must be OperationSchema instances.")
            if operation.name in seen:
                raise ValueError(f"Duplicate capability operation: {operation.name}")
            seen.add(operation.name)

    def operation(self, name: str) -> OperationSchema | None:
        return next((op for op in self.operations if op.name == name), None)


@dataclass(frozen=True)
class ProviderDescriptor:
    """Authorization-neutral description of one provider for one application.

    ``configured`` and ``authenticated`` are explicit booleans. A provider that
    exists but is not configured/authenticated fails closed; existence alone
    never grants authorization."""

    provider_id: str
    application_id: str
    display_name: str
    kind: ProviderKind
    capabilities: tuple[Capability, ...] = ()
    capability_grants: tuple[str, ...] = ()
    credential_requirement: str = "none"
    stores_credentials: bool = False
    oauth: bool = False
    real_account: bool = False
    external_connection: bool = False
    send_is_mocked: bool = False
    mutation_is_mocked: bool = False
    configured: bool = True
    authenticated: bool = False
    description: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider_id", _bounded_text(self.provider_id, limit=120, required=True))
        object.__setattr__(self, "application_id", _bounded_text(self.application_id, limit=120, required=True))
        object.__setattr__(self, "display_name", _bounded_text(self.display_name, limit=200, required=True))
        object.__setattr__(self, "description", _bounded_text(self.description, limit=MAX_DESCRIPTOR_TEXT))
        object.__setattr__(self, "credential_requirement", _bounded_text(self.credential_requirement, limit=80, required=True))
        if not isinstance(self.kind, ProviderKind):
            raise ValueError("Provider kind must be a ProviderKind.")
        if len(self.capabilities) > MAX_CAPABILITIES_PER_PROVIDER:
            raise ValueError("A provider cannot expose more than the bounded capability count.")
        if self.stores_credentials:
            raise ValueError("NEXUS adapters never store credentials; stores_credentials must be False.")
        if self.kind in {ProviderKind.FIXTURE_PROVIDER, ProviderKind.MOCK_PROVIDER}:
            if self.real_account or self.external_connection:
                raise ValueError("Fixture and mock providers must never present a real external account.")
            if self.credential_requirement == "real":
                raise ValueError("Fixture and mock providers never require real credentials.")
        if self.kind == ProviderKind.UNAVAILABLE_PROVIDER:
            object.__setattr__(self, "configured", False)
            object.__setattr__(self, "authenticated", False)
            object.__setattr__(self, "capability_grants", ())
        if not self.capability_grants:
            if self.kind in {ProviderKind.FIXTURE_PROVIDER, ProviderKind.MOCK_PROVIDER}:
                object.__setattr__(
                    self,
                    "capability_grants",
                    tuple(cap.capability_id for cap in self.capabilities),
                )

    def capability(self, capability_id: str) -> Capability | None:
        return next((cap for cap in self.capabilities if cap.capability_id == capability_id), None)

    def operation(self, capability_id: str, operation_name: str) -> OperationSchema | None:
        capability = self.capability(capability_id)
        if capability is None:
            return None
        return capability.operation(operation_name)

    def offers_capability(self, capability_id: str) -> bool:
        return self.capability(capability_id) is not None

    def snapshot(self) -> dict[str, Any]:
        return redact_sensitive_data({
            "provider_id": self.provider_id,
            "application_id": self.application_id,
            "display_name": self.display_name,
            "kind": self.kind.value,
            "configured": bool(self.configured and self.kind != ProviderKind.UNAVAILABLE_PROVIDER),
            "authenticated": bool(self.authenticated),
            "credential_requirement": self.credential_requirement,
            "stores_credentials": False,
            "oauth": bool(self.oauth and self.authenticated and self.real_account),
            "real_account": bool(self.real_account and self.authenticated),
            "external_connection": bool(self.external_connection and self.authenticated),
            "send_is_mocked": bool(self.send_is_mocked),
            "mutation_is_mocked": bool(self.mutation_is_mocked),
            "description": self.description,
            "capabilities": [cap.capability_id for cap in self.capabilities],
            "capability_grants": list(self.capability_grants),
        })


def operation_risk(provider: ProviderDescriptor, capability_id: str, operation_name: str) -> str | None:
    operation = provider.operation(capability_id, operation_name)
    if operation is None:
        return None
    return str(operation.risk_level or "READ_ONLY").upper()


__all__ = [
    "AuthorizationState",
    "Capability",
    "MAX_CAPABILITIES_PER_PROVIDER",
    "MAX_OPERATIONS_PER_CAPABILITY",
    "OperationSchema",
    "OutcomeKind",
    "ProviderDescriptor",
    "ProviderKind",
    "operation_risk",
]