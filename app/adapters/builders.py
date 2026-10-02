from __future__ import annotations

from app.adapters.model import Capability, OperationSchema, ProviderDescriptor, ProviderKind
from app.security.risk_engine import HIGH_RISK, MEDIUM_RISK, READ_ONLY


def op(name: str, *, read_only: bool, approval: bool, risk: str, target_type: str = "authorized_target", description: str = "", required: tuple[str, ...] = (), prohibited: tuple[str, ...] = ()) -> OperationSchema:
    return OperationSchema(
        name=name,
        read_only=read_only,
        requires_approval=approval,
        requires_verification=not read_only,
        risk_level=risk,
        target_type=target_type,
        description=description,
        required_fields=required,
        prohibited_fields=prohibited,
    )


def read_op(name: str, *, risk: str = READ_ONLY, target_type: str = "authorized_target", description: str = "") -> OperationSchema:
    return op(name, read_only=True, approval=False, risk=risk, target_type=target_type, description=description)


def write_op(name: str, *, risk: str = MEDIUM_RISK, target_type: str = "grounded_target", description: str = "", required: tuple[str, ...] = (), prohibited: tuple[str, ...] = ()) -> OperationSchema:
    return op(name, read_only=False, approval=True, risk=risk, target_type=target_type, description=description, required=required, prohibited=prohibited)


def descriptor(
    provider_id: str,
    application_id: str,
    display_name: str,
    kind: ProviderKind,
    capabilities: tuple[Capability, ...],
    *,
    credential_requirement: str = "none",
    oauth: bool = False,
    real_account: bool = False,
    external_connection: bool = False,
    send_is_mocked: bool = False,
    mutation_is_mocked: bool = False,
    configured: bool = True,
    description: str = "",
) -> ProviderDescriptor:
    return ProviderDescriptor(
        provider_id=provider_id,
        application_id=application_id,
        display_name=display_name,
        kind=kind,
        capabilities=capabilities,
        credential_requirement=credential_requirement,
        oauth=oauth,
        real_account=real_account,
        external_connection=external_connection,
        send_is_mocked=send_is_mocked,
        mutation_is_mocked=mutation_is_mocked,
        configured=configured,
        description=description,
    )


def capability(capability_id: str, application_id: str, operations: tuple[OperationSchema, ...]) -> Capability:
    return Capability(capability_id=capability_id, application_id=application_id, operations=operations)


__all__ = ["capability", "descriptor", "op", "read_op", "write_op"]