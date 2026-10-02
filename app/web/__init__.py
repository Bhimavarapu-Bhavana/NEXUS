"""NEXUS Web Control Surface.

A local-only user interface over the existing NEXUS control plane. It serves a
static interface and a narrowly scoped API; it never becomes an independent
agent. Requests are routed through the existing TaskRunner -> StateGraph path,
lifecycle transitions through the existing AutonomousService, and approval
decisions through the existing ApprovalAuthority.
"""