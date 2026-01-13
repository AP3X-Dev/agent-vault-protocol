from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


AVPVersion = Literal["1.0"]
EnvName = Literal["dev", "staging", "prod"]
ModeName = Literal["secret_resolution", "proxy_only", "both"]


class StrictAVPModel(BaseModel):
    """Base model for AVP messages that forbids extra fields.

    AVP-021: Security-sensitive payloads must reject unknown fields
    to prevent injection attacks and ensure protocol compliance.
    """
    model_config = ConfigDict(extra="forbid")


class Capability(StrictAVPModel):
    """Capability grant for a service."""
    service: str
    scopes: List[str]
    environment: EnvName
    resource: Optional[str] = None
    mode: ModeName = "both"


class AgentHello(StrictAVPModel):
    """Agent session initiation request."""
    avp_version: AVPVersion = "1.0"
    type: Literal["agent_hello"] = "agent_hello"
    agent_id: str
    agent_version: str = "0.0.0"
    runtime: str = "unknown"
    metadata: Dict[str, Any] = Field(default_factory=dict)
    requested_capabilities: List[Capability]


class AgentSession(StrictAVPModel):
    """Agent session response after successful hello."""
    avp_version: AVPVersion = "1.0"
    type: Literal["agent_session"] = "agent_session"
    session_id: str
    session_token: str
    agent_id: str
    principal_id: str
    granted_capabilities: List[Capability]
    expires_at: str
    constraints: Dict[str, Any] = Field(default_factory=dict)
    capability_handles: Dict[str, str] = Field(default_factory=dict)


class ResolveFilters(StrictAVPModel):
    """Filters for secret resolution request."""
    services: Optional[List[str]] = None
    format: Literal["environment", "json"] = "environment"


class ResolveSecrets(StrictAVPModel):
    """Request to resolve secrets for granted capabilities."""
    avp_version: AVPVersion = "1.0"
    type: Literal["resolve_secrets"] = "resolve_secrets"
    session_id: str
    filters: ResolveFilters = Field(default_factory=ResolveFilters)


class SecretBundle(StrictAVPModel):
    """Response containing resolved secrets."""
    avp_version: AVPVersion = "1.0"
    type: Literal["secret_bundle"] = "secret_bundle"
    session_id: str
    environment: EnvName
    secrets: Dict[str, Any]


class ProxyCall(StrictAVPModel):
    """Request to proxy an API call through AVP."""
    avp_version: AVPVersion = "1.0"
    type: Literal["proxy_call"] = "proxy_call"
    session_id: str
    capability_handle: str
    operation: str
    payload: Dict[str, Any] = Field(default_factory=dict)


class ProxyError(StrictAVPModel):
    """Error information from a proxy call."""
    code: str
    message: str


class ProxyResult(StrictAVPModel):
    """Response from a proxy call."""
    avp_version: AVPVersion = "1.0"
    type: Literal["proxy_result"] = "proxy_result"
    request_id: str
    status: Literal["ok", "error"]
    result: Optional[Dict[str, Any]] = None
    error: Optional[ProxyError] = None


class SessionRevoke(StrictAVPModel):
    """Request to revoke a session."""
    avp_version: AVPVersion = "1.0"
    type: Literal["session_revoke"] = "session_revoke"
    session_id: str
    reason: str = "revoked"


class SessionStatusResponse(StrictAVPModel):
    """Response containing session status."""
    avp_version: AVPVersion = "1.0"
    type: Literal["session_status_response"] = "session_status_response"
    session_id: str
    active: bool
    expires_at: str
    granted_capabilities: List[Capability]


class AVPError(StrictAVPModel):
    """AVP error envelope format."""
    avp_version: AVPVersion = "1.0"
    type: Literal["error"] = "error"
    code: str
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)
