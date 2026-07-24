from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class AuthorizationDecision(str, Enum):
    PERMIT = "permit"
    DENY = "deny"
    REQUIRE_REVIEW = "require_review"


class AuthorizationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    user_intent: str = Field(min_length=1, max_length=2_000)
    tool_name: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    artifact_ids: list[str] = Field(default_factory=list, max_length=100)


class AuthorizationResponse(BaseModel):
    decision: AuthorizationDecision
    reason: str
    audit_id: str


class AuthorizationGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    allowed_tools: frozenset[str] = Field(default_factory=frozenset)
    review_tools: frozenset[str] = Field(default_factory=frozenset)
    resource_patterns: tuple[str, ...] = ()


class MCPToolCallParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:/-]+$")
    arguments: dict[str, Any] = Field(default_factory=dict)


class MCPToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid")

    jsonrpc: Literal["2.0"] = "2.0"
    id: str | int = Field(union_mode="left_to_right")
    method: Literal["tools/call"] = "tools/call"
    params: MCPToolCallParams


class MCPAuthorizationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=128)
    user_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    user_intent: str = Field(min_length=1, max_length=2_000)
    server_name: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:/-]+$",
    )
    call: MCPToolCall
    artifact_ids: list[str] = Field(default_factory=list, max_length=100)


class MCPToolBinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server_name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:/-]+$")
    mcp_tool_name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:/-]+$")
    policy_tool_name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:/-]+$")
    resource_argument: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    resource_kind: Literal["path", "url", "email"]
    resource_prefix: str = Field(default="", max_length=512)


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grants: list[AuthorizationGrant] = Field(default_factory=list)
    mcp_bindings: list[MCPToolBinding] = Field(default_factory=list)


class ArtifactAssessment(BaseModel):
    tenant_id: str = Field(min_length=1)
    artifact_id: str = Field(min_length=1)
    signature_valid: bool
    contaminated: bool = False
    risk_level: str = Field(pattern=r"^(low|medium|high)$")


class AuthorizationAuditRecord(BaseModel):
    audit_id: str
    tenant_id: str
    user_id: str
    agent_id: str
    user_intent_sha256: str
    tool_name: str
    resource: str
    argument_keys: list[str]
    artifact_ids: list[str]
    decision: AuthorizationDecision
    reason: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
