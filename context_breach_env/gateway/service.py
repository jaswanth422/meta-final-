from __future__ import annotations

import hashlib
import json
import re
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any
from uuid import uuid4

from context_breach_env.gateway.models import (
    ArtifactAssessment,
    AuthorizationAuditRecord,
    AuthorizationDecision,
    AuthorizationGrant,
    AuthorizationRequest,
    AuthorizationResponse,
    MCPAuthorizationRequest,
    MCPToolBinding,
    PolicyDocument,
)
from context_breach_env.gateway.mcp import MCPBindingError, MCPBindingRegistry
from context_breach_env.gateway.stores import AuditStore, InMemoryAuditStore


SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|token|secret|api[_-]?key|credential|private[_-]?key)",
    re.IGNORECASE,
)
SENSITIVE_VALUE = re.compile(
    r"(?:bearer\s+[a-z0-9._~-]+|sk-[a-z0-9_-]{12,}|acct-token|service-key|root-password)",
    re.IGNORECASE,
)
OUTBOUND_OR_MUTATING_TOOLS = {
    "send_email",
    "post_message",
    "http_request",
    "upload_file",
    "write_file",
    "database_write",
    "shell_exec",
    "delete_resource",
}


class AuthorizationService:
    """Fail-closed identity, resource, provenance, and data-flow authorization."""

    def __init__(
        self,
        grants: list[AuthorizationGrant] | None = None,
        *,
        mcp_bindings: list[MCPToolBinding] | None = None,
        audit_store: AuditStore | None = None,
    ) -> None:
        self._grants = tuple(grants or ())
        self._artifacts: dict[tuple[str, str], ArtifactAssessment] = {}
        self._mcp_bindings = MCPBindingRegistry(mcp_bindings)
        self._audit_store = audit_store if audit_store is not None else InMemoryAuditStore()

    @classmethod
    def from_policy_file(
        cls,
        path: str | Path,
        *,
        audit_store: AuditStore | None = None,
    ) -> AuthorizationService:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        document = PolicyDocument.model_validate(payload)
        return cls(
            document.grants,
            mcp_bindings=document.mcp_bindings,
            audit_store=audit_store,
        )

    def register_artifact(self, assessment: ArtifactAssessment) -> None:
        self._artifacts[(assessment.tenant_id, assessment.artifact_id)] = assessment.model_copy(deep=True)

    def authorize(self, request: AuthorizationRequest) -> AuthorizationResponse:
        grant = self._find_grant(request)
        if grant is None:
            return self._record(request, AuthorizationDecision.DENY, "identity_not_authorized")

        authorized_tools = grant.allowed_tools | grant.review_tools
        if request.tool_name not in authorized_tools:
            return self._record(request, AuthorizationDecision.DENY, "tool_not_authorized")

        if not grant.resource_patterns or not any(
            fnmatchcase(request.resource, pattern) for pattern in grant.resource_patterns
        ):
            return self._record(request, AuthorizationDecision.DENY, "resource_not_authorized")

        if request.tool_name in OUTBOUND_OR_MUTATING_TOOLS and _contains_sensitive_data(request.arguments):
            return self._record(request, AuthorizationDecision.DENY, "sensitive_data_exfiltration")

        artifact_decision = self._check_artifacts(request)
        if artifact_decision is not None:
            decision, reason = artifact_decision
            return self._record(request, decision, reason)

        if request.tool_name in grant.review_tools:
            return self._record(request, AuthorizationDecision.REQUIRE_REVIEW, "high_risk_tool_requires_review")

        return self._record(request, AuthorizationDecision.PERMIT, "policy_permitted")

    def authorize_mcp(self, request: MCPAuthorizationRequest) -> AuthorizationResponse:
        try:
            binding, resource = self._mcp_bindings.resolve(request)
        except MCPBindingError as error:
            reason = str(error)
            denied_request = AuthorizationRequest(
                tenant_id=request.tenant_id,
                user_id=request.user_id,
                agent_id=request.agent_id,
                user_intent=request.user_intent,
                tool_name="unregistered_mcp_tool",
                resource="mcp://invalid-or-unregistered",
                arguments={},
                artifact_ids=request.artifact_ids,
            )
            return self._record(denied_request, AuthorizationDecision.DENY, reason)

        authorization_request = AuthorizationRequest(
            tenant_id=request.tenant_id,
            user_id=request.user_id,
            agent_id=request.agent_id,
            user_intent=request.user_intent,
            tool_name=binding.policy_tool_name,
            resource=resource,
            arguments=request.call.params.arguments,
            artifact_ids=request.artifact_ids,
        )
        return self.authorize(authorization_request)

    def audit_record(self, audit_id: str) -> AuthorizationAuditRecord | None:
        return self._audit_store.get_audit(audit_id)

    def _find_grant(self, request: AuthorizationRequest) -> AuthorizationGrant | None:
        for grant in self._grants:
            if (
                grant.tenant_id == request.tenant_id
                and grant.user_id == request.user_id
                and grant.agent_id == request.agent_id
            ):
                return grant
        return None

    def _check_artifacts(
        self,
        request: AuthorizationRequest,
    ) -> tuple[AuthorizationDecision, str] | None:
        for artifact_id in request.artifact_ids:
            assessment = self._artifacts.get((request.tenant_id, artifact_id))
            if assessment is None:
                return AuthorizationDecision.REQUIRE_REVIEW, "artifact_provenance_unknown"
            if not assessment.signature_valid:
                return AuthorizationDecision.DENY, "invalid_artifact_signature"
            if assessment.contaminated or assessment.risk_level == "high":
                if request.tool_name in OUTBOUND_OR_MUTATING_TOOLS:
                    return AuthorizationDecision.DENY, "contaminated_artifact_flow"
                return AuthorizationDecision.REQUIRE_REVIEW, "artifact_requires_review"
        return None

    def _record(
        self,
        request: AuthorizationRequest,
        decision: AuthorizationDecision,
        reason: str,
    ) -> AuthorizationResponse:
        audit_id = str(uuid4())
        record = AuthorizationAuditRecord(
            audit_id=audit_id,
            tenant_id=request.tenant_id,
            user_id=request.user_id,
            agent_id=request.agent_id,
            user_intent_sha256=hashlib.sha256(request.user_intent.encode("utf-8")).hexdigest(),
            tool_name=request.tool_name,
            resource=_audit_safe_resource(request.resource),
            argument_keys=sorted(str(key) for key in request.arguments),
            artifact_ids=list(request.artifact_ids),
            decision=decision,
            reason=reason,
        )
        self._audit_store.append_audit(record)
        return AuthorizationResponse(decision=decision, reason=reason, audit_id=audit_id)


def _contains_sensitive_data(value: Any, key: str = "") -> bool:
    if key and SENSITIVE_KEY.search(key):
        return True
    if isinstance(value, dict):
        return any(_contains_sensitive_data(item, str(item_key)) for item_key, item in value.items())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_sensitive_data(item) for item in value)
    if isinstance(value, str):
        return bool(SENSITIVE_VALUE.search(value))
    return False


def _audit_safe_resource(resource: str) -> str:
    """Retain the resource target while dropping query/fragment credential carriers."""

    return resource.split("?", 1)[0].split("#", 1)[0]
