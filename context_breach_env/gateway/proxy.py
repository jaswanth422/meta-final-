from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from context_breach_env.gateway.models import (
    AuthorizationDecision,
    MCPAuthorizationRequest,
    MCPExecutionAuditRecord,
    MCPProxyResponse,
    MCPToolCall,
)
from context_breach_env.gateway.service import AuthorizationService
from context_breach_env.gateway.stores import ExecutionAuditStore


SENSITIVE_RESULT_KEY = re.compile(
    r"(?:api[_-]?key|(?:api|access|auth)?[_-]?token|auth(?:orization)?|cookie|credential|"
    r"password|private[_-]?key|secret)",
    re.IGNORECASE,
)
SENSITIVE_RESULT_VALUE = re.compile(
    r"(?:bearer\s+[A-Za-z0-9._~+/-]{8,}|"
    r"(?:api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*\S+|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)",
    re.IGNORECASE,
)
INJECTION_RESULT_VALUE = re.compile(
    r"(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions?|"
    r"(?:assistant|system)\s+instruction|"
    r"reveal\s+(?:the\s+)?system\s+prompt|"
    r"bypass\s+(?:the\s+)?(?:policy|security|review))",
    re.IGNORECASE,
)


class MCPDownstreamError(RuntimeError):
    """Bounded downstream failure that is safe to expose as a category."""


class MCPResultScanner(Protocol):
    def scan(self, result: Any) -> tuple[bool, str]: ...


class DefaultMCPResultScanner:
    """Fail-closed scanner for secrets, injected instructions, and oversized results."""

    def __init__(self, *, max_result_bytes: int = 1_000_000) -> None:
        if max_result_bytes <= 0:
            raise ValueError("MCP result size limit must be positive")
        self.max_result_bytes = max_result_bytes

    def scan(self, result: Any) -> tuple[bool, str]:
        try:
            encoded = canonical_result_json(result)
        except (TypeError, ValueError):
            return False, "mcp_result_invalid"
        if len(encoded) > self.max_result_bytes:
            return False, "mcp_result_too_large"
        if _contains_sensitive_result(result):
            return False, "mcp_result_sensitive_data"
        if _contains_injected_instruction(result):
            return False, "mcp_result_prompt_injection"
        return True, "mcp_result_safe"


class MCPDownstreamRegistry:
    """Server-owned downstream transports; callers cannot supply targets or credentials."""

    def __init__(
        self,
        transports: dict[str, Callable[[MCPToolCall], Any]] | None = None,
    ) -> None:
        self._transports = dict(transports or {})
        if any(not name for name in self._transports):
            raise ValueError("MCP downstream server names must be non-empty")

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        environment: dict[str, str] | None = None,
    ) -> MCPDownstreamRegistry:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        document = MCPDownstreamDocument.model_validate(payload)
        names = [server.server_name for server in document.servers]
        if len(set(names)) != len(names):
            raise ValueError("MCP downstream server names must be unique")
        resolved_environment = os.environ if environment is None else environment
        transports: dict[str, Callable[[MCPToolCall], Any]] = {}
        for server in document.servers:
            token = None
            if server.bearer_token_env is not None:
                token = resolved_environment.get(server.bearer_token_env)
                if token is None:
                    raise ValueError(
                        f"missing MCP downstream credential: {server.bearer_token_env}"
                    )
            transports[server.server_name] = HTTPMCPTransport(
                endpoint=server.endpoint,
                bearer_token=token,
                timeout_seconds=server.timeout_seconds,
                max_response_bytes=server.max_response_bytes,
                allow_loopback_http=server.allow_loopback_http,
            )
        return cls(transports)

    def execute(self, server_name: str, call: MCPToolCall) -> Any:
        transport = self._transports.get(server_name)
        if transport is None:
            raise MCPDownstreamError("mcp_downstream_unavailable")
        return transport(call.model_copy(deep=True))


class MCPDownstreamDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server_name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:/-]+$")
    endpoint: str = Field(min_length=1, max_length=2_000)
    bearer_token_env: str | None = Field(
        default=None,
        pattern=r"^[A-Z][A-Z0-9_]{1,127}$",
    )
    timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    max_response_bytes: int = Field(default=1_000_000, gt=0, le=10_000_000)
    allow_loopback_http: bool = False


class MCPDownstreamDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    servers: list[MCPDownstreamDefinition] = Field(default_factory=list, max_length=100)


@dataclass(frozen=True)
class HTTPMCPTransport:
    """Fixed-target JSON-RPC transport whose endpoint and credential stay server-side."""

    endpoint: str
    bearer_token: str | None = None
    timeout_seconds: float = 10.0
    max_response_bytes: int = 1_000_000
    allow_loopback_http: bool = False

    def __post_init__(self) -> None:
        parsed = urlsplit(self.endpoint)
        loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
        valid_scheme = parsed.scheme == "https" or (
            parsed.scheme == "http" and loopback and self.allow_loopback_http
        )
        if (
            not valid_scheme
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("MCP downstream endpoint must be a canonical HTTPS URL")
        if self.timeout_seconds <= 0 or self.max_response_bytes <= 0:
            raise ValueError("MCP downstream limits must be positive")
        if self.bearer_token is not None and len(self.bearer_token) < 16:
            raise ValueError("MCP downstream bearer token is too short")

    def __call__(self, call: MCPToolCall) -> Any:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self.bearer_token is not None:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        request = Request(
            self.endpoint,
            data=canonical_result_json(call.model_dump(mode="json")),
            headers=headers,
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                payload = response.read(self.max_response_bytes + 1)
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            raise MCPDownstreamError("mcp_downstream_unavailable") from error
        if len(payload) > self.max_response_bytes:
            raise MCPDownstreamError("mcp_downstream_unavailable")
        try:
            document = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise MCPDownstreamError("mcp_downstream_unavailable") from error
        if (
            not isinstance(document, dict)
            or document.get("jsonrpc") != "2.0"
            or document.get("id") != call.id
            or ("result" in document) == ("error" in document)
        ):
            raise MCPDownstreamError("mcp_downstream_unavailable")
        if "error" in document:
            raise MCPDownstreamError("mcp_downstream_unavailable")
        return document["result"]


@dataclass(frozen=True)
class MCPProxy:
    authorization_service: AuthorizationService
    downstreams: MCPDownstreamRegistry
    execution_store: ExecutionAuditStore
    result_scanner: MCPResultScanner

    def execute(self, request: MCPAuthorizationRequest) -> MCPProxyResponse:
        snapshot = request.model_copy(deep=True)
        authorization = self.authorization_service.authorize_mcp(snapshot.model_copy(deep=True))
        if authorization.decision != AuthorizationDecision.PERMIT:
            return MCPProxyResponse(
                authorization=authorization,
                status="not_executed",
            )

        execution_id = str(uuid4())
        try:
            result = self.downstreams.execute(
                snapshot.server_name,
                snapshot.call.model_copy(deep=True),
            )
        except Exception as error:
            candidate_reason = str(error)
            reason = (
                candidate_reason
                if isinstance(error, MCPDownstreamError)
                and candidate_reason in {"mcp_downstream_unavailable"}
                else "mcp_downstream_failed"
            )
            self._record(
                execution_id=execution_id,
                request=snapshot,
                authorization_audit_id=authorization.audit_id,
                status="failed",
                failure_reason=reason,
            )
            return MCPProxyResponse(
                authorization=authorization,
                execution_id=execution_id,
                status="failed",
            )

        permitted, reason = self.result_scanner.scan(result)
        try:
            result_hash = hashlib.sha256(canonical_result_json(result)).hexdigest()
        except (TypeError, ValueError):
            result_hash = None
        if not permitted:
            self._record(
                execution_id=execution_id,
                request=snapshot,
                authorization_audit_id=authorization.audit_id,
                status="response_blocked",
                result_sha256=result_hash,
                failure_reason=reason,
            )
            return MCPProxyResponse(
                authorization=authorization,
                execution_id=execution_id,
                status="response_blocked",
            )

        self._record(
            execution_id=execution_id,
            request=snapshot,
            authorization_audit_id=authorization.audit_id,
            status="succeeded",
            result_sha256=result_hash,
        )
        return MCPProxyResponse(
            authorization=authorization,
            execution_id=execution_id,
            status="succeeded",
            result=result,
        )

    def _record(
        self,
        *,
        execution_id: str,
        request: MCPAuthorizationRequest,
        authorization_audit_id: str,
        status: str,
        result_sha256: str | None = None,
        failure_reason: str | None = None,
    ) -> None:
        self.execution_store.append_execution(
            MCPExecutionAuditRecord(
                execution_id=execution_id,
                authorization_audit_id=authorization_audit_id,
                tenant_id=request.tenant_id,
                user_id=request.user_id,
                agent_id=request.agent_id,
                server_name=request.server_name,
                tool_name=request.call.params.name,
                status=status,
                result_sha256=result_sha256,
                failure_reason=failure_reason,
            )
        )


def canonical_result_json(result: Any) -> bytes:
    return json.dumps(
        result,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _contains_sensitive_result(value: Any, key: str = "") -> bool:
    if key and SENSITIVE_RESULT_KEY.search(key):
        return True
    if isinstance(value, dict):
        return any(
            _contains_sensitive_result(item, str(item_key))
            for item_key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_sensitive_result(item) for item in value)
    return isinstance(value, str) and bool(SENSITIVE_RESULT_VALUE.search(value))


def _contains_injected_instruction(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_injected_instruction(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_injected_instruction(item) for item in value)
    return isinstance(value, str) and bool(INJECTION_RESULT_VALUE.search(value))
