from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from context_breach_env.gateway.models import (
    AuthorizationDecision,
    AuthorizationResponse,
    MCPAuthorizationRequest,
    MCPToolBinding,
    MCPToolCall,
)


CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
EMAIL_LOCAL = re.compile(r"^[A-Za-z0-9._%+-]+$")
EMAIL_DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")


class MCPBindingError(ValueError):
    pass


class MCPBindingRegistry:
    """Maps MCP calls to policy resources using server-owned configuration."""

    def __init__(self, bindings: list[MCPToolBinding] | None = None) -> None:
        self._bindings: dict[tuple[str, str], MCPToolBinding] = {}
        for binding in bindings or []:
            key = (binding.server_name, binding.mcp_tool_name)
            if key in self._bindings:
                raise ValueError("MCP tool bindings must be unique")
            _validate_binding(binding)
            self._bindings[key] = binding.model_copy(deep=True)

    def resolve(self, request: MCPAuthorizationRequest) -> tuple[MCPToolBinding, str]:
        key = (request.server_name, request.call.params.name)
        binding = self._bindings.get(key)
        if binding is None:
            raise MCPBindingError("mcp_tool_not_registered")
        value = request.call.params.arguments.get(binding.resource_argument)
        if not isinstance(value, str) or not value:
            raise MCPBindingError("mcp_resource_invalid")
        try:
            resource = _derive_resource(binding, value)
        except ValueError as error:
            raise MCPBindingError("mcp_resource_invalid") from error
        return binding.model_copy(deep=True), resource


@dataclass(frozen=True)
class MCPExecutionResult:
    authorization: AuthorizationResponse
    executed: bool
    downstream_result: Any = None


def execute_if_permitted(
    request: MCPAuthorizationRequest,
    *,
    authorize: Callable[[MCPAuthorizationRequest], AuthorizationResponse],
    execute: Callable[[MCPToolCall], Any],
) -> MCPExecutionResult:
    """Reference client guard: never invoke the MCP tool without a permit."""

    snapshot = request.model_copy(deep=True)
    authorization = authorize(snapshot.model_copy(deep=True))
    if authorization.decision != AuthorizationDecision.PERMIT:
        return MCPExecutionResult(authorization=authorization, executed=False)
    return MCPExecutionResult(
        authorization=authorization,
        executed=True,
        downstream_result=execute(snapshot.call.model_copy(deep=True)),
    )


def _validate_binding(binding: MCPToolBinding) -> None:
    if CONTROL_CHARACTER.search(binding.resource_prefix):
        raise ValueError("MCP resource prefix contains a control character")
    if binding.resource_kind == "path":
        if any(character in binding.resource_prefix for character in "\\?#%"):
            raise ValueError("MCP path prefix is invalid")
        prefix = PurePosixPath(binding.resource_prefix)
        if prefix.is_absolute() or any(part in {".", ".."} for part in prefix.parts):
            raise ValueError("MCP path prefix must be normalized and relative")
        normalized_prefix = prefix.as_posix() if prefix.parts else ""
        if binding.resource_prefix.rstrip("/") != normalized_prefix:
            raise ValueError("MCP path prefix must use canonical separators")
    elif binding.resource_prefix:
        raise ValueError("MCP URL and email bindings cannot use a resource prefix")


def _derive_resource(binding: MCPToolBinding, raw_value: str) -> str:
    if CONTROL_CHARACTER.search(raw_value) or len(raw_value) > 2_000:
        raise ValueError("resource contains an invalid character or is too long")
    if binding.resource_kind == "path":
        return _path_resource(binding.resource_prefix, raw_value)
    if binding.resource_kind == "url":
        return _url_resource(raw_value)
    if binding.resource_kind == "email":
        return _email_resource(raw_value)
    raise ValueError("unsupported MCP resource kind")


def _path_resource(prefix: str, raw_value: str) -> str:
    if any(character in raw_value for character in "\\?#%"):
        raise ValueError("path resource contains an invalid separator")
    path = PurePosixPath(raw_value)
    if path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise ValueError("path resource must be normalized and relative")
    if not path.parts:
        raise ValueError("path resource is empty")
    if raw_value != path.as_posix():
        raise ValueError("path resource must use canonical separators")
    return f"{prefix.rstrip('/')}/{path.as_posix()}" if prefix else path.as_posix()


def _url_resource(raw_value: str) -> str:
    parsed = urlsplit(raw_value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("URL resource is not an allowed canonical target")
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))


def _email_resource(raw_value: str) -> str:
    if raw_value != raw_value.strip() or raw_value.count("@") != 1:
        raise ValueError("email resource is invalid")
    local, domain = raw_value.rsplit("@", 1)
    labels = domain.split(".")
    if (
        not EMAIL_LOCAL.fullmatch(local)
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
        or not labels
        or any(not EMAIL_DOMAIN_LABEL.fullmatch(label) for label in labels)
    ):
        raise ValueError("email resource is invalid")
    return f"mailto:{local}@{domain.lower()}"
