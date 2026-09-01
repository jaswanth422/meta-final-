"""Identity-aware authorization gateway for agent tool calls."""

from __future__ import annotations

from importlib import import_module
from typing import Any


_EXPORTS = {
    "app": ("context_breach_env.gateway.app", "app"),
    "create_app": ("context_breach_env.gateway.app", "create_app"),
    "AuthorizationService": (
        "context_breach_env.gateway.service",
        "AuthorizationService",
    ),
}


def __getattr__(name: str) -> Any:
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute = target
    value = getattr(import_module(module_name), attribute)
    globals()[name] = value
    return value


__all__ = sorted(_EXPORTS)
