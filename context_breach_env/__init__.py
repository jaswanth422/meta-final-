"""Context Breach public API without eager training/runtime imports."""

from __future__ import annotations

from importlib import import_module
from typing import Any


_EXPORTS = {
    "AgentMessage": ("context_breach_env.integrations", "AgentMessage"),
    "AgentWorkflowGuard": (
        "context_breach_env.integrations",
        "AgentWorkflowGuard",
    ),
    "ContextBreachAction": ("context_breach_env.models", "ContextBreachAction"),
    "ContextBreachEnv": ("context_breach_env.client", "ContextBreachEnv"),
    "ContextBreachObservation": (
        "context_breach_env.models",
        "ContextBreachObservation",
    ),
    "ContextBreachEnvironment": (
        "context_breach_env.server.context_breach_environment",
        "ContextBreachEnvironment",
    ),
    "ContextBreachGuard": ("context_breach_env.sdk", "ContextBreachGuard"),
    "GuardResult": ("context_breach_env.sdk", "GuardResult"),
    "RuntimeDecision": ("context_breach_env.integrations", "RuntimeDecision"),
    "ToolCall": ("context_breach_env.integrations", "ToolCall"),
    "UnsafeAgentAction": ("context_breach_env.sdk", "UnsafeAgentAction"),
}


def __getattr__(name: str) -> Any:
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute = target
    value = getattr(import_module(module_name), attribute)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()).union(_EXPORTS))


__all__ = sorted(_EXPORTS)
