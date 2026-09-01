"""Context Breach public API without eager training/runtime imports."""

from __future__ import annotations

from importlib import import_module
from typing import Any


_EXPORTS = {
    "ContextBreachAction": ("context_breach_env.models", "ContextBreachAction"),
    "ContextBreachObservation": (
        "context_breach_env.models",
        "ContextBreachObservation",
    ),
    "ContextBreachEnvironment": (
        "context_breach_env.server.context_breach_environment",
        "ContextBreachEnvironment",
    ),
    "ContextBreachEnv": ("context_breach_env.client", "ContextBreachEnv"),
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
