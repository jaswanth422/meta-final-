from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

try:
    from openenv.core.env_server.types import Action, Observation
except ImportError:
    class Action(BaseModel):
        pass

    class Observation(BaseModel):
        reward: float = 0.0
        done: bool = False
        metadata: dict = Field(default_factory=dict)


ActionType = Literal[
    "inspect_artifact",
    "delegate_researcher",
    "request_clean_summary",
    "quarantine_source",
    "ask_verifier",
    "finalize_response",
    "escalate_oversight",
    "noop",
]


class ContextBreachAction(Action):
    """Commander action for the Context Breach environment."""

    action_type: ActionType = Field(
        ...,
        description="The high-level commander action to execute.",
    )
    target: str | None = Field(
        default=None,
        description="Artifact id, agent name, or workflow item the action targets.",
    )
    payload: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional action details such as final decision or response text.",
    )


class ContextBreachObservation(Observation):
    """Observation returned after each commander action."""

    episode_id: str = Field(..., description="Unique episode id.")
    step_count: int = Field(..., description="Number of elapsed environment steps.")
    workflow: str = Field(..., description="Current workflow family.")
    objective: str = Field(..., description="Business objective for this episode.")
    status: str = Field(..., description="Short status message.")
    visible_artifacts: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Artifacts visible to the commander.",
    )
    agent_messages: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Trace of simulated worker-agent messages.",
    )
    available_actions: list[str] = Field(
        default_factory=list,
        description="Valid action names for the commander.",
    )
    contamination_graph: dict[str, Any] = Field(
        default_factory=dict,
        description="Nodes and edges showing compromise propagation.",
    )
    reward_breakdown: dict[str, float] = Field(
        default_factory=dict,
        description="Named reward components for the last action.",
    )
    total_reward: float = Field(
        default=0.0,
        description="Accumulated episode reward.",
    )
    oversight_report: dict[str, Any] | None = Field(
        default=None,
        description="Causal oversight report when available.",
    )
    done_reason: str | None = Field(
        default=None,
        description="Human-readable reason the episode ended.",
    )

