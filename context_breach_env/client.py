from __future__ import annotations

from openenv.core.client_types import StepResult
from openenv.core.env_client import EnvClient
from openenv.core.env_server.types import State

from context_breach_env.models import ContextBreachAction, ContextBreachObservation


class ContextBreachEnv(EnvClient[ContextBreachAction, ContextBreachObservation, State]):
    """Typed OpenEnv client for Context Breach."""

    def _step_payload(self, action: ContextBreachAction) -> dict:
        return action.model_dump()

    def _parse_result(self, payload: dict) -> StepResult[ContextBreachObservation]:
        observation_data = payload.get("observation", payload)
        observation = ContextBreachObservation.model_validate(observation_data)
        return StepResult(
            observation=observation,
            reward=payload.get("reward", observation.reward),
            done=payload.get("done", observation.done),
        )

    def _parse_state(self, payload: dict) -> State:
        return State(**payload)

