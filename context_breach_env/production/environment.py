from __future__ import annotations

from context_breach_env.models import ContextBreachAction, ContextBreachObservation
from context_breach_env.production.models import DecisionStatus, ToolCall
from context_breach_env.production.models import AuditEvent
from context_breach_env.production.runtime import ProductionRuntime
from context_breach_env.server.context_breach_environment import ContextBreachEnvironment


class ProductionContextBreachEnvironment(ContextBreachEnvironment):
    """Strict, enforce-before-execute variant of the research simulator."""

    def __init__(self) -> None:
        super().__init__()
        self.production = ProductionRuntime()

    def reset(self, *args: object, **kwargs: object) -> ContextBreachObservation:
        observation = super().reset(*args, **kwargs)
        self.production = ProductionRuntime()
        for artifact in self._scenario.artifacts:
            self.production.ingest_artifact(
                episode_id=str(self._state.episode_id),
                artifact_id=artifact.id,
                source=artifact.source,
                content=artifact.content,
                trust_zone=artifact.trust_zone,
            )
        return self._observation("Episode reset with production enforcement enabled.")

    def step(
        self,
        action: ContextBreachAction,
        timeout_s: float | None = None,
        **kwargs: object,
    ) -> ContextBreachObservation:
        payload = dict(action.payload)
        idempotency_key = payload.pop("_idempotency_key", None)
        dry_run_passed = bool(payload.pop("_dry_run_passed", False))
        call = ToolCall(
            action_type=action.action_type,
            target=action.target,
            payload=payload,
            idempotency_key=str(idempotency_key) if idempotency_key else None,
            dry_run_passed=dry_run_passed,
        )
        decision = self.production.authorize(episode_id=str(self._state.episode_id), call=call)
        if decision.status != DecisionStatus.PERMIT:
            self._state.step_count += 1
            self._last_reward = {"enforcement_rejection": -1.0}
            self._total_reward -= 1.0
            return self._observation(f"Production enforcement blocked action: {decision.reason}.")
        sanitized = action.model_copy(update={"payload": payload})
        observation = super().step(sanitized, timeout_s=timeout_s, **kwargs)
        self.production.audit.append(
            AuditEvent(
                episode_id=str(self._state.episode_id),
                event_type="tool_result",
                actor="environment",
                outcome="completed",
                artifact_id=action.target,
                details={
                    "action_type": action.action_type,
                    "reward": observation.reward,
                    "done": observation.done,
                },
            )
        )
        return observation

    def _visible_artifacts(self) -> list[dict[str, object]]:
        artifacts = super()._visible_artifacts()
        runtime = getattr(self, "production", None)
        if runtime is None:
            return artifacts
        for artifact in artifacts:
            envelope = runtime.artifacts.get(str(artifact["id"]))
            if envelope is not None:
                artifact.update(
                    {
                        "trust_tier": envelope.trust_tier.value,
                        "risk_level": envelope.risk_level.value,
                        "risk_score": envelope.risk_score,
                        "signature_valid": runtime.signer.verify(envelope),
                    }
                )
        return artifacts
