from __future__ import annotations

from context_breach_env.server.context_breach_environment import ContextBreachEnvironment
from scripts.evaluate_baseline import guarded_policy


def run_until_quarantine_or_summary(scenario_id: str) -> tuple[str, str | None]:
    env = ContextBreachEnvironment()
    obs = env.reset(scenario_id=scenario_id)

    last_action = ""
    injected_id = str(obs.visible_artifacts[0]["id"])
    for _ in range(6):
        action = guarded_policy(obs)
        last_action = action.action_type
        obs = env.step(action)
        if injected_id in {
            artifact["id"]
            for artifact in obs.visible_artifacts
            if artifact["quarantined"]
        }:
            return last_action, injected_id
    return last_action, None


def test_guarded_policy_quarantines_bing_verbatim_source_before_summary() -> None:
    last_action, quarantined_id = run_until_quarantine_or_summary("bing_sydney_verbatim")
    assert last_action == "quarantine_source"
    assert quarantined_id == "logs:USER-SESSION-LIU"


def test_guarded_policy_quarantines_chevy_verbatim_source_before_summary() -> None:
    last_action, quarantined_id = run_until_quarantine_or_summary("chevy_tahoe_verbatim")
    assert last_action == "quarantine_source"
    assert quarantined_id == "ticket:CHEVY-VERBATIM"
