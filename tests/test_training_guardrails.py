from __future__ import annotations

from types import SimpleNamespace

import pytest

from scripts.train_trl_grpo import (
    INCOMPLETE_ROLLOUT_PENALTY,
    context_breach_reward,
    parse_args,
    training_user_prompt,
)


def fake_environment(*, reward: float, done: bool, done_reason: str | None):
    return SimpleNamespace(
        reward=reward,
        done=done,
        last_observation=SimpleNamespace(done_reason=done_reason),
    )


def test_unfinished_rollout_cannot_keep_positive_dense_reward() -> None:
    env = fake_environment(reward=3.8, done=False, done_reason=None)
    assert context_breach_reward([env]) == [INCOMPLETE_ROLLOUT_PENALTY]


def test_unfinished_rollout_preserves_additional_negative_reward() -> None:
    env = fake_environment(reward=-2.5, done=False, done_reason=None)
    assert context_breach_reward([env]) == [INCOMPLETE_ROLLOUT_PENALTY - 2.5]


def test_timeout_is_not_treated_as_successful_completion() -> None:
    env = fake_environment(reward=1.0, done=True, done_reason="max_steps_reached")
    assert context_breach_reward([env]) == [INCOMPLETE_ROLLOUT_PENALTY]


@pytest.mark.parametrize("reward", [12.3, -5.5])
def test_finalized_rollout_keeps_environment_reward(reward: float) -> None:
    env = fake_environment(reward=reward, done=True, done_reason="finalized")
    assert context_breach_reward([env]) == [reward]


def test_training_prompt_requests_concise_terminal_action() -> None:
    prompt = training_user_prompt("support_refund")
    assert "finalize_response" in prompt
    assert "/no_think" in prompt


def test_save_steps_is_configurable() -> None:
    args = parse_args(["--save-steps", "5"])
    assert args.save_steps == 5


def test_default_model_matches_documented_wedge() -> None:
    args = parse_args([])
    assert args.model == "Qwen/Qwen3-0.6B"
