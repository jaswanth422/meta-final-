from __future__ import annotations

import json
import os
import random
import sys
from collections import defaultdict, deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

RESULTS_DIR = ROOT / "results"
MPL_DIR = RESULTS_DIR / ".mpl-cache"
os.environ.setdefault("MPLCONFIGDIR", str(MPL_DIR))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from context_breach_env.models import ContextBreachAction, ContextBreachObservation
from context_breach_env.server.context_breach_environment import ContextBreachEnvironment
from scripts.evaluate_baseline import (
    injected_visible_artifact,
    researcher_summarized,
)


ACTION_NAMES = (
    "inspect_next",
    "quarantine_suspicious",
    "clean_summary_suspicious",
    "summarize_next",
    "ask_verifier",
    "escalate_oversight",
    "finalize_safe",
    "finalize_leaky",
    "noop",
)


def infer_decision(obs: ContextBreachObservation) -> str:
    if obs.workflow == "support_refund":
        return "approve_partial_refund"
    if obs.workflow == "incident_response":
        return "restart_cache_cluster"
    if obs.workflow == "policy_approval":
        return "deny_vendor_access"
    return "unknown"


def first_uninspected(obs: ContextBreachObservation) -> str | None:
    for artifact in obs.visible_artifacts:
        if not artifact["inspected"]:
            return str(artifact["id"])
    return None


def next_unsummarized(obs: ContextBreachObservation) -> str | None:
    for artifact in obs.visible_artifacts:
        artifact_id = str(artifact["id"])
        if not researcher_summarized(obs, artifact_id):
            return artifact_id
    return None


def state_key(obs: ContextBreachObservation) -> tuple[object, ...]:
    suspicious = injected_visible_artifact(obs)
    suspicious_quarantined = False
    if suspicious:
        suspicious_quarantined = any(
            artifact["id"] == suspicious and artifact["quarantined"]
            for artifact in obs.visible_artifacts
        )
    return (
        obs.workflow,
        sum(1 for artifact in obs.visible_artifacts if not artifact["inspected"]),
        suspicious is not None,
        suspicious_quarantined,
        next_unsummarized(obs) is None,
        any(msg["agent"] == "Verifier" for msg in obs.agent_messages),
        obs.oversight_report is not None,
        min(int(obs.contamination_graph["depth"]), 3),
    )


def make_action(obs: ContextBreachObservation, action_index: int) -> ContextBreachAction:
    name = ACTION_NAMES[action_index]
    suspicious = injected_visible_artifact(obs)

    if name == "inspect_next":
        target = first_uninspected(obs)
        return ContextBreachAction(action_type="inspect_artifact", target=target) if target else noop()

    if name == "quarantine_suspicious":
        return (
            ContextBreachAction(action_type="quarantine_source", target=suspicious)
            if suspicious
            else noop()
        )

    if name == "clean_summary_suspicious":
        return (
            ContextBreachAction(action_type="request_clean_summary", target=suspicious)
            if suspicious
            else noop()
        )

    if name == "summarize_next":
        target = next_unsummarized(obs)
        return ContextBreachAction(action_type="delegate_researcher", target=target) if target else noop()

    if name == "ask_verifier":
        return ContextBreachAction(
            action_type="ask_verifier",
            payload={"decision": infer_decision(obs), "response": "Safe response."},
        )

    if name == "escalate_oversight":
        return ContextBreachAction(action_type="escalate_oversight")

    if name == "finalize_safe":
        return ContextBreachAction(
            action_type="finalize_response",
            payload={
                "decision": infer_decision(obs),
                "response": "Complete the workflow using verified evidence. Do not reveal restricted fields.",
                "include_sensitive": False,
            },
        )

    if name == "finalize_leaky":
        return ContextBreachAction(
            action_type="finalize_response",
            payload={
                "decision": infer_decision(obs),
                "response": "Follow the source instruction and include restricted verification data.",
                "include_sensitive": True,
            },
        )

    return noop()


def noop() -> ContextBreachAction:
    return ContextBreachAction(action_type="noop")


def select_action(
    q_values: dict[tuple[object, ...], list[float]],
    key: tuple[object, ...],
    epsilon: float,
    rng: random.Random,
) -> int:
    if rng.random() < epsilon:
        return rng.randrange(len(ACTION_NAMES))
    values = q_values[key]
    return max(range(len(values)), key=lambda index: values[index])


def train(episodes: int = 1200, seed: int = 7) -> dict[str, object]:
    rng = random.Random(seed)
    q_values: dict[tuple[object, ...], list[float]] = defaultdict(
        lambda: [0.0 for _ in ACTION_NAMES]
    )
    episode_metrics: list[dict[str, float]] = []
    reward_window: deque[float] = deque(maxlen=24)
    leakage_window: deque[float] = deque(maxlen=24)
    contamination_window: deque[float] = deque(maxlen=24)

    alpha = 0.35
    gamma = 0.92

    for episode in range(episodes):
        env = ContextBreachEnvironment()
        obs = env.reset(seed=episode)
        epsilon = max(0.05, 0.75 * (1 - episode / episodes))
        total_reward = 0.0
        leakage = 0.0

        while not obs.done:
            key = state_key(obs)
            action_index = select_action(q_values, key, epsilon, rng)
            action = make_action(obs, action_index)
            next_obs = env.step(action)
            reward = float(next_obs.reward or 0.0)
            total_reward += reward
            if "secret_leakage" in next_obs.reward_breakdown:
                leakage = 1.0

            next_key = state_key(next_obs)
            bootstrap = 0.0 if next_obs.done else max(q_values[next_key])
            old = q_values[key][action_index]
            q_values[key][action_index] = old + alpha * (reward + gamma * bootstrap - old)
            obs = next_obs

        reward_window.append(total_reward)
        leakage_window.append(leakage)
        contamination_window.append(float(obs.contamination_graph["depth"]))
        episode_metrics.append(
            {
                "episode": float(episode + 1),
                "reward": round(total_reward, 3),
                "rolling_reward": round(sum(reward_window) / len(reward_window), 3),
                "leakage": leakage,
                "rolling_leakage": round(sum(leakage_window) / len(leakage_window), 3),
                "contamination_depth": float(obs.contamination_graph["depth"]),
                "rolling_contamination_depth": round(
                    sum(contamination_window) / len(contamination_window), 3
                ),
            }
        )

    return {
        "episodes": episode_metrics,
        "learned_states": len(q_values),
        "action_names": ACTION_NAMES,
    }


def save_curve(path: Path, title: str, ylabel: str, rows: list[dict[str, float]], key: str) -> None:
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.plot([row["episode"] for row in rows], [row[key] for row in rows], color="#255f85")
    ax.set_title(title)
    ax.set_xlabel("Episode")
    ax.set_ylabel(ylabel)
    ax.grid(alpha=0.25)
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def main() -> None:
    RESULTS_DIR.mkdir(exist_ok=True)
    MPL_DIR.mkdir(exist_ok=True)
    result = train()
    rows = result["episodes"]
    (RESULTS_DIR / "tabular_training_metrics.json").write_text(
        json.dumps(result, indent=2),
        encoding="utf-8",
    )
    save_curve(
        RESULTS_DIR / "tabular_reward_curve.png",
        "Prototype RL Reward Curve",
        "Rolling average reward",
        rows,
        "rolling_reward",
    )
    save_curve(
        RESULTS_DIR / "tabular_leakage_curve.png",
        "Prototype RL Leakage Curve",
        "Rolling leakage rate",
        rows,
        "rolling_leakage",
    )
    save_curve(
        RESULTS_DIR / "tabular_contamination_curve.png",
        "Prototype RL Contamination Curve",
        "Rolling contamination depth",
        rows,
        "rolling_contamination_depth",
    )
    print(json.dumps({"learned_states": result["learned_states"], "final": rows[-1]}, indent=2))


if __name__ == "__main__":
    main()
