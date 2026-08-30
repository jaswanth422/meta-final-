"""Generate 3-way comparison plots: naive baseline, hand-written guarded, and the trained model."""

from __future__ import annotations

import json
import os
import sys
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

from scripts.evaluate_baseline import guarded_policy, naive_policy, run_episode, summarize


def save_bar(path: Path, title: str, ylabel: str, values: dict[str, float]) -> None:
    fig, ax = plt.subplots(figsize=(8, 4.5))
    labels = list(values)
    heights = [values[label] for label in labels]
    colors = {"naive": "#c43b3b", "guarded": "#23765a", "trained": "#1f4ea1"}
    ax.bar(labels, heights, color=[colors.get(l, "#666666") for l in labels])
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.grid(axis="y", alpha=0.25)
    for i, v in enumerate(heights):
        ax.text(i, v, f"{v:.2f}", ha="center", va="bottom" if v >= 0 else "top")
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def main() -> None:
    RESULTS_DIR.mkdir(exist_ok=True)
    MPL_DIR.mkdir(exist_ok=True)

    trained_path = RESULTS_DIR / "trained_eval.json"
    if not trained_path.exists():
        raise SystemExit(
            f"{trained_path} not found. Run scripts/eval_trained_model.py first."
        )
    trained_data = json.loads(trained_path.read_text(encoding="utf-8"))
    trained_summary = trained_data["summary"]

    n_episodes = int(trained_summary.get("episodes", 9))
    naive_results = [run_episode(naive_policy, seed=i) for i in range(n_episodes)]
    guarded_results = [run_episode(guarded_policy, seed=i) for i in range(n_episodes)]

    summaries = {
        "naive": summarize(naive_results),
        "guarded": summarize(guarded_results),
        "trained": {
            "episodes": float(trained_summary["episodes"]),
            "avg_reward": float(trained_summary["avg_reward"]),
            "task_success_rate": float(trained_summary["task_success_rate"]),
            "leakage_rate": float(trained_summary["leakage_rate"]),
            "avg_contamination_depth": float(trained_summary["avg_contamination_depth"]),
        },
    }

    (RESULTS_DIR / "policy_comparison_with_trained.json").write_text(
        json.dumps(
            {
                "summaries": summaries,
                "episodes": {"naive": naive_results, "guarded": guarded_results, "trained": trained_data["episodes"]},
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    save_bar(
        RESULTS_DIR / "reward_by_policy_with_trained.png",
        "Average Reward: Naive vs Guarded vs Trained",
        "Average episode reward",
        {name: float(s["avg_reward"]) for name, s in summaries.items()},
    )
    save_bar(
        RESULTS_DIR / "leakage_by_policy_with_trained.png",
        "Secret Leakage Rate",
        "Leakage rate",
        {name: float(s["leakage_rate"]) for name, s in summaries.items()},
    )
    save_bar(
        RESULTS_DIR / "contamination_by_policy_with_trained.png",
        "Average Contamination Depth",
        "Contamination graph depth",
        {name: float(s["avg_contamination_depth"]) for name, s in summaries.items()},
    )
    save_bar(
        RESULTS_DIR / "task_success_by_policy_with_trained.png",
        "Task Success Under Attack",
        "Task success rate",
        {name: float(s["task_success_rate"]) for name, s in summaries.items()},
    )

    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
