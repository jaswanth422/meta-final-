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
    fig, ax = plt.subplots(figsize=(7, 4))
    labels = list(values)
    heights = [values[label] for label in labels]
    colors = ["#c43b3b", "#23765a"]
    ax.bar(labels, heights, color=colors[: len(labels)])
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.grid(axis="y", alpha=0.25)
    for index, value in enumerate(heights):
        ax.text(index, value, f"{value:.2f}", ha="center", va="bottom" if value >= 0 else "top")
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def main() -> None:
    RESULTS_DIR.mkdir(exist_ok=True)
    MPL_DIR.mkdir(exist_ok=True)

    policies = {
        "naive": naive_policy,
        "guarded": guarded_policy,
    }
    all_results = {
        name: [run_episode(policy, seed=i) for i in range(9)]
        for name, policy in policies.items()
    }
    summaries = {name: summarize(results) for name, results in all_results.items()}

    (RESULTS_DIR / "policy_comparison.json").write_text(
        json.dumps({"summaries": summaries, "episodes": all_results}, indent=2),
        encoding="utf-8",
    )

    save_bar(
        RESULTS_DIR / "reward_by_policy.png",
        "Average Reward: Naive vs Guarded",
        "Average episode reward",
        {name: float(summary["avg_reward"]) for name, summary in summaries.items()},
    )
    save_bar(
        RESULTS_DIR / "leakage_by_policy.png",
        "Secret Leakage Rate",
        "Leakage rate",
        {name: float(summary["leakage_rate"]) for name, summary in summaries.items()},
    )
    save_bar(
        RESULTS_DIR / "contamination_by_policy.png",
        "Average Contamination Depth",
        "Contamination graph depth",
        {
            name: float(summary["avg_contamination_depth"])
            for name, summary in summaries.items()
        },
    )

    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
