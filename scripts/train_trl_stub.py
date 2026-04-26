"""Minimal training-entry sketch for the hackathon notebook.

This file intentionally avoids heavyweight downloads. During the onsite phase,
replace the `policy` function with a TRL/Unsloth model policy that maps
observations to `ContextBreachAction` JSON and uses `obs.reward` as the reward.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.evaluate_baseline import guarded_policy, run_episode, summarize


def main() -> None:
    results = [run_episode(guarded_policy, seed=i) for i in range(12)]
    print("Training stub smoke test. Replace guarded_policy with TRL/Unsloth policy.")
    print(summarize(results))


if __name__ == "__main__":
    main()
