from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.evaluate_baseline import guarded_policy, naive_policy, run_episode


def main() -> None:
    demo = {
        "before_training_naive": run_episode(naive_policy, seed=0),
        "after_training_guarded": run_episode(guarded_policy, seed=0),
    }
    print(json.dumps(demo, indent=2))


if __name__ == "__main__":
    main()
