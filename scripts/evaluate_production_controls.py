from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from context_breach_env.models import ContextBreachAction
from context_breach_env.production import ProductionContextBreachEnvironment


def main() -> None:
    env = ProductionContextBreachEnvironment()
    initial = env.reset(scenario_id="support_refund_direct")

    blocked = env.step(
        ContextBreachAction(
            action_type="delegate_researcher",
            target="ticket:T-1842",
        )
    )
    inspected = env.step(
        ContextBreachAction(
            action_type="inspect_artifact",
            target="ticket:T-1842",
        )
    )
    quarantined = env.step(
        ContextBreachAction(
            action_type="quarantine_source",
            target="ticket:T-1842",
        )
    )

    output = {
        "scenario": initial.metadata["scenario_id"],
        "blocked_external_delegation": blocked.status,
        "inspection": inspected.status,
        "quarantine": quarantined.status,
        "audit_events": [event.model_dump(mode="json") for event in env.production.audit.events()],
        "quarantine_entries": [
            entry.model_dump(mode="json") for entry in env.production.quarantine.entries()
        ],
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
