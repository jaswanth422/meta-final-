from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from context_breach_env.product import build_audit_report, guard_tool_call, scan_text


class UnsafeAgentAction(RuntimeError):
    """Raised when Context Breach blocks an unsafe agent action."""


@dataclass(frozen=True)
class GuardResult:
    decision: str
    risk_level: str
    risk_score: int
    attack_types: list[str]
    reasons: list[str]
    recommended_next_step: str
    audit_report: dict[str, Any]

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    @property
    def blocked(self) -> bool:
        return self.decision == "block"

    @property
    def needs_review(self) -> bool:
        return self.decision == "escalate"


class ContextBreachGuard:
    """Small in-process SDK wrapper for agent apps and prototypes."""

    def scan(self, text: str, *, source: str = "artifact") -> dict[str, Any]:
        return scan_text(text, source=source)

    def check_action(
        self,
        *,
        artifact_text: str,
        action: str,
        payload: dict[str, Any],
        verified: bool = False,
    ) -> GuardResult:
        scan = self.scan(artifact_text)
        guard = guard_tool_call(
            action=action,
            payload=payload,
            source_risk=scan["risk_level"],
            verified=verified,
        )
        audit = build_audit_report(
            artifact_text=artifact_text,
            action=action,
            payload=payload,
            verified=verified,
        )
        return GuardResult(
            decision=guard["decision"],
            risk_level=scan["risk_level"],
            risk_score=scan["risk_score"],
            attack_types=list(scan["attack_types"]),
            reasons=list(guard["reasons"]),
            recommended_next_step=guard["recommended_next_step"],
            audit_report=audit,
        )

    def enforce(
        self,
        *,
        artifact_text: str,
        action: str,
        payload: dict[str, Any],
        verified: bool = False,
    ) -> GuardResult:
        result = self.check_action(
            artifact_text=artifact_text,
            action=action,
            payload=payload,
            verified=verified,
        )
        if result.blocked:
            raise UnsafeAgentAction(result.recommended_next_step)
        return result
