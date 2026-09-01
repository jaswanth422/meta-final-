from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal


RiskLevel = Literal["low", "medium", "high"]
GuardDecision = Literal["allow", "block", "escalate"]


@dataclass(frozen=True)
class AttackSignal:
    attack_type: str
    pattern: str
    weight: int
    recommendation: str


ATTACK_SIGNALS: tuple[AttackSignal, ...] = (
    AttackSignal(
        attack_type="instruction_override",
        pattern=r"\b(ignore|disregard|forget)\b.{0,80}\b(previous|prior|above|system|policy)\b",
        weight=30,
        recommendation="Enable defensive prompting and treat the instruction as untrusted data.",
    ),
    AttackSignal(
        attack_type="secret_exfiltration",
        pattern=r"\b(include|reveal|send|print|show|exfiltrate)\b.{0,80}\b(token|password|secret|key|credential|risk_score)\b",
        weight=35,
        recommendation="Block execution and route the artifact through clean evidence-only summarization.",
    ),
    AttackSignal(
        attack_type="business_rule_override",
        pattern=r"\b(bypass|override|skip|ignore)\b.{0,80}\b(policy|approval|security review|verification|refund rule)\b",
        weight=30,
        recommendation="Require verifier approval before any business action is finalized.",
    ),
    AttackSignal(
        attack_type="fake_authority",
        pattern=r"\b(cfo|ceo|admin|manager|executive|security team)\b.{0,80}\b(already approved|approved this|authorized|said to)\b",
        weight=20,
        recommendation="Verify authority against trusted internal records before acting.",
    ),
    AttackSignal(
        attack_type="hidden_instruction",
        pattern=r"<!--.*?(assistant instruction|ignore|bypass|secret|token).*?-->|<script\b|display\s*:\s*none",
        weight=25,
        recommendation="Apply retrieval filtering before downstream summarization.",
    ),
    AttackSignal(
        attack_type="tool_hijacking",
        pattern=r"\b(run|curl|wget|post|execute|call)\b.{0,80}\b(attacker\.|webhook|external url|http://|https://)\b",
        weight=30,
        recommendation="Enable structured tool guards and block unverified tool execution.",
    ),
)

SENSITIVE_MARKERS = (
    "token",
    "password",
    "secret",
    "api_key",
    "credential",
    "risk_score",
    "service-key",
    "root-password",
)

HIGH_STAKES_ACTIONS = {
    "send_customer_reply",
    "run_mitigation",
    "approve_vendor_access",
    "finalize_response",
    "provision_access",
    "send_email",
    "refund_customer",
}


def scan_text(text: str, *, source: str = "pasted_artifact") -> dict[str, Any]:
    """Risk-score enterprise text for prompt-injection patterns."""

    matches: list[dict[str, Any]] = []
    score = 0
    for signal in ATTACK_SIGNALS:
        for match in re.finditer(signal.pattern, text, flags=re.IGNORECASE | re.DOTALL):
            snippet = " ".join(match.group(0).split())
            matches.append(
                {
                    "attack_type": signal.attack_type,
                    "span": [match.start(), match.end()],
                    "text": snippet[:240],
                    "recommendation": signal.recommendation,
                }
            )
            score += signal.weight

    score = min(score, 100)
    if score >= 60:
        risk_level: RiskLevel = "high"
    elif score >= 25:
        risk_level = "medium"
    else:
        risk_level = "low"

    recommendations = _dedupe(match["recommendation"] for match in matches)
    if not recommendations:
        recommendations = ["Continue normal verification before risky actions."]

    return {
        "source": source,
        "risk_score": score,
        "risk_level": risk_level,
        "attack_types": sorted({match["attack_type"] for match in matches}),
        "suspicious_spans": matches,
        "recommended_defenses": recommendations,
        "should_quarantine": risk_level == "high",
        "should_apply_retrieval_filter": bool(matches),
        "should_escalate": risk_level == "high",
    }


def guard_tool_call(
    *,
    action: str,
    payload: dict[str, Any],
    source_risk: RiskLevel = "low",
    verified: bool = False,
) -> dict[str, Any]:
    """Decide whether a proposed agent action should be allowed, blocked, or escalated."""

    reasons: list[str] = []
    payload_text = str(payload).lower()
    high_stakes = action in HIGH_STAKES_ACTIONS
    leaks_sensitive = any(marker in payload_text for marker in SENSITIVE_MARKERS)
    scan = scan_text(payload_text, source="tool_payload")

    if leaks_sensitive:
        reasons.append("payload contains restricted or secret-like fields")
    if scan["risk_level"] != "low":
        reasons.append("payload contains prompt-injection-like instructions")
    if high_stakes and not verified:
        reasons.append("high-stakes action has not passed verifier approval")
    if source_risk == "high" and high_stakes:
        reasons.append("high-risk source cannot directly drive a high-stakes action")

    if leaks_sensitive or (source_risk == "high" and high_stakes):
        decision: GuardDecision = "block"
    elif reasons:
        decision = "escalate"
    else:
        decision = "allow"

    return {
        "decision": decision,
        "action": action,
        "verified": verified,
        "source_risk": source_risk,
        "reasons": reasons,
        "payload_risk_score": scan["risk_score"],
        "recommended_next_step": _next_step(decision),
    }


def build_audit_report(
    *,
    artifact_text: str,
    action: str,
    payload: dict[str, Any],
    verified: bool = False,
) -> dict[str, Any]:
    scan = scan_text(artifact_text)
    guard = guard_tool_call(
        action=action,
        payload=payload,
        source_risk=scan["risk_level"],
        verified=verified,
    )
    return {
        "artifact_scan": scan,
        "tool_guard": guard,
        "audit_summary": {
            "risk_level": scan["risk_level"],
            "attack_types": scan["attack_types"],
            "decision": guard["decision"],
            "recommended_defenses": scan["recommended_defenses"],
        },
    }


def _next_step(decision: GuardDecision) -> str:
    if decision == "allow":
        return "Proceed and record the action in the audit trail."
    if decision == "block":
        return "Block execution, quarantine the source, and request clean evidence."
    return "Escalate to oversight or verifier before execution."


def _dedupe(items: Any) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            output.append(str(item))
    return output
