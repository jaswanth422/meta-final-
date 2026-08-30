from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from context_breach_env.product import GuardDecision, RiskLevel, guard_tool_call, scan_text


SourceTrust = Literal["external", "internal-unverified", "internal-verified", "system"]


@dataclass(frozen=True)
class AgentMessage:
    """A framework-neutral message moving between agents or from an outside artifact."""

    source_agent: str
    target_agent: str
    content: str
    source_trust: SourceTrust = "internal-unverified"
    artifact_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolCall:
    """A proposed tool call from an agent before the application executes it."""

    agent: str
    action: str
    payload: dict[str, Any]
    source_risk: RiskLevel = "low"
    verified: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RuntimeDecision:
    decision: GuardDecision
    risk_level: RiskLevel
    risk_score: int
    attack_types: list[str]
    reasons: list[str]
    recommended_next_step: str
    audit_event: dict[str, Any]

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    @property
    def blocked(self) -> bool:
        return self.decision == "block"

    @property
    def needs_review(self) -> bool:
        return self.decision == "escalate"


class AgentWorkflowGuard:
    """Guard real multi-agent workflows at message, handoff, and tool boundaries."""

    def inspect_message(self, message: AgentMessage) -> dict[str, Any]:
        source = _message_source(message)
        scan = scan_text(message.content, source=source)
        return {
            **scan,
            "source_agent": message.source_agent,
            "target_agent": message.target_agent,
            "source_trust": message.source_trust,
            "artifact_id": message.artifact_id,
        }

    def guard_handoff(self, message: AgentMessage) -> RuntimeDecision:
        scan = self.inspect_message(message)
        reasons = _handoff_reasons(message, scan["risk_level"])
        decision = _handoff_decision(message, scan["risk_level"], reasons)
        return RuntimeDecision(
            decision=decision,
            risk_level=scan["risk_level"],
            risk_score=scan["risk_score"],
            attack_types=list(scan["attack_types"]),
            reasons=reasons,
            recommended_next_step=_handoff_next_step(decision),
            audit_event={
                "event_type": "agent_handoff",
                "source_agent": message.source_agent,
                "target_agent": message.target_agent,
                "source_trust": message.source_trust,
                "artifact_id": message.artifact_id,
                "decision": decision,
                "scan": scan,
                "metadata": message.metadata,
            },
        )

    def guard_tool_execution(self, tool_call: ToolCall) -> RuntimeDecision:
        guard = guard_tool_call(
            action=tool_call.action,
            payload=tool_call.payload,
            source_risk=tool_call.source_risk,
            verified=tool_call.verified,
        )
        return RuntimeDecision(
            decision=guard["decision"],
            risk_level=tool_call.source_risk,
            risk_score=guard["payload_risk_score"],
            attack_types=[],
            reasons=list(guard["reasons"]),
            recommended_next_step=guard["recommended_next_step"],
            audit_event={
                "event_type": "tool_call",
                "agent": tool_call.agent,
                "action": tool_call.action,
                "decision": guard["decision"],
                "source_risk": tool_call.source_risk,
                "verified": tool_call.verified,
                "payload": tool_call.payload,
                "metadata": tool_call.metadata,
            },
        )

    def audit_workflow(
        self,
        *,
        messages: list[AgentMessage],
        tool_calls: list[ToolCall] | None = None,
    ) -> dict[str, Any]:
        handoff_events = [self.guard_handoff(message).audit_event for message in messages]
        tool_events = [
            self.guard_tool_execution(tool_call).audit_event
            for tool_call in (tool_calls or [])
        ]
        decisions = handoff_events + tool_events
        return {
            "events": decisions,
            "blocked_count": _count_decisions(decisions, "block"),
            "escalation_count": _count_decisions(decisions, "escalate"),
            "allowed_count": _count_decisions(decisions, "allow"),
            "highest_risk": _highest_risk(handoff_events),
            "recommended_response": _workflow_response(decisions),
        }


def _message_source(message: AgentMessage) -> str:
    artifact = message.artifact_id or "message"
    return f"{message.source_agent}->{message.target_agent}:{artifact}"


def _handoff_reasons(message: AgentMessage, risk_level: RiskLevel) -> list[str]:
    reasons: list[str] = []
    if risk_level == "high":
        reasons.append("message contains high-risk prompt-injection signals")
    elif risk_level == "medium":
        reasons.append("message contains suspicious instructions that need review")
    if message.source_trust == "external":
        reasons.append("external content must not become trusted agent instructions")
    if message.source_trust == "internal-unverified" and risk_level != "low":
        reasons.append("unverified internal summary may propagate contamination")
    return reasons


def _handoff_decision(
    message: AgentMessage,
    risk_level: RiskLevel,
    reasons: list[str],
) -> GuardDecision:
    if not reasons:
        return "allow"
    if risk_level == "high" and message.source_trust in {"external", "internal-unverified"}:
        if message.target_agent.lower() in {"oversight", "security", "verifier"}:
            return "escalate"
        return "block"
    return "escalate"


def _handoff_next_step(decision: GuardDecision) -> str:
    if decision == "allow":
        return "Forward the message and record the handoff in the audit trail."
    if decision == "block":
        return "Stop the handoff, quarantine the source, and request a clean evidence summary."
    return "Route to verifier or oversight before another agent acts on the content."


def _count_decisions(events: list[dict[str, Any]], decision: GuardDecision) -> int:
    return sum(1 for event in events if event.get("decision") == decision)


def _highest_risk(events: list[dict[str, Any]]) -> RiskLevel:
    order: dict[RiskLevel, int] = {"low": 0, "medium": 1, "high": 2}
    highest: RiskLevel = "low"
    for event in events:
        risk = event.get("scan", {}).get("risk_level", "low")
        if risk in order and order[risk] > order[highest]:
            highest = risk
    return highest


def _workflow_response(events: list[dict[str, Any]]) -> str:
    if _count_decisions(events, "block"):
        return "Containment required: block unsafe boundaries before continuing the workflow."
    if _count_decisions(events, "escalate"):
        return "Human or verifier review required before execution."
    return "Workflow can continue with audit logging enabled."
