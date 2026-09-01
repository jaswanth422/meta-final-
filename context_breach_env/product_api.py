from __future__ import annotations

from typing import Any, Literal

from fastapi import FastAPI
from pydantic import BaseModel, Field

from context_breach_env.integrations import AgentMessage, AgentWorkflowGuard, ToolCall
from context_breach_env.product import build_audit_report, guard_tool_call, scan_text
from context_breach_env.prototype import POLICIES, run_episode
from context_breach_env.scenarios import SCENARIOS


class ScanRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Ticket, log, email, document, or tool output.")
    source: str = Field(default="api_artifact", description="Human-readable source label.")


class GuardRequest(BaseModel):
    action: str = Field(..., description="Proposed tool or workflow action.")
    payload: dict[str, Any] = Field(default_factory=dict, description="Proposed action payload.")
    source_risk: Literal["low", "medium", "high"] = Field(default="low")
    verified: bool = Field(default=False, description="Whether a verifier approved the action.")


class AuditRequest(BaseModel):
    artifact_text: str = Field(..., min_length=1)
    action: str = Field(default="finalize_response")
    payload: dict[str, Any] = Field(default_factory=dict)
    verified: bool = False


class HandoffRequest(BaseModel):
    source_agent: str
    target_agent: str
    content: str = Field(..., min_length=1)
    source_trust: Literal["external", "internal-unverified", "internal-verified", "system"] = (
        "internal-unverified"
    )
    artifact_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class WorkflowToolCallRequest(BaseModel):
    agent: str
    action: str
    payload: dict[str, Any] = Field(default_factory=dict)
    source_risk: Literal["low", "medium", "high"] = "low"
    verified: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class WorkflowAuditRequest(BaseModel):
    messages: list[HandoffRequest]
    tool_calls: list[WorkflowToolCallRequest] = Field(default_factory=list)


class SimulateRequest(BaseModel):
    policy: Literal["naive", "guarded"] = "guarded"
    scenario_id: str | None = None
    seed: int = 0


app = FastAPI(
    title="Context Breach Product API",
    description=(
        "Runtime security API for AI agent workflows: scan prompt-injection risk, "
        "guard tool calls, simulate containment, and generate audit reports."
    ),
    version="0.1.0",
)


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "context-breach-product-api",
        "policies": list(POLICIES),
        "scenarios": [scenario.id for scenario in SCENARIOS],
    }


@app.post("/scan")
def scan(request: ScanRequest) -> dict[str, Any]:
    return scan_text(request.text, source=request.source)


@app.post("/guard-tool-call")
def guard(request: GuardRequest) -> dict[str, Any]:
    return guard_tool_call(
        action=request.action,
        payload=request.payload,
        source_risk=request.source_risk,
        verified=request.verified,
    )


@app.post("/audit-report")
def audit_report(request: AuditRequest) -> dict[str, Any]:
    return build_audit_report(
        artifact_text=request.artifact_text,
        action=request.action,
        payload=request.payload,
        verified=request.verified,
    )


@app.post("/guard-handoff")
def guard_handoff(request: HandoffRequest) -> dict[str, Any]:
    runtime_guard = AgentWorkflowGuard()
    decision = runtime_guard.guard_handoff(
        AgentMessage(
            source_agent=request.source_agent,
            target_agent=request.target_agent,
            content=request.content,
            source_trust=request.source_trust,
            artifact_id=request.artifact_id,
            metadata=request.metadata,
        )
    )
    return {
        "decision": decision.decision,
        "risk_level": decision.risk_level,
        "risk_score": decision.risk_score,
        "attack_types": decision.attack_types,
        "reasons": decision.reasons,
        "recommended_next_step": decision.recommended_next_step,
        "audit_event": decision.audit_event,
    }


@app.post("/workflow-audit")
def workflow_audit(request: WorkflowAuditRequest) -> dict[str, Any]:
    runtime_guard = AgentWorkflowGuard()
    messages = [
        AgentMessage(
            source_agent=message.source_agent,
            target_agent=message.target_agent,
            content=message.content,
            source_trust=message.source_trust,
            artifact_id=message.artifact_id,
            metadata=message.metadata,
        )
        for message in request.messages
    ]
    tool_calls = [
        ToolCall(
            agent=tool_call.agent,
            action=tool_call.action,
            payload=tool_call.payload,
            source_risk=tool_call.source_risk,
            verified=tool_call.verified,
            metadata=tool_call.metadata,
        )
        for tool_call in request.tool_calls
    ]
    return runtime_guard.audit_workflow(messages=messages, tool_calls=tool_calls)


@app.post("/simulate")
def simulate(request: SimulateRequest) -> dict[str, Any]:
    return run_episode(
        request.policy,
        seed=request.seed,
        scenario_id=request.scenario_id,
    )
