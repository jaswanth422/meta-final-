from __future__ import annotations

import os

from context_breach_env.production.enforcement import PolicyEngine, SchemaValidator
from context_breach_env.production.ingestion import IngestionGateway
from context_breach_env.production.models import (
    ArtifactEnvelope,
    AuditEvent,
    DecisionStatus,
    PolicyDecision,
    QuarantineEntry,
    RiskLevel,
    Severity,
    ToolCall,
    TrustTier,
)
from context_breach_env.production.security import HMACSigner
from context_breach_env.production.stores import AppendOnlyAuditStore, AppendOnlyQuarantineStore


def trust_tier_from_zone(trust_zone: str) -> TrustTier:
    if trust_zone == "trusted_internal":
        return TrustTier.INTERNAL_VERIFIED
    if trust_zone.startswith("internal"):
        return TrustTier.INTERNAL_UNVERIFIED
    return TrustTier.EXTERNAL


class ProductionRuntime:
    """Composable production-security boundary around the research environment."""

    def __init__(self, secret: bytes | None = None) -> None:
        resolved_secret = secret or os.urandom(32)
        self.audit = AppendOnlyAuditStore()
        self.quarantine = AppendOnlyQuarantineStore()
        self.signer = HMACSigner(resolved_secret)
        self.ingestion = IngestionGateway(
            signer=self.signer,
            audit_store=self.audit,
            quarantine_store=self.quarantine,
        )
        self.validator = SchemaValidator()
        self.policy = PolicyEngine()
        self.artifacts: dict[str, ArtifactEnvelope] = {}

    def ingest_artifact(
        self,
        *,
        episode_id: str,
        artifact_id: str,
        source: str,
        content: str,
        trust_zone: str,
    ) -> ArtifactEnvelope:
        result = self.ingestion.ingest(
            episode_id=episode_id,
            artifact_id=artifact_id,
            source=source,
            content=content,
            trust_tier=trust_tier_from_zone(trust_zone),
        )
        self.artifacts[artifact_id] = result.envelope
        return result.envelope

    def authorize(self, *, episode_id: str, call: ToolCall) -> PolicyDecision:
        schema = self.validator.validate(call)
        if not schema.permitted:
            return self._reject(episode_id, call, schema)

        envelope = self.artifacts.get(call.target or "")
        if envelope is not None and not self.signer.verify(envelope):
            return self._reject(
                episode_id,
                call,
                PolicyDecision(status=DecisionStatus.DENY, reason="invalid_artifact_signature"),
            )
        if (
            envelope is not None
            and envelope.risk_level == RiskLevel.HIGH
            and call.action_type not in {"inspect_artifact", "quarantine_source", "escalate_oversight"}
        ):
            return self._reject(
                episode_id,
                call,
                PolicyDecision(status=DecisionStatus.DENY, reason="high_risk_artifact_quarantined"),
            )
        tier = envelope.trust_tier if envelope is not None else TrustTier.INTERNAL_VERIFIED
        policy = self.policy.check(call, tier)
        if policy.status != DecisionStatus.PERMIT:
            return self._reject(episode_id, call, policy)

        self.audit.append(
            AuditEvent(
                episode_id=episode_id,
                event_type="tool_call",
                actor="commander",
                outcome="permitted",
                artifact_id=call.target,
                details={"action_type": call.action_type},
            )
        )
        return policy

    def _reject(self, episode_id: str, call: ToolCall, decision: PolicyDecision) -> PolicyDecision:
        severity = Severity.HIGH if decision.reason in {"invalid_artifact_signature", "trust_tier_violation"} else Severity.MEDIUM
        self.quarantine.append(
            QuarantineEntry(
                episode_id=episode_id,
                artifact_id=call.target,
                severity=severity,
                reason=decision.reason,
                payload=call.model_dump(),
            )
        )
        self.audit.append(
            AuditEvent(
                episode_id=episode_id,
                event_type="tool_call",
                actor="commander",
                outcome=decision.status.value,
                artifact_id=call.target,
                details={"action_type": call.action_type, "reason": decision.reason},
            )
        )
        return decision
