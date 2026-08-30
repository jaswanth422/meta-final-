from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class TrustTier(str, Enum):
    EXTERNAL = "external"
    INTERNAL_UNVERIFIED = "internal-unverified"
    INTERNAL_VERIFIED = "internal-verified"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ArtifactEnvelope(BaseModel):
    """Signed metadata envelope carried with an artifact through the system."""

    artifact_id: str
    source: str
    content: str
    trust_tier: TrustTier
    risk_score: float = Field(ge=0.0, le=1.0)
    risk_level: RiskLevel
    content_hash: str
    origin_agent: str = "ingestion-gateway"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    key_id: str = "local-hmac-v1"
    signature: str = ""

    def signing_payload(self) -> bytes:
        fields = (
            self.artifact_id,
            self.source,
            self.content_hash,
            self.trust_tier.value,
            f"{self.risk_score:.6f}",
            self.risk_level.value,
            self.origin_agent,
            self.created_at.isoformat(),
            self.key_id,
        )
        return "\x1f".join(fields).encode("utf-8")


class ScanFinding(BaseModel):
    detector: str
    score: float = Field(ge=0.0, le=1.0)
    matches: list[str] = Field(default_factory=list)


class IngestionResult(BaseModel):
    accepted: bool
    envelope: ArtifactEnvelope
    findings: list[ScanFinding] = Field(default_factory=list)
    reason: str | None = None


class ToolCall(BaseModel):
    action_type: str
    target: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = None
    dry_run_passed: bool = False


class DecisionStatus(str, Enum):
    PERMIT = "permit"
    DENY = "deny"
    REQUIRE_DRY_RUN = "require_dry_run"


class PolicyDecision(BaseModel):
    status: DecisionStatus
    reason: str

    @property
    def permitted(self) -> bool:
        return self.status == DecisionStatus.PERMIT


class AuditEvent(BaseModel):
    episode_id: str
    event_type: str
    actor: str
    outcome: str
    artifact_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class QuarantineEntry(BaseModel):
    episode_id: str
    artifact_id: str | None = None
    severity: Severity
    reason: str
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


MetricName = Literal[
    "leakage_rate",
    "contamination_depth",
    "overblock_rate",
    "task_success_rate",
    "escalation_accuracy",
]


class EpisodeMetrics(BaseModel):
    leakage_count: int = Field(default=0, ge=0)
    leakage_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    contamination_depth: float = Field(default=0.0, ge=0.0)
    overblock_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    task_success_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    escalation_accuracy: float = Field(default=0.0, ge=0.0, le=1.0)
