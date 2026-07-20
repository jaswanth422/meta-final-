from __future__ import annotations

import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from context_breach_env.production.models import (
    ArtifactEnvelope,
    AuditEvent,
    IngestionResult,
    QuarantineEntry,
    RiskLevel,
    Severity,
    TrustTier,
)
from context_breach_env.production.security import (
    HMACSigner,
    SemanticHeuristicScanner,
    StaticInjectionScanner,
    sha256_content,
)
from context_breach_env.production.stores import AppendOnlyAuditStore, AppendOnlyQuarantineStore


class IngestionGateway:
    def __init__(
        self,
        *,
        signer: HMACSigner,
        audit_store: AppendOnlyAuditStore,
        quarantine_store: AppendOnlyQuarantineStore,
        max_artifact_bytes: int = 524_288,
        rate_limit_per_source_per_minute: int = 60,
        dedup_window_seconds: int = 300,
    ) -> None:
        self.signer = signer
        self.audit_store = audit_store
        self.quarantine_store = quarantine_store
        self.max_artifact_bytes = max_artifact_bytes
        self.rate_limit = rate_limit_per_source_per_minute
        self.dedup_window_seconds = dedup_window_seconds
        self.static_scanner = StaticInjectionScanner()
        self.semantic_scanner = SemanticHeuristicScanner()
        self._source_events: dict[str, deque[float]] = defaultdict(deque)
        self._recent_hashes: dict[str, float] = {}

    def ingest(
        self,
        *,
        episode_id: str,
        artifact_id: str,
        source: str,
        content: str,
        trust_tier: TrustTier,
        now: float | None = None,
    ) -> IngestionResult:
        current = time.time() if now is None else now
        content_hash = sha256_content(content)
        preliminary = ArtifactEnvelope(
            artifact_id=artifact_id,
            source=source,
            content=content,
            trust_tier=trust_tier,
            risk_score=0.0,
            risk_level=RiskLevel.LOW,
            content_hash=content_hash,
            created_at=datetime.fromtimestamp(current, timezone.utc),
        )

        rejection = self._gateway_rejection(source, content, content_hash, current)
        if rejection is not None:
            envelope = self.signer.sign(preliminary.model_copy(update={"risk_score": 1.0, "risk_level": RiskLevel.HIGH}))
            return self._quarantine(episode_id, envelope, rejection, [])

        static = self.static_scanner.scan(content)
        semantic = self.semantic_scanner.scan(content)
        risk_score = round(0.4 * static.score + 0.6 * semantic.score, 4)
        risk_level = RiskLevel.HIGH if risk_score >= 0.80 else RiskLevel.MEDIUM if risk_score >= 0.50 else RiskLevel.LOW
        envelope = self.signer.sign(
            preliminary.model_copy(update={"risk_score": risk_score, "risk_level": risk_level})
        )
        findings = [static, semantic]
        self._recent_hashes[content_hash] = current

        if risk_level == RiskLevel.HIGH:
            return self._quarantine(episode_id, envelope, "high_ingestion_risk", findings)

        self.audit_store.append(
            AuditEvent(
                episode_id=episode_id,
                event_type="artifact_ingested",
                actor="ingestion-gateway",
                outcome="accepted",
                artifact_id=artifact_id,
                details={"risk_level": risk_level.value, "risk_score": risk_score},
            )
        )
        return IngestionResult(accepted=True, envelope=envelope, findings=findings)

    def _gateway_rejection(
        self,
        source: str,
        content: str,
        content_hash: str,
        current: float,
    ) -> str | None:
        if len(content.encode("utf-8")) > self.max_artifact_bytes:
            return "artifact_size_limit_exceeded"
        previous = self._recent_hashes.get(content_hash)
        if previous is not None and current - previous <= self.dedup_window_seconds:
            return "duplicate_artifact"
        events = self._source_events[source]
        while events and current - events[0] >= 60:
            events.popleft()
        if len(events) >= self.rate_limit:
            return "source_rate_limit_exceeded"
        events.append(current)
        return None

    def _quarantine(self, episode_id: str, envelope: ArtifactEnvelope, reason: str, findings: list) -> IngestionResult:
        self.quarantine_store.append(
            QuarantineEntry(
                episode_id=episode_id,
                artifact_id=envelope.artifact_id,
                severity=Severity.HIGH,
                reason=reason,
                payload={"risk_score": envelope.risk_score},
            )
        )
        self.audit_store.append(
            AuditEvent(
                episode_id=episode_id,
                event_type="artifact_ingested",
                actor="ingestion-gateway",
                outcome="quarantined",
                artifact_id=envelope.artifact_id,
                details={"reason": reason},
            )
        )
        return IngestionResult(accepted=False, envelope=envelope, findings=findings, reason=reason)
