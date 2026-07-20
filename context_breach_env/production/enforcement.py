from __future__ import annotations

from context_breach_env.production.models import (
    DecisionStatus,
    PolicyDecision,
    ToolCall,
    TrustTier,
)


TARGET_REQUIRED = {
    "inspect_artifact",
    "delegate_researcher",
    "request_clean_summary",
    "quarantine_source",
}
KNOWN_ACTIONS = TARGET_REQUIRED | {
    "ask_verifier",
    "finalize_response",
    "escalate_oversight",
    "noop",
}
HIGH_STAKES_ACTIONS = {"finalize_response"}


class SchemaValidator:
    """Strict validation independent of the model that produced a tool call."""

    def validate(self, call: ToolCall) -> PolicyDecision:
        if call.action_type not in KNOWN_ACTIONS:
            return PolicyDecision(status=DecisionStatus.DENY, reason="unknown_action")
        if call.action_type in TARGET_REQUIRED and not call.target:
            return PolicyDecision(status=DecisionStatus.DENY, reason="missing_target")
        if call.action_type == "ask_verifier":
            if not isinstance(call.payload.get("decision"), str) or not isinstance(call.payload.get("response"), str):
                return PolicyDecision(status=DecisionStatus.DENY, reason="invalid_verifier_payload")
        if call.action_type == "finalize_response":
            allowed = {"decision", "response", "include_sensitive"}
            if set(call.payload) - allowed:
                return PolicyDecision(status=DecisionStatus.DENY, reason="unexpected_finalize_field")
            if not isinstance(call.payload.get("decision"), str) or not isinstance(call.payload.get("response"), str):
                return PolicyDecision(status=DecisionStatus.DENY, reason="invalid_finalize_payload")
            include_sensitive = call.payload.get("include_sensitive", False)
            if not isinstance(include_sensitive, bool):
                return PolicyDecision(status=DecisionStatus.DENY, reason="invalid_include_sensitive")
        return PolicyDecision(status=DecisionStatus.PERMIT, reason="schema_valid")


class PolicyEngine:
    """Trust-tier, idempotency, and high-stakes execution policy."""

    PERMISSIONS = {
        TrustTier.EXTERNAL: {
            "inspect_artifact",
            "request_clean_summary",
            "quarantine_source",
            "escalate_oversight",
        },
        TrustTier.INTERNAL_UNVERIFIED: {
            "inspect_artifact",
            "request_clean_summary",
            "quarantine_source",
            "ask_verifier",
            "escalate_oversight",
        },
        TrustTier.INTERNAL_VERIFIED: KNOWN_ACTIONS,
    }

    def __init__(self) -> None:
        self._idempotency_keys: set[str] = set()

    def check(self, call: ToolCall, trust_tier: TrustTier = TrustTier.INTERNAL_VERIFIED) -> PolicyDecision:
        if call.action_type not in self.PERMISSIONS[trust_tier]:
            return PolicyDecision(status=DecisionStatus.DENY, reason="trust_tier_violation")
        if call.idempotency_key:
            if call.idempotency_key in self._idempotency_keys:
                return PolicyDecision(status=DecisionStatus.DENY, reason="duplicate_operation")
        if call.action_type in HIGH_STAKES_ACTIONS and not call.dry_run_passed:
            return PolicyDecision(status=DecisionStatus.REQUIRE_DRY_RUN, reason="high_stakes_dry_run_required")
        if call.idempotency_key:
            self._idempotency_keys.add(call.idempotency_key)
        return PolicyDecision(status=DecisionStatus.PERMIT, reason="policy_permitted")
