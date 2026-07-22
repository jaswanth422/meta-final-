from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from threading import Lock


LATENCY_BUCKETS_SECONDS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)


def gateway_logger() -> logging.Logger:
    """Return a logger that reliably emits only the structured message."""

    logger = logging.getLogger("context_breach.gateway")
    logger.setLevel(logging.INFO)
    logger.disabled = False
    if not any(getattr(handler, "_context_breach_gateway", False) for handler in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        handler._context_breach_gateway = True  # type: ignore[attr-defined]
        logger.addHandler(handler)
    logger.propagate = False
    return logger


class GatewayMetrics:
    """Thread-safe, bounded-cardinality gateway metrics registry."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._requests: Counter[tuple[str, str, int]] = Counter()
        self._decisions: Counter[tuple[str, str]] = Counter()
        self._authentication_failures: Counter[tuple[str, str]] = Counter()
        self._state_failures: Counter[str] = Counter()
        self._latency_buckets: Counter[tuple[str, float]] = Counter()
        self._latency_count: Counter[str] = Counter()
        self._latency_sum: defaultdict[str, float] = defaultdict(float)

    def record_request(
        self,
        *,
        method: str,
        route: str,
        status_code: int,
        duration_seconds: float,
    ) -> None:
        operation = operation_name(route)
        normalized_method = method.upper() if method.upper() in {"GET", "POST"} else "OTHER"
        normalized_status = status_code if 100 <= status_code <= 599 else 500
        duration = max(0.0, duration_seconds)
        with self._lock:
            self._requests[(normalized_method, operation, normalized_status)] += 1
            self._latency_count[operation] += 1
            self._latency_sum[operation] += duration
            for boundary in LATENCY_BUCKETS_SECONDS:
                if duration <= boundary:
                    self._latency_buckets[(operation, boundary)] += 1

    def record_decision(self, *, decision: str, reason: str) -> None:
        with self._lock:
            self._decisions[(_safe_decision(decision), _safe_reason(reason))] += 1

    def record_authentication_failure(self, *, operation: str, reason: str) -> None:
        with self._lock:
            self._authentication_failures[(operation_name(operation), _safe_reason(reason))] += 1

    def record_state_failure(self, *, operation: str) -> None:
        with self._lock:
            self._state_failures[operation_name(operation)] += 1

    def render_prometheus(self) -> str:
        with self._lock:
            requests = self._requests.copy()
            decisions = self._decisions.copy()
            authentication_failures = self._authentication_failures.copy()
            state_failures = self._state_failures.copy()
            latency_buckets = self._latency_buckets.copy()
            latency_count = self._latency_count.copy()
            latency_sum = dict(self._latency_sum)

        lines = [
            "# HELP context_breach_gateway_requests_total HTTP requests handled by the gateway.",
            "# TYPE context_breach_gateway_requests_total counter",
        ]
        for (method, operation, status), value in sorted(requests.items()):
            lines.append(
                "context_breach_gateway_requests_total"
                f'{{method="{method}",operation="{operation}",status="{status}"}} {value}'
            )

        lines.extend(
            (
                "# HELP context_breach_authorization_decisions_total Authorization policy decisions.",
                "# TYPE context_breach_authorization_decisions_total counter",
            )
        )
        for (decision, reason), value in sorted(decisions.items()):
            lines.append(
                "context_breach_authorization_decisions_total"
                f'{{decision="{decision}",reason="{reason}"}} {value}'
            )

        lines.extend(
            (
                "# HELP context_breach_authentication_failures_total Rejected authentication attempts.",
                "# TYPE context_breach_authentication_failures_total counter",
            )
        )
        for (operation, reason), value in sorted(authentication_failures.items()):
            lines.append(
                "context_breach_authentication_failures_total"
                f'{{operation="{operation}",reason="{reason}"}} {value}'
            )

        lines.extend(
            (
                "# HELP context_breach_gateway_state_failures_total Durable state operation failures.",
                "# TYPE context_breach_gateway_state_failures_total counter",
            )
        )
        for operation, value in sorted(state_failures.items()):
            lines.append(
                f'context_breach_gateway_state_failures_total{{operation="{operation}"}} {value}'
            )

        lines.extend(
            (
                "# HELP context_breach_gateway_request_duration_seconds Gateway request latency.",
                "# TYPE context_breach_gateway_request_duration_seconds histogram",
            )
        )
        for operation in sorted(latency_count):
            for boundary in LATENCY_BUCKETS_SECONDS:
                value = latency_buckets[(operation, boundary)]
                lines.append(
                    "context_breach_gateway_request_duration_seconds_bucket"
                    f'{{operation="{operation}",le="{boundary:g}"}} {value}'
                )
            count = latency_count[operation]
            lines.append(
                "context_breach_gateway_request_duration_seconds_bucket"
                f'{{operation="{operation}",le="+Inf"}} {count}'
            )
            lines.append(
                "context_breach_gateway_request_duration_seconds_sum"
                f'{{operation="{operation}"}} {latency_sum[operation]:.9f}'
            )
            lines.append(
                "context_breach_gateway_request_duration_seconds_count"
                f'{{operation="{operation}"}} {count}'
            )
        return "\n".join(lines) + "\n"


def structured_log(logger: logging.Logger, level: int, event: str, **fields: object) -> None:
    payload = {"event": event, **fields}
    logger.log(level, json.dumps(payload, sort_keys=True, separators=(",", ":")))


def operation_name(route: str) -> str:
    known = {
        "/health": "health",
        "/metrics": "metrics",
        "/v1/authorize": "authorize",
        "/v1/audit/{audit_id}": "audit",
        "authorize": "authorize",
        "audit": "audit",
        "health": "health",
        "metrics": "metrics",
    }
    return known.get(route, "unmatched")


def _safe_decision(decision: str) -> str:
    return decision if decision in {"permit", "deny", "require_review"} else "unknown"


def _safe_reason(reason: str) -> str:
    allowed = {
        "artifact_provenance_unknown",
        "artifact_requires_review",
        "authentication_required",
        "contaminated_artifact_flow",
        "credential_expired",
        "credential_identity_mismatch",
        "credential_lifetime_too_long",
        "credential_not_yet_valid",
        "credential_replayed",
        "gateway_state_unavailable",
        "high_risk_tool_requires_review",
        "identity_not_authorized",
        "invalid_artifact_signature",
        "invalid_credential_lifetime",
        "invalid_metrics_token",
        "invalid_request_signature",
        "malformed_authentication_headers",
        "metrics_authentication_required",
        "policy_permitted",
        "resource_not_authorized",
        "sensitive_data_exfiltration",
        "tool_not_authorized",
        "unknown_signing_key",
    }
    return reason if reason in allowed else "other"
