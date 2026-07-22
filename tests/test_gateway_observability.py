from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from context_breach_env.gateway.app import create_app
from context_breach_env.gateway.auth import (
    HMACIdentityKey,
    HMACRequestAuthenticator,
    HMACRequestSigner,
)
from context_breach_env.gateway.models import (
    AuthorizationGrant,
    AuthorizationRequest,
)
from context_breach_env.gateway.observability import GatewayMetrics
from context_breach_env.gateway.service import AuthorizationService
from context_breach_env.gateway.stores import GatewayStateError


METRICS_TOKEN = "metrics-test-token-material-32-bytes-minimum"
KEY = HMACIdentityKey(
    key_id="observability-test-v1",
    secret=b"observability-test-secret-material-32-bytes",
    tenant_id="tenant-1",
    user_id="user-1",
    agent_id="research-agent",
)
GRANT = AuthorizationGrant(
    tenant_id="tenant-1",
    user_id="user-1",
    agent_id="research-agent",
    allowed_tools={"read_document"},
    resource_patterns=("documents/*",),
)


def _request(**updates: object) -> AuthorizationRequest:
    values: dict[str, object] = {
        "tenant_id": "tenant-1",
        "user_id": "user-1",
        "agent_id": "research-agent",
        "user_intent": "Read the quarterly report",
        "tool_name": "read_document",
        "resource": "documents/report.pdf",
        "arguments": {"page": 1},
        "artifact_ids": [],
    }
    values.update(updates)
    return AuthorizationRequest.model_validate(values)


def _gateway(*, nonce_store=None) -> tuple[TestClient, HMACRequestSigner]:
    service = AuthorizationService([GRANT])
    authenticator = HMACRequestAuthenticator([KEY], nonce_store=nonce_store)
    app = create_app(
        service,
        authenticator,
        metrics=GatewayMetrics(),
        metrics_token=METRICS_TOKEN,
    )
    return TestClient(app), HMACRequestSigner(KEY)


def _authorize(
    client: TestClient,
    signer: HMACRequestSigner,
    request: AuthorizationRequest,
):
    credentials = signer.sign_authorization(request)
    return client.post(
        "/v1/authorize",
        json=request.model_dump(mode="json"),
        headers=credentials.as_http_headers(),
    )


def _scrape(client: TestClient) -> str:
    response = client.get(
        "/metrics",
        headers={"Authorization": f"Bearer {METRICS_TOKEN}"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    return response.text


def test_metrics_endpoint_requires_a_dedicated_bearer_token() -> None:
    client, _ = _gateway()

    missing = client.get("/metrics")
    invalid = client.get("/metrics", headers={"Authorization": "Bearer wrong"})
    valid = _scrape(client)

    assert missing.status_code == 401
    assert missing.json()["detail"] == "metrics_authentication_required"
    assert invalid.status_code == 401
    assert invalid.json()["detail"] == "invalid_metrics_token"
    assert (
        'context_breach_authentication_failures_total{operation="metrics",'
        'reason="metrics_authentication_required"} 1'
    ) in valid
    assert (
        'context_breach_authentication_failures_total{operation="metrics",'
        'reason="invalid_metrics_token"} 1'
    ) in valid


def test_unconfigured_metrics_endpoint_fails_closed(
    monkeypatch,
) -> None:
    monkeypatch.delenv("CONTEXT_BREACH_METRICS_TOKEN", raising=False)
    service = AuthorizationService([GRANT])
    authenticator = HMACRequestAuthenticator([KEY])
    client = TestClient(create_app(service, authenticator))

    response = client.get("/metrics")

    assert response.status_code == 503
    assert response.json()["detail"] == "metrics_not_configured"


def test_metrics_report_decisions_authentication_failures_and_latency() -> None:
    client, signer = _gateway()
    permitted = _authorize(client, signer, _request())
    denied = _authorize(client, signer, _request(resource="private/payroll.csv"))

    original = _request()
    credentials = signer.sign_authorization(original)
    modified = original.model_copy(update={"user_intent": "Modified after signing"})
    rejected = client.post(
        "/v1/authorize",
        json=modified.model_dump(mode="json"),
        headers=credentials.as_http_headers(),
    )
    metrics = _scrape(client)

    assert permitted.status_code == 200
    assert denied.status_code == 200
    assert rejected.status_code == 401
    assert (
        'context_breach_authorization_decisions_total{decision="permit",'
        'reason="policy_permitted"} 1'
    ) in metrics
    assert (
        'context_breach_authorization_decisions_total{decision="deny",'
        'reason="resource_not_authorized"} 1'
    ) in metrics
    assert (
        'context_breach_authentication_failures_total{operation="authorize",'
        'reason="invalid_request_signature"} 1'
    ) in metrics
    assert (
        'context_breach_gateway_requests_total{method="POST",operation="authorize",status="200"} 2'
    ) in metrics
    assert (
        'context_breach_gateway_requests_total{method="POST",operation="authorize",status="401"} 1'
    ) in metrics
    assert 'context_breach_gateway_request_duration_seconds_bucket{operation="authorize"' in metrics
    assert 'context_breach_gateway_request_duration_seconds_count{operation="authorize"} 3' in metrics


def test_dependency_layer_authentication_failures_are_counted() -> None:
    client, _ = _gateway()
    response = client.post(
        "/v1/authorize",
        json=_request().model_dump(mode="json"),
    )
    metrics = _scrape(client)

    assert response.status_code == 401
    assert (
        'context_breach_authentication_failures_total{operation="authorize",'
        'reason="authentication_required"} 1'
    ) in metrics


class _FailingNonceStore:
    def consume_nonce(self, **_: object) -> bool:
        raise GatewayStateError("database location and credentials must not be exposed")


def test_state_failures_are_counted_without_exposing_exception_details() -> None:
    client, signer = _gateway(nonce_store=_FailingNonceStore())
    response = _authorize(client, signer, _request())
    metrics = _scrape(client)

    assert response.status_code == 503
    assert response.json()["detail"] == "gateway_state_unavailable"
    assert 'context_breach_gateway_state_failures_total{operation="authorize"} 1' in metrics
    assert "database location" not in metrics
    assert "credentials" not in metrics


class _CaptureHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def test_structured_request_log_excludes_request_and_identity_data() -> None:
    client, signer = _gateway()
    secret_intent = "Send confidential launch plans"
    secret_resource = "documents/acquisition-target.pdf"
    logger = logging.getLogger("context_breach.gateway")
    capture = _CaptureHandler()
    logger.addHandler(capture)
    try:
        response = _authorize(
            client,
            signer,
            _request(
                user_intent=secret_intent,
                resource=secret_resource,
                arguments={"authorization": "Bearer never-log-this"},
            ),
        )
    finally:
        logger.removeHandler(capture)

    assert len(capture.messages) == 1
    payload = json.loads(capture.messages[0])
    assert payload["event"] == "gateway_request"
    assert payload["operation"] == "authorize"
    assert payload["request_id"] == response.headers["X-Request-ID"]
    rendered = capture.messages[0]
    assert secret_intent not in rendered
    assert secret_resource not in rendered
    assert "never-log-this" not in rendered
    assert KEY.tenant_id not in rendered
    assert KEY.user_id not in rendered
    assert KEY.agent_id not in rendered


def test_dynamic_paths_and_unknown_labels_are_collapsed() -> None:
    metrics = GatewayMetrics()
    metrics.record_request(
        method="TRACE",
        route="/attacker-controlled/value",
        status_code=999,
        duration_seconds=-1,
    )
    metrics.record_decision(decision="attacker-decision", reason="attacker-reason")
    rendered = metrics.render_prometheus()

    assert "attacker-controlled" not in rendered
    assert "attacker-decision" not in rendered
    assert "attacker-reason" not in rendered
    assert 'method="OTHER",operation="unmatched",status="500"' in rendered
    assert 'decision="unknown",reason="other"' in rendered


def test_metric_updates_are_thread_safe() -> None:
    metrics = GatewayMetrics()

    def record(_: int) -> None:
        metrics.record_request(
            method="POST",
            route="/v1/authorize",
            status_code=200,
            duration_seconds=0.01,
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(record, range(500)))

    rendered = metrics.render_prometheus()
    assert (
        'context_breach_gateway_requests_total{method="POST",operation="authorize",status="200"} 500'
    ) in rendered
    assert 'context_breach_gateway_request_duration_seconds_count{operation="authorize"} 500' in rendered
