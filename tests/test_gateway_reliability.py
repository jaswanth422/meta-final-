from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from context_breach_env.gateway.app import create_app
from context_breach_env.gateway.auth import (
    HMACIdentityKey,
    HMACRequestAuthenticator,
    HMACRequestSigner,
)
from context_breach_env.gateway.loadtest import (
    LoadSample,
    bounded_error_category,
    evaluate_thresholds,
    run_concurrent_load,
    summarize_load,
)
from context_breach_env.gateway.models import AuthorizationGrant, AuthorizationRequest
from context_breach_env.gateway.observability import GatewayMetrics
from context_breach_env.gateway.service import AuthorizationService
from context_breach_env.gateway.stores import SQLiteGatewayStateStore


METRICS_TOKEN = "reliability-metrics-token-material-32-bytes"
KEYS = (
    HMACIdentityKey(
        key_id="reliability-key-a",
        secret=b"reliability-key-a-secret-material-32-bytes",
        tenant_id="tenant-a",
        user_id="user-a",
        agent_id="agent-a",
    ),
    HMACIdentityKey(
        key_id="reliability-key-b",
        secret=b"reliability-key-b-secret-material-32-bytes",
        tenant_id="tenant-b",
        user_id="user-b",
        agent_id="agent-b",
    ),
)
GRANTS = [
    AuthorizationGrant(
        tenant_id=key.tenant_id,
        user_id=key.user_id,
        agent_id=key.agent_id,
        allowed_tools={"read_document"},
        resource_patterns=(f"documents/{key.tenant_id}/*",),
    )
    for key in KEYS
]


def _request(key: HMACIdentityKey, sequence: int = 0) -> AuthorizationRequest:
    return AuthorizationRequest(
        tenant_id=key.tenant_id,
        user_id=key.user_id,
        agent_id=key.agent_id,
        user_intent="Read an authorized document",
        tool_name="read_document",
        resource=f"documents/{key.tenant_id}/report-{sequence}.pdf",
        arguments={"page": 1},
    )


def _post(
    client: TestClient,
    signer: HMACRequestSigner,
    request: AuthorizationRequest,
    *,
    nonce: str | None = None,
):
    credentials = signer.sign_authorization(request, nonce=nonce)
    return client.post(
        "/v1/authorize",
        json=request.model_dump(mode="json"),
        headers=credentials.as_http_headers(),
    )


def test_concurrent_identity_sessions_remain_isolated_and_fully_audited(
    tmp_path: Path,
) -> None:
    database = tmp_path / "gateway.sqlite3"
    store = SQLiteGatewayStateStore(database)
    metrics = GatewayMetrics()
    app = create_app(
        AuthorizationService(GRANTS, audit_store=store),
        HMACRequestAuthenticator(list(KEYS), nonce_store=store),
        state_store=store,
        metrics=metrics,
        metrics_token=METRICS_TOKEN,
    )
    client = TestClient(app)
    signers = tuple(HMACRequestSigner(key) for key in KEYS)

    def authorize(sequence: int) -> tuple[int, str, str]:
        index = sequence % len(KEYS)
        response = _post(client, signers[index], _request(KEYS[index], sequence))
        body = response.json()
        return response.status_code, body.get("decision", ""), body.get("audit_id", "")

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(authorize, range(60)))

    assert all(status == 200 and decision == "permit" for status, decision, _ in results)
    audit_ids = [audit_id for _, _, audit_id in results]
    assert len(set(audit_ids)) == 60
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM gateway_audit_records").fetchone()[0] == 60

    rendered = metrics.render_prometheus()
    assert (
        'context_breach_authorization_decisions_total{decision="permit",'
        'reason="policy_permitted"} 60'
    ) in rendered
    assert "tenant-a" not in rendered
    assert "tenant-b" not in rendered


def test_same_credential_is_accepted_only_once_under_concurrent_replay(
    tmp_path: Path,
) -> None:
    store = SQLiteGatewayStateStore(tmp_path / "gateway.sqlite3")
    app = create_app(
        AuthorizationService(GRANTS, audit_store=store),
        HMACRequestAuthenticator(list(KEYS), nonce_store=store),
        state_store=store,
        metrics_token=METRICS_TOKEN,
    )
    client = TestClient(app)
    request = _request(KEYS[0])
    credentials = HMACRequestSigner(KEYS[0]).sign_authorization(
        request,
        nonce="concurrent-http-replay-nonce-01",
    )

    def replay(_: int) -> tuple[int, str]:
        response = client.post(
            "/v1/authorize",
            json=request.model_dump(mode="json"),
            headers=credentials.as_http_headers(),
        )
        return response.status_code, response.json().get("detail", "")

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(replay, range(16)))

    assert sum(status == 200 for status, _ in results) == 1
    assert sum(status == 401 and detail == "credential_replayed" for status, detail in results) == 15


def test_nonce_storage_failure_recovers_without_accepting_during_outage(
    tmp_path: Path,
) -> None:
    database = tmp_path / "gateway.sqlite3"
    store = SQLiteGatewayStateStore(database)
    app = create_app(
        AuthorizationService(GRANTS, audit_store=store),
        HMACRequestAuthenticator(list(KEYS), nonce_store=store),
        state_store=store,
        metrics_token=METRICS_TOKEN,
    )
    client = TestClient(app)
    request = _request(KEYS[0])
    credentials = HMACRequestSigner(KEYS[0]).sign_authorization(
        request,
        nonce="recovery-nonce-store-nonce-01",
    )
    original_path = store.path
    store.path = tmp_path

    unavailable = client.post(
        "/v1/authorize",
        json=request.model_dump(mode="json"),
        headers=credentials.as_http_headers(),
    )
    store.path = original_path
    recovered = client.post(
        "/v1/authorize",
        json=request.model_dump(mode="json"),
        headers=credentials.as_http_headers(),
    )
    replay = client.post(
        "/v1/authorize",
        json=request.model_dump(mode="json"),
        headers=credentials.as_http_headers(),
    )

    assert unavailable.status_code == 503
    assert recovered.status_code == 200
    assert recovered.json()["decision"] == "permit"
    assert replay.status_code == 401
    assert replay.json()["detail"] == "credential_replayed"


def test_audit_failure_consumes_nonce_and_requires_fresh_retry(
    tmp_path: Path,
) -> None:
    database = tmp_path / "gateway.sqlite3"
    audit_store = SQLiteGatewayStateStore(database)
    app = create_app(
        AuthorizationService(GRANTS, audit_store=audit_store),
        HMACRequestAuthenticator(list(KEYS)),
        metrics_token=METRICS_TOKEN,
    )
    client = TestClient(app)
    signer = HMACRequestSigner(KEYS[0])
    request = _request(KEYS[0])
    credentials = signer.sign_authorization(request, nonce="audit-failure-retry-nonce-01")
    original_path = audit_store.path
    audit_store.path = tmp_path

    unavailable = client.post(
        "/v1/authorize",
        json=request.model_dump(mode="json"),
        headers=credentials.as_http_headers(),
    )
    audit_store.path = original_path
    same_credential = client.post(
        "/v1/authorize",
        json=request.model_dump(mode="json"),
        headers=credentials.as_http_headers(),
    )
    fresh_credential = _post(client, signer, request)

    assert unavailable.status_code == 503
    assert same_credential.status_code == 401
    assert same_credential.json()["detail"] == "credential_replayed"
    assert fresh_credential.status_code == 200
    assert fresh_credential.json()["decision"] == "permit"


def test_load_report_aggregates_without_exposing_audit_ids() -> None:
    samples = [
        LoadSample(10.0, 200, "permit", "sensitive-audit-id-1"),
        LoadSample(20.0, 200, "permit", "sensitive-audit-id-2"),
    ]
    report = summarize_load(
        samples,
        requests=2,
        concurrency=2,
        expected_decision="permit",
        elapsed_seconds=0.025,
    )
    rendered = json.dumps(report)

    assert report["results"]["passed"] is True
    assert report["results"]["throughput_rps"] == 80.0
    assert report["results"]["latency_ms"]["p95"] == 20.0
    assert report["results"]["unique_audit_ids"] == 2
    assert "sensitive-audit-id" not in rendered


def test_load_runner_and_error_categories_are_bounded() -> None:
    def send(sequence: int) -> LoadSample:
        if sequence == 3:
            return LoadSample(5.0, None, None, None, bounded_error_category(RuntimeError("secret")))
        return LoadSample(float(sequence + 1), 200, "permit", f"audit-{sequence}")

    ticks = iter((10.0, 11.0))
    report = run_concurrent_load(
        send,
        requests=4,
        concurrency=2,
        expected_decision="permit",
        timer=lambda: next(ticks),
    )

    assert report["results"]["passed"] is False
    assert report["results"]["errors"] == {"other": 1}
    assert "secret" not in json.dumps(report)


def test_reliability_thresholds_include_tail_latency() -> None:
    report = summarize_load(
        [LoadSample(2.0, 200, "permit", "audit-1"), LoadSample(500.0, 200, "permit", "audit-2")],
        requests=2,
        concurrency=2,
        expected_decision="permit",
        elapsed_seconds=0.5,
    )

    failures = evaluate_thresholds(
        report,
        max_p95_ms=600,
        max_p99_ms=100,
        min_throughput_rps=10,
    )

    assert failures == ["p99_latency_exceeded", "throughput_below_minimum"]

    with pytest.raises(ValueError, match="non-negative"):
        evaluate_thresholds(report, max_p99_ms=-1)
