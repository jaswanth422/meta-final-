from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
from fastapi.testclient import TestClient

from context_breach_env.gateway.app import create_app
from context_breach_env.gateway.auth import (
    AuthenticationError,
    HMACIdentityKey,
    HMACRequestAuthenticator,
    HMACRequestSigner,
)
from context_breach_env.gateway.models import (
    AuthorizationDecision,
    AuthorizationGrant,
    AuthorizationRequest,
)
from context_breach_env.gateway.service import AuthorizationService
from context_breach_env.gateway.stores import GatewayStateError, SQLiteGatewayStateStore


NOW = 1_800_000_000
KEY = HMACIdentityKey(
    key_id="persistence-test-v1",
    secret=b"persistence-test-secret-material-32-bytes",
    tenant_id="tenant-1",
    user_id="user-1",
    agent_id="research-agent",
)
GRANT = AuthorizationGrant(
    tenant_id="tenant-1",
    user_id="user-1",
    agent_id="research-agent",
    allowed_tools={"read_document"},
    review_tools={"send_email"},
    resource_patterns=("documents/*", "mailto:*"),
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


def _authenticator(store) -> HMACRequestAuthenticator:
    return HMACRequestAuthenticator([KEY], time_source=lambda: NOW, nonce_store=store)


def _headers(request: AuthorizationRequest, *, nonce: str) -> dict[str, str]:
    signer = HMACRequestSigner(KEY, time_source=lambda: NOW)
    return signer.sign_authorization(request, nonce=nonce).as_http_headers()


def test_audit_record_and_redaction_survive_restart(tmp_path: Path) -> None:
    database = tmp_path / "gateway.sqlite3"
    first_store = SQLiteGatewayStateStore(database)
    first_service = AuthorizationService([GRANT], audit_store=first_store)
    request = _request(
        user_intent="Email the report without exposing credentials",
        tool_name="send_email",
        resource="mailto:reviewer@example.com?access_token=resource-secret",
        arguments={"api_token": "super-secret-value", "subject": "Review"},
    )
    response = first_service.authorize(request)
    assert response.decision == AuthorizationDecision.DENY

    restarted_store = SQLiteGatewayStateStore(database)
    restarted_service = AuthorizationService([GRANT], audit_store=restarted_store)
    record = restarted_service.audit_record(response.audit_id)
    assert record is not None
    assert record.argument_keys == ["api_token", "subject"]
    assert record.resource == "mailto:reviewer@example.com"
    assert "super-secret-value" not in database.read_bytes().decode("utf-8", errors="ignore")
    assert "resource-secret" not in database.read_bytes().decode("utf-8", errors="ignore")


def test_consumed_nonce_remains_blocked_after_restart(tmp_path: Path) -> None:
    database = tmp_path / "gateway.sqlite3"
    request = _request()
    credentials = HMACRequestSigner(KEY, time_source=lambda: NOW).sign_authorization(
        request,
        nonce="restart-persistent-nonce-01",
    )
    _authenticator(SQLiteGatewayStateStore(database)).verify_authorization(request, credentials)

    restarted = _authenticator(SQLiteGatewayStateStore(database))
    with pytest.raises(AuthenticationError, match="credential_replayed"):
        restarted.verify_authorization(request, credentials)


def test_concurrent_workers_cannot_consume_same_nonce(tmp_path: Path) -> None:
    database = tmp_path / "gateway.sqlite3"
    request = _request()
    credentials = HMACRequestSigner(KEY, time_source=lambda: NOW).sign_authorization(
        request,
        nonce="concurrent-worker-nonce-01",
    )
    authenticators = [
        _authenticator(SQLiteGatewayStateStore(database)),
        _authenticator(SQLiteGatewayStateStore(database)),
    ]
    barrier = Barrier(2)

    def verify(authenticator: HMACRequestAuthenticator) -> str:
        barrier.wait()
        try:
            authenticator.verify_authorization(request, credentials)
            return "accepted"
        except AuthenticationError as error:
            return error.reason

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(verify, authenticators))

    assert sorted(results) == ["accepted", "credential_replayed"]


def test_sqlite_audit_table_rejects_updates_and_deletes(tmp_path: Path) -> None:
    database = tmp_path / "gateway.sqlite3"
    store = SQLiteGatewayStateStore(database)
    response = AuthorizationService([GRANT], audit_store=store).authorize(_request())

    with sqlite3.connect(database) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE gateway_audit_records SET tenant_id = ? WHERE audit_id = ?",
                ("attacker-tenant", response.audit_id),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM gateway_audit_records WHERE audit_id = ?",
                (response.audit_id,),
            )


class _FailingNonceStore:
    def consume_nonce(self, **_: object) -> bool:
        raise GatewayStateError("nonce database unavailable")


class _FailingAuditStore:
    def append_audit(self, *_: object) -> None:
        raise GatewayStateError("audit database unavailable")

    def get_audit(self, *_: object):
        raise GatewayStateError("audit database unavailable")


def test_nonce_store_failure_returns_503_without_authorizing() -> None:
    request = _request()
    service = AuthorizationService([GRANT])
    authenticator = _authenticator(_FailingNonceStore())
    client = TestClient(create_app(service, authenticator))

    response = client.post(
        "/v1/authorize",
        json=request.model_dump(mode="json"),
        headers=_headers(request, nonce="failing-nonce-store-001"),
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "gateway_state_unavailable"
    assert service.audit_record(response.headers.get("X-Audit-ID", "missing")) is None


def test_audit_store_failure_returns_503_instead_of_permit() -> None:
    request = _request()
    service = AuthorizationService([GRANT], audit_store=_FailingAuditStore())
    authenticator = _authenticator(None)
    client = TestClient(create_app(service, authenticator))

    response = client.post(
        "/v1/authorize",
        json=request.model_dump(mode="json"),
        headers=_headers(request, nonce="failing-audit-store-001"),
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "gateway_state_unavailable"


def test_health_reports_sqlite_storage(tmp_path: Path) -> None:
    store = SQLiteGatewayStateStore(tmp_path / "gateway.sqlite3")
    service = AuthorizationService([GRANT], audit_store=store)
    authenticator = _authenticator(store)
    client = TestClient(create_app(service, authenticator, state_store=store))
    assert client.get("/health").json() == {
        "status": "ok",
        "authentication": "configured",
        "storage": "sqlite",
    }


def test_health_fails_when_sqlite_becomes_unavailable(tmp_path: Path) -> None:
    store = SQLiteGatewayStateStore(tmp_path / "gateway.sqlite3")
    service = AuthorizationService([GRANT], audit_store=store)
    authenticator = _authenticator(store)
    client = TestClient(create_app(service, authenticator, state_store=store))
    store.path = tmp_path

    response = client.get("/health")
    assert response.status_code == 503
    assert response.json()["detail"] == "gateway_state_unavailable"


def test_environment_config_wires_shared_state_across_app_instances(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "gateway.sqlite3"
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"grants": [GRANT.model_dump(mode="json")]}), encoding="utf-8")
    environment = {
        "CONTEXT_BREACH_DATABASE_PATH": str(database),
        "CONTEXT_BREACH_POLICY_FILE": str(policy),
        "CONTEXT_BREACH_HMAC_KEY_ID": KEY.key_id,
        "CONTEXT_BREACH_HMAC_SECRET": KEY.secret.decode("utf-8"),
        "CONTEXT_BREACH_HMAC_TENANT_ID": KEY.tenant_id,
        "CONTEXT_BREACH_HMAC_USER_ID": KEY.user_id,
        "CONTEXT_BREACH_HMAC_AGENT_ID": KEY.agent_id,
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, value)

    first_client = TestClient(create_app())
    restarted_client = TestClient(create_app())
    request = _request()
    signer = HMACRequestSigner(KEY)
    credentials = signer.sign_authorization(request, nonce="environment-wiring-nonce-01")
    headers = credentials.as_http_headers()

    first = first_client.post(
        "/v1/authorize",
        json=request.model_dump(mode="json"),
        headers=headers,
    )
    replay = restarted_client.post(
        "/v1/authorize",
        json=request.model_dump(mode="json"),
        headers=headers,
    )
    assert first.status_code == 200
    assert replay.status_code == 401
    assert replay.json()["detail"] == "credential_replayed"

    audit_credentials = signer.sign_audit_access(first.json()["audit_id"])
    persisted_audit = restarted_client.get(
        f"/v1/audit/{first.json()['audit_id']}",
        headers=audit_credentials.as_http_headers(),
    )
    assert persisted_audit.status_code == 200
    assert restarted_client.get("/health").json()["storage"] == "sqlite"
