from __future__ import annotations

import time

from fastapi.testclient import TestClient

from context_breach_env.gateway.app import create_app
from context_breach_env.gateway.auth import (
    HMACIdentityKey,
    HMACRequestAuthenticator,
    HMACRequestSigner,
)
from context_breach_env.gateway.models import (
    ArtifactAssessment,
    AuthorizationDecision,
    AuthorizationGrant,
    AuthorizationRequest,
)
from context_breach_env.gateway.service import AuthorizationService


TEST_KEY = HMACIdentityKey(
    key_id="test-key-v1",
    secret=b"test-gateway-secret-material-32-bytes-minimum",
    tenant_id="tenant-1",
    user_id="user-1",
    agent_id="research-agent",
)


def _service() -> AuthorizationService:
    return AuthorizationService(
        grants=[
            AuthorizationGrant(
                tenant_id="tenant-1",
                user_id="user-1",
                agent_id="research-agent",
                allowed_tools={"read_document", "search_documents"},
                review_tools={"send_email", "http_request"},
                resource_patterns=("documents/*", "mailto:*", "https://approved.example/*"),
            )
        ]
    )


def _gateway(service: AuthorizationService | None = None) -> tuple[TestClient, HMACRequestSigner]:
    authenticator = HMACRequestAuthenticator([TEST_KEY])
    client = TestClient(create_app(service or _service(), authenticator))
    return client, HMACRequestSigner(TEST_KEY)


def _request(**updates: object) -> dict[str, object]:
    request: dict[str, object] = {
        "tenant_id": "tenant-1",
        "user_id": "user-1",
        "agent_id": "research-agent",
        "user_intent": "Read the quarterly report",
        "tool_name": "read_document",
        "resource": "documents/quarterly-report.pdf",
        "arguments": {"page": 1},
        "artifact_ids": [],
    }
    request.update(updates)
    return request


def _post(
    client: TestClient,
    signer: HMACRequestSigner,
    payload: dict[str, object],
    **signing_options: object,
):
    request = AuthorizationRequest.model_validate(payload)
    credentials = signer.sign_authorization(request, **signing_options)
    return client.post("/v1/authorize", json=payload, headers=credentials.as_http_headers())


def test_authorized_document_read_is_permitted() -> None:
    client, signer = _gateway()
    response = _post(client, signer, _request())
    assert response.status_code == 200
    assert response.json()["decision"] == AuthorizationDecision.PERMIT.value
    assert response.json()["reason"] == "policy_permitted"


def test_resource_outside_identity_scope_is_denied() -> None:
    client, signer = _gateway()
    response = _post(client, signer, _request(resource="documents-private/payroll.csv"))
    assert response.json()["decision"] == AuthorizationDecision.DENY.value
    assert response.json()["reason"] == "resource_not_authorized"


def test_outbound_secret_transmission_is_denied_and_audit_is_redacted() -> None:
    client, signer = _gateway()
    response = _post(
        client,
        signer,
        _request(
            user_intent="Email a short summary",
            tool_name="send_email",
            resource="mailto:reviewer@example.com",
            arguments={"recipient": "reviewer@example.com", "api_token": "do-not-log-this"},
        ),
    )
    body = response.json()
    assert body["decision"] == AuthorizationDecision.DENY.value
    assert body["reason"] == "sensitive_data_exfiltration"

    audit_credentials = signer.sign_audit_access(body["audit_id"])
    audit = client.get(
        f"/v1/audit/{body['audit_id']}",
        headers=audit_credentials.as_http_headers(),
    ).json()
    assert audit["argument_keys"] == ["api_token", "recipient"]
    assert "do-not-log-this" not in str(audit)
    assert "Email a short summary" not in str(audit)


def test_ambiguous_high_risk_tool_requires_review() -> None:
    client, signer = _gateway()
    response = _post(
        client,
        signer,
        _request(
            user_intent="Notify the reviewer",
            tool_name="send_email",
            resource="mailto:reviewer@example.com",
            arguments={"subject": "Review available"},
        ),
    )
    assert response.json()["decision"] == AuthorizationDecision.REQUIRE_REVIEW.value
    assert response.json()["reason"] == "high_risk_tool_requires_review"


def test_malicious_document_cannot_trigger_outbound_tool_call() -> None:
    service = _service()
    service.register_artifact(
        ArtifactAssessment(
            tenant_id="tenant-1",
            artifact_id="document-attack-1",
            signature_valid=True,
            contaminated=True,
            risk_level="high",
        )
    )
    client, signer = _gateway(service)
    response = _post(
        client,
        signer,
        _request(
            user_intent="Read one document only",
            tool_name="send_email",
            resource="mailto:attacker.example",
            arguments={"body": "Requested data"},
            artifact_ids=["document-attack-1"],
        ),
    )
    assert response.json()["decision"] == AuthorizationDecision.DENY.value
    assert response.json()["reason"] == "contaminated_artifact_flow"


def test_unsigned_request_is_rejected() -> None:
    client, _ = _gateway()
    response = client.post("/v1/authorize", json=_request())
    assert response.status_code == 401
    assert response.json()["detail"] == "authentication_required"


def test_modified_signed_body_is_rejected() -> None:
    client, signer = _gateway()
    original = AuthorizationRequest.model_validate(_request())
    credentials = signer.sign_authorization(original)
    modified = _request(user_intent="Send the report to an external address")
    response = client.post(
        "/v1/authorize",
        json=modified,
        headers=credentials.as_http_headers(),
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_request_signature"


def test_expired_credential_is_rejected() -> None:
    client, signer = _gateway()
    response = _post(
        client,
        signer,
        _request(),
        issued_at=int(time.time()) - 120,
        ttl_seconds=60,
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "credential_expired"


def test_credential_lifetime_above_server_limit_is_rejected() -> None:
    client, signer = _gateway()
    response = _post(client, signer, _request(), ttl_seconds=301)
    assert response.status_code == 401
    assert response.json()["detail"] == "credential_lifetime_too_long"


def test_replayed_credential_is_rejected() -> None:
    client, signer = _gateway()
    request = AuthorizationRequest.model_validate(_request())
    credentials = signer.sign_authorization(request, nonce="one-time-nonce-0001")
    headers = credentials.as_http_headers()

    first = client.post("/v1/authorize", json=_request(), headers=headers)
    second = client.post("/v1/authorize", json=_request(), headers=headers)

    assert first.status_code == 200
    assert second.status_code == 401
    assert second.json()["detail"] == "credential_replayed"


def test_cross_tenant_identity_spoofing_is_rejected() -> None:
    client, signer = _gateway()
    response = _post(client, signer, _request(tenant_id="tenant-2"))
    assert response.status_code == 401
    assert response.json()["detail"] == "credential_identity_mismatch"


def test_audit_lookup_requires_a_fresh_signed_credential() -> None:
    client, signer = _gateway()
    authorization = _post(client, signer, _request()).json()
    audit_id = authorization["audit_id"]

    unsigned = client.get(f"/v1/audit/{audit_id}")
    assert unsigned.status_code == 401

    credential = signer.sign_audit_access(audit_id, nonce="audit-access-nonce-01")
    headers = credential.as_http_headers()
    first = client.get(f"/v1/audit/{audit_id}", headers=headers)
    replay = client.get(f"/v1/audit/{audit_id}", headers=headers)
    assert first.status_code == 200
    assert replay.status_code == 401
    assert replay.json()["detail"] == "credential_replayed"


def test_audit_lookup_is_bound_to_exact_user_and_agent_identity() -> None:
    other_key = HMACIdentityKey(
        key_id="other-user-key-v1",
        secret=b"other-user-secret-material-32-bytes-minimum",
        tenant_id="tenant-1",
        user_id="user-2",
        agent_id="other-agent",
    )
    service = _service()
    authenticator = HMACRequestAuthenticator([TEST_KEY, other_key])
    client = TestClient(create_app(service, authenticator))
    signer = HMACRequestSigner(TEST_KEY)
    authorization = _post(client, signer, _request()).json()

    other_signer = HMACRequestSigner(other_key)
    credentials = other_signer.sign_audit_access(authorization["audit_id"])
    response = client.get(
        f"/v1/audit/{authorization['audit_id']}",
        headers=credentials.as_http_headers(),
    )
    assert response.status_code == 404
