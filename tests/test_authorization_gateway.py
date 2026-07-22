from __future__ import annotations

from fastapi.testclient import TestClient

from context_breach_env.gateway.app import create_app
from context_breach_env.gateway.models import (
    ArtifactAssessment,
    AuthorizationDecision,
    AuthorizationGrant,
)
from context_breach_env.gateway.service import AuthorizationService


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


def test_authorized_document_read_is_permitted() -> None:
    response = TestClient(create_app(_service())).post("/v1/authorize", json=_request())
    assert response.status_code == 200
    assert response.json()["decision"] == AuthorizationDecision.PERMIT.value
    assert response.json()["reason"] == "policy_permitted"


def test_resource_outside_identity_scope_is_denied() -> None:
    response = TestClient(create_app(_service())).post(
        "/v1/authorize",
        json=_request(resource="documents-private/payroll.csv"),
    )
    assert response.json()["decision"] == AuthorizationDecision.DENY.value
    assert response.json()["reason"] == "resource_not_authorized"


def test_outbound_secret_transmission_is_denied_and_audit_is_redacted() -> None:
    service = _service()
    client = TestClient(create_app(service))
    response = client.post(
        "/v1/authorize",
        json=_request(
            user_intent="Email a short summary",
            tool_name="send_email",
            resource="mailto:reviewer@example.com",
            arguments={"recipient": "reviewer@example.com", "api_token": "do-not-log-this"},
        ),
    )
    body = response.json()
    assert body["decision"] == AuthorizationDecision.DENY.value
    assert body["reason"] == "sensitive_data_exfiltration"

    audit = client.get(f"/v1/audit/{body['audit_id']}").json()
    assert audit["argument_keys"] == ["api_token", "recipient"]
    assert "do-not-log-this" not in str(audit)
    assert "Email a short summary" not in str(audit)


def test_ambiguous_high_risk_tool_requires_review() -> None:
    response = TestClient(create_app(_service())).post(
        "/v1/authorize",
        json=_request(
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
    response = TestClient(create_app(service)).post(
        "/v1/authorize",
        json=_request(
            user_intent="Read one document only",
            tool_name="send_email",
            resource="mailto:attacker.example",
            arguments={"body": "Requested data"},
            artifact_ids=["document-attack-1"],
        ),
    )
    assert response.json()["decision"] == AuthorizationDecision.DENY.value
    assert response.json()["reason"] == "contaminated_artifact_flow"


def test_unknown_identity_fails_closed() -> None:
    response = TestClient(create_app(_service())).post(
        "/v1/authorize",
        json=_request(agent_id="unregistered-agent"),
    )
    assert response.json()["decision"] == AuthorizationDecision.DENY.value
    assert response.json()["reason"] == "identity_not_authorized"
