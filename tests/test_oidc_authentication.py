from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from context_breach_env.gateway.app import (
    _oidc_authenticator_from_environment,
    create_app,
)
from context_breach_env.gateway.auth import (
    CompositeRequestAuthenticator,
    HMACIdentityKey,
    HMACRequestAuthenticator,
    HMACRequestSigner,
    OIDCJWTAuthenticator,
)
from context_breach_env.gateway.models import (
    AuthorizationGrant,
    AuthorizationRequest,
    RAGChunk,
    RAGCorporaDocument,
    RAGCorpus,
    RAGSearchRequest,
)
from context_breach_env.gateway.proxy import DefaultMCPResultScanner
from context_breach_env.gateway.rag import PermissionAwareRAGRetriever, RAGCorpusRegistry
from context_breach_env.gateway.service import AuthorizationService
from context_breach_env.gateway.stores import InMemoryGatewayStateStore


ISSUER = "https://identity.example.test/realms/company"
AUDIENCE = "context-breach-gateway"
AGENT_ID = "research-agent"
PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_KEY = PRIVATE_KEY.public_key()
HMAC_KEY = HMACIdentityKey(
    key_id="oidc-compat-hmac-v1",
    secret=b"oidc-compatibility-secret-at-least-32-bytes",
    tenant_id="tenant-1",
    user_id="alice",
    agent_id=AGENT_ID,
    groups=frozenset({"finance"}),
)


def _claims(
    *,
    scope: str,
    tenant_id: object = "tenant-1",
    subject: object = "alice",
    groups: object = None,
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
    expires_in: int = 300,
) -> dict[str, object]:
    now = int(time.time())
    return {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "iat": now,
        "exp": now + expires_in,
        "jti": "test-token-id",
        "client_id": "test-client",
        "tenant_id": tenant_id,
        "groups": ["finance"] if groups is None else groups,
        "scope": scope,
    }


def _token(**updates: object) -> str:
    claims = _claims(scope="context:authorize")
    claims.update(updates)
    return jwt.encode(
        claims,
        PRIVATE_KEY,
        algorithm="RS256",
        headers={"typ": "at+jwt", "kid": "test-key-v1"},
    )


def _oidc(*, resolver=None) -> OIDCJWTAuthenticator:
    return OIDCJWTAuthenticator(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url="https://identity.example.test/realms/company/jwks",
        agent_id=AGENT_ID,
        signing_key_resolver=resolver or (lambda _: PUBLIC_KEY),
    )


def _authorization_request(**updates: object) -> AuthorizationRequest:
    values: dict[str, object] = {
        "tenant_id": "tenant-1",
        "user_id": "alice",
        "agent_id": AGENT_ID,
        "user_intent": "Read the approved company report",
        "tool_name": "read_document",
        "resource": "documents/public/report.pdf",
        "arguments": {},
    }
    values.update(updates)
    return AuthorizationRequest.model_validate(values)


def _grant() -> AuthorizationGrant:
    return AuthorizationGrant(
        tenant_id="tenant-1",
        user_id="alice",
        agent_id=AGENT_ID,
        allowed_tools={"read_document", "search_documents"},
        resource_patterns=("documents/public/*", "rag://company-documents"),
    )


def _gateway(
    *,
    oidc: OIDCJWTAuthenticator | None = None,
) -> tuple[TestClient, InMemoryGatewayStateStore]:
    store = InMemoryGatewayStateStore()
    service = AuthorizationService([_grant()], audit_store=store)
    authenticator = CompositeRequestAuthenticator(
        HMACRequestAuthenticator([HMAC_KEY], nonce_store=store),
        oidc,
    )
    corpus = RAGCorpusRegistry(
        RAGCorporaDocument(
            corpora=[
                RAGCorpus(
                    corpus_name="company-documents",
                    chunks=[
                        RAGChunk(
                            tenant_id="tenant-1",
                            document_id="finance-forecast",
                            document_version="v1",
                            chunk_id="finance-1",
                            content="Quarterly revenue forecast and operating margin.",
                            allowed_groups={"finance"},
                            classification="confidential",
                            acl_version="acl-v1",
                        )
                    ],
                )
            ]
        )
    )
    retriever = PermissionAwareRAGRetriever(
        authorization_service=service,
        corpora=corpus,
        retrieval_store=store,
        result_scanner=DefaultMCPResultScanner(),
    )
    return (
        TestClient(
            create_app(
                service,
                authenticator,
                state_store=store,
                rag_retriever=retriever,
            )
        ),
        store,
    )


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_valid_oidc_token_authorizes_request_from_verified_claims() -> None:
    client, store = _gateway(oidc=_oidc())
    request = _authorization_request()
    token = _token()

    response = client.post(
        "/v1/authorize",
        json=request.model_dump(mode="json"),
        headers=_bearer(token),
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "permit"
    record = store.get_audit(response.json()["audit_id"])
    assert record is not None
    assert token not in record.model_dump_json()


def test_oidc_group_claim_drives_rag_acl_without_client_supplied_groups() -> None:
    client, _ = _gateway(oidc=_oidc())
    request = RAGSearchRequest(
        tenant_id="tenant-1",
        user_id="alice",
        agent_id=AGENT_ID,
        user_intent="Read the authorized finance forecast",
        corpus_name="company-documents",
        query="quarterly revenue",
    )
    token = _token(scope="context:rag:search")

    response = client.post(
        "/v1/rag/search",
        json=request.model_dump(mode="json"),
        headers=_bearer(token),
    )

    assert response.status_code == 200
    assert [result["document_id"] for result in response.json()["results"]] == [
        "finance-forecast"
    ]


def test_oidc_identity_claims_cannot_be_overridden_by_request_body() -> None:
    client, _ = _gateway(oidc=_oidc())
    request = _authorization_request(user_id="mallory")

    response = client.post(
        "/v1/authorize",
        json=request.model_dump(mode="json"),
        headers=_bearer(_token()),
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "credential_identity_mismatch"


def test_endpoint_specific_scope_is_required() -> None:
    client, _ = _gateway(oidc=_oidc())
    request = _authorization_request()

    response = client.post(
        "/v1/authorize",
        json=request.model_dump(mode="json"),
        headers=_bearer(_token(scope="context:rag:search")),
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "insufficient_token_scope"


@pytest.mark.parametrize(
    "token",
    [
        _token(aud="different-audience"),
        _token(iss="https://attacker.example.test"),
        _token(exp=int(time.time()) - 120),
    ],
)
def test_invalid_standard_jwt_claims_are_rejected(token: str) -> None:
    client, _ = _gateway(oidc=_oidc())
    response = client.post(
        "/v1/authorize",
        json=_authorization_request().model_dump(mode="json"),
        headers=_bearer(token),
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_bearer_token"


def test_non_rs256_token_is_rejected_before_key_resolution() -> None:
    resolution_attempted = False

    def resolver(_: str):
        nonlocal resolution_attempted
        resolution_attempted = True
        return PUBLIC_KEY

    token = jwt.encode(
        _claims(scope="context:authorize"),
        "attacker-controlled-secret-at-least-32-bytes",
        algorithm="HS256",
    )
    client, _ = _gateway(oidc=_oidc(resolver=resolver))

    response = client.post(
        "/v1/authorize",
        json=_authorization_request().model_dump(mode="json"),
        headers=_bearer(token),
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_bearer_token"
    assert resolution_attempted is False


def test_hmac_and_bearer_credentials_cannot_be_combined() -> None:
    client, _ = _gateway(oidc=_oidc())
    request = _authorization_request()
    signed = HMACRequestSigner(HMAC_KEY).sign_authorization(request)
    headers = {**signed.as_http_headers(), **_bearer(_token())}

    response = client.post(
        "/v1/authorize",
        json=request.model_dump(mode="json"),
        headers=headers,
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "ambiguous_authentication"


def test_partial_hmac_headers_are_rejected_even_with_no_bearer() -> None:
    client, _ = _gateway(oidc=_oidc())
    response = client.post(
        "/v1/authorize",
        json=_authorization_request().model_dump(mode="json"),
        headers={"X-Context-Key-Id": HMAC_KEY.key_id},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "malformed_authentication_headers"


def test_bearer_token_is_rejected_when_oidc_is_not_configured() -> None:
    client, _ = _gateway(oidc=None)
    response = client.post(
        "/v1/authorize",
        json=_authorization_request().model_dump(mode="json"),
        headers=_bearer(_token()),
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "oidc_not_configured"


def test_identity_provider_network_failure_returns_sanitized_503() -> None:
    def unavailable(_: str):
        raise jwt.exceptions.PyJWKClientConnectionError(
            "network failure with internal identity-provider details"
        )

    client, _ = _gateway(oidc=_oidc(resolver=unavailable))
    response = client.post(
        "/v1/authorize",
        json=_authorization_request().model_dump(mode="json"),
        headers=_bearer(_token()),
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "identity_provider_unavailable"}
    assert "internal identity-provider" not in response.text


def test_malformed_groups_claim_is_rejected() -> None:
    client, _ = _gateway(oidc=_oidc())
    response = client.post(
        "/v1/authorize",
        json=_authorization_request().model_dump(mode="json"),
        headers=_bearer(_token(groups="finance")),
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_bearer_token_claims"


def test_oidc_audit_read_requires_read_scope_and_exact_identity() -> None:
    client, _ = _gateway(oidc=_oidc())
    request = _authorization_request()
    signed = HMACRequestSigner(HMAC_KEY).sign_authorization(request)
    decision = client.post(
        "/v1/authorize",
        json=request.model_dump(mode="json"),
        headers=signed.as_http_headers(),
    ).json()

    permitted = client.get(
        f"/v1/audit/{decision['audit_id']}",
        headers=_bearer(_token(scope="context:audit:read")),
    )
    wrong_user = client.get(
        f"/v1/audit/{decision['audit_id']}",
        headers=_bearer(
            _token(
                scope="context:audit:read",
                sub="bob",
            )
        ),
    )

    assert permitted.status_code == 200
    assert wrong_user.status_code == 404


def test_existing_hmac_path_remains_compatible() -> None:
    client, _ = _gateway(oidc=_oidc())
    request = _authorization_request()
    signed = HMACRequestSigner(HMAC_KEY).sign_authorization(request)

    response = client.post(
        "/v1/authorize",
        json=request.model_dump(mode="json"),
        headers=signed.as_http_headers(),
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "permit"


def test_partial_oidc_environment_fails_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    names = (
        "CONTEXT_BREACH_OIDC_ISSUER",
        "CONTEXT_BREACH_OIDC_AUDIENCE",
        "CONTEXT_BREACH_OIDC_JWKS_URL",
        "CONTEXT_BREACH_OIDC_AGENT_ID",
    )
    for name in names:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CONTEXT_BREACH_OIDC_ISSUER", ISSUER)

    with pytest.raises(ValueError, match="incomplete OIDC configuration"):
        _oidc_authenticator_from_environment()


def test_non_loopback_http_oidc_configuration_is_rejected() -> None:
    with pytest.raises(ValueError, match="canonical HTTPS"):
        OIDCJWTAuthenticator(
            issuer="http://identity.example.test",
            audience=AUDIENCE,
            jwks_url="http://identity.example.test/jwks",
            agent_id=AGENT_ID,
            signing_key_resolver=lambda _: PUBLIC_KEY,
        )
