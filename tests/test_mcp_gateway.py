from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from context_breach_env.gateway.app import create_app
from context_breach_env.gateway.auth import (
    HMACIdentityKey,
    HMACRequestAuthenticator,
    HMACRequestSigner,
)
from context_breach_env.gateway.mcp import MCPBindingRegistry, execute_if_permitted
from context_breach_env.gateway.models import (
    AuthorizationDecision,
    AuthorizationGrant,
    AuthorizationResponse,
    MCPAuthorizationRequest,
    MCPToolBinding,
)
from context_breach_env.gateway.service import AuthorizationService


KEY = HMACIdentityKey(
    key_id="mcp-test-key-v1",
    secret=b"mcp-test-secret-material-at-least-32-bytes",
    tenant_id="tenant-1",
    user_id="user-1",
    agent_id="agent-1",
)
OTHER_KEY = HMACIdentityKey(
    key_id="mcp-test-key-v2",
    secret=b"other-mcp-test-secret-material-32-bytes",
    tenant_id="tenant-2",
    user_id="user-2",
    agent_id="agent-2",
)
BINDINGS = [
    MCPToolBinding(
        server_name="filesystem",
        mcp_tool_name="read_document",
        policy_tool_name="read_document",
        resource_argument="path",
        resource_kind="path",
        resource_prefix="documents",
    ),
    MCPToolBinding(
        server_name="mail",
        mcp_tool_name="send",
        policy_tool_name="send_email",
        resource_argument="recipient",
        resource_kind="email",
    ),
]
GRANT = AuthorizationGrant(
    tenant_id=KEY.tenant_id,
    user_id=KEY.user_id,
    agent_id=KEY.agent_id,
    allowed_tools={"read_document"},
    review_tools={"send_email"},
    resource_patterns=("documents/*", "mailto:*"),
)


def _request(
    *,
    server_name: str = "filesystem",
    tool_name: str = "read_document",
    arguments: dict[str, object] | None = None,
    **updates: object,
) -> MCPAuthorizationRequest:
    values: dict[str, object] = {
        "tenant_id": KEY.tenant_id,
        "user_id": KEY.user_id,
        "agent_id": KEY.agent_id,
        "user_intent": "Read the quarterly report",
        "server_name": server_name,
        "call": {
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments if arguments is not None else {"path": "report.pdf"},
            },
        },
        "artifact_ids": [],
    }
    values.update(updates)
    return MCPAuthorizationRequest.model_validate(values)


def _service() -> AuthorizationService:
    return AuthorizationService([GRANT], mcp_bindings=BINDINGS)


def _gateway(
    service: AuthorizationService | None = None,
) -> tuple[TestClient, HMACRequestSigner, AuthorizationService]:
    resolved_service = service or _service()
    authenticator = HMACRequestAuthenticator([KEY, OTHER_KEY])
    return (
        TestClient(create_app(resolved_service, authenticator)),
        HMACRequestSigner(KEY),
        resolved_service,
    )


def _post(
    client: TestClient,
    signer: HMACRequestSigner,
    request: MCPAuthorizationRequest,
):
    credentials = signer.sign_mcp_authorization(request)
    return client.post(
        "/v1/mcp/authorize",
        json=request.model_dump(mode="json"),
        headers=credentials.as_http_headers(),
    )


def test_registered_filesystem_call_is_mapped_permitted_and_audited() -> None:
    client, signer, service = _gateway()
    response = _post(client, signer, _request(arguments={"path": "reports/q2.pdf", "page": 2}))

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "permit"
    assert body["reason"] == "policy_permitted"
    audit = service.audit_record(body["audit_id"])
    assert audit is not None
    assert audit.tool_name == "read_document"
    assert audit.resource == "documents/reports/q2.pdf"
    assert audit.argument_keys == ["page", "path"]


@pytest.mark.parametrize(
    "path",
    (
        "../private.txt",
        "reports/../private.txt",
        "/etc/passwd",
        "reports\\private.txt",
        "reports//q2.pdf",
        "reports/./q2.pdf",
        "reports/%2e%2e/private.txt",
        "report.pdf?token=secret",
        "report.pdf#fragment",
    ),
)
def test_noncanonical_or_traversal_paths_fail_closed(path: str) -> None:
    service = _service()
    request = _request(arguments={"path": path})
    response = service.authorize_mcp(request)

    assert response.decision == AuthorizationDecision.DENY
    assert response.reason == "mcp_resource_invalid"
    audit = service.audit_record(response.audit_id)
    assert audit is not None
    assert audit.tool_name == "unregistered_mcp_tool"
    assert audit.resource == "mcp://invalid-or-unregistered"
    assert audit.argument_keys == []


def test_unknown_tool_fails_closed_without_auditing_attacker_fields() -> None:
    service = _service()
    request = _request(
        tool_name="attacker_controlled_tool",
        arguments={"api_token": "must-never-enter-audit"},
    )
    response = service.authorize_mcp(request)

    assert response.decision == AuthorizationDecision.DENY
    assert response.reason == "mcp_tool_not_registered"
    audit = service.audit_record(response.audit_id)
    assert audit is not None
    rendered = audit.model_dump_json()
    assert "attacker_controlled_tool" not in rendered
    assert "api_token" not in rendered
    assert "must-never-enter-audit" not in rendered


def test_signature_covers_complete_mcp_call() -> None:
    client, signer, _ = _gateway()
    original = _request(arguments={"path": "report.pdf"})
    credentials = signer.sign_mcp_authorization(original)
    modified = _request(arguments={"path": "private/payroll.pdf"})

    response = client.post(
        "/v1/mcp/authorize",
        json=modified.model_dump(mode="json"),
        headers=credentials.as_http_headers(),
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_request_signature"


def test_mcp_credential_is_one_time_and_identity_bound() -> None:
    client, signer, _ = _gateway()
    request = _request()
    credentials = signer.sign_mcp_authorization(request, nonce="mcp-one-time-nonce-0001")
    headers = credentials.as_http_headers()

    first = client.post("/v1/mcp/authorize", json=request.model_dump(mode="json"), headers=headers)
    replay = client.post("/v1/mcp/authorize", json=request.model_dump(mode="json"), headers=headers)
    spoofed = _request(tenant_id=OTHER_KEY.tenant_id)
    spoofed_response = _post(client, signer, spoofed)

    assert first.status_code == 200
    assert replay.status_code == 401
    assert replay.json()["detail"] == "credential_replayed"
    assert spoofed_response.status_code == 401
    assert spoofed_response.json()["detail"] == "credential_identity_mismatch"


def test_execute_helper_invokes_downstream_exactly_once_after_permit() -> None:
    service = _service()
    executed: list[str] = []

    result = execute_if_permitted(
        _request(),
        authorize=service.authorize_mcp,
        execute=lambda call: executed.append(call.params.name) or {"content": "ok"},
    )

    assert result.authorization.decision == AuthorizationDecision.PERMIT
    assert result.executed is True
    assert result.downstream_result == {"content": "ok"}
    assert executed == ["read_document"]


def test_execute_helper_uses_immutable_snapshot_across_authorization_boundary() -> None:
    request = _request(arguments={"path": "report.pdf"})
    executed_paths: list[str] = []

    def mutating_authorizer(candidate: MCPAuthorizationRequest) -> AuthorizationResponse:
        candidate.call.params.arguments["path"] = "private/payroll.pdf"
        request.call.params.arguments["path"] = "also-mutated-by-caller.pdf"
        return AuthorizationResponse(
            decision=AuthorizationDecision.PERMIT,
            reason="policy_permitted",
            audit_id="test-audit-id",
        )

    result = execute_if_permitted(
        request,
        authorize=mutating_authorizer,
        execute=lambda call: executed_paths.append(str(call.params.arguments["path"])),
    )

    assert result.executed is True
    assert executed_paths == ["report.pdf"]


@pytest.mark.parametrize(
    ("arguments", "expected_decision", "expected_reason"),
    (
        (
            {"recipient": "reviewer@example.com", "subject": "Review"},
            AuthorizationDecision.REQUIRE_REVIEW,
            "high_risk_tool_requires_review",
        ),
        (
            {"recipient": "reviewer@example.com", "api_token": "secret-value"},
            AuthorizationDecision.DENY,
            "sensitive_data_exfiltration",
        ),
    ),
)
def test_nonpermit_mail_calls_never_reach_downstream(
    arguments: dict[str, object],
    expected_decision: AuthorizationDecision,
    expected_reason: str,
) -> None:
    service = _service()
    executed: list[str] = []

    result = execute_if_permitted(
        _request(server_name="mail", tool_name="send", arguments=arguments),
        authorize=service.authorize_mcp,
        execute=lambda call: executed.append(call.params.name),
    )

    assert result.authorization.decision == expected_decision
    assert result.authorization.reason == expected_reason
    assert result.executed is False
    assert result.downstream_result is None
    assert executed == []


@pytest.mark.parametrize(
    "url",
    (
        "https://user:password@approved.example/report",
        "https://approved.example/report?token=secret",
        "https://approved.example/report#fragment",
        "file:///etc/passwd",
    ),
)
def test_url_binding_rejects_credential_and_non_http_targets(url: str) -> None:
    binding = MCPToolBinding(
        server_name="web",
        mcp_tool_name="fetch",
        policy_tool_name="read_document",
        resource_argument="url",
        resource_kind="url",
    )
    service = AuthorizationService(
        [
            GRANT.model_copy(
                update={"resource_patterns": ("https://approved.example/*",)},
            )
        ],
        mcp_bindings=[binding],
    )
    response = service.authorize_mcp(
        _request(server_name="web", tool_name="fetch", arguments={"url": url})
    )

    assert response.decision == AuthorizationDecision.DENY
    assert response.reason == "mcp_resource_invalid"


@pytest.mark.parametrize(
    "recipient",
    (
        '"quoted"@example.com',
        ".leading@example.com",
        "double..dot@example.com",
        "user@-example.com",
        "user@example..com",
    ),
)
def test_email_binding_rejects_noncanonical_mailboxes(recipient: str) -> None:
    response = _service().authorize_mcp(
        _request(
            server_name="mail",
            tool_name="send",
            arguments={"recipient": recipient, "subject": "Review"},
        )
    )

    assert response.decision == AuthorizationDecision.DENY
    assert response.reason == "mcp_resource_invalid"


def test_binding_registry_rejects_duplicate_and_invalid_bindings() -> None:
    with pytest.raises(ValueError, match="unique"):
        MCPBindingRegistry([BINDINGS[0], BINDINGS[0]])
    with pytest.raises(ValueError, match="prefix"):
        MCPBindingRegistry(
            [
                BINDINGS[0].model_copy(update={"resource_prefix": "../documents"}),
            ]
        )


def test_mcp_json_rpc_shape_is_strict() -> None:
    payload = _request().model_dump(mode="json")
    payload["call"]["method"] = "resources/read"
    with pytest.raises(ValidationError):
        MCPAuthorizationRequest.model_validate(payload)

    payload = _request().model_dump(mode="json")
    payload["call"]["unexpected"] = "field"
    with pytest.raises(ValidationError):
        MCPAuthorizationRequest.model_validate(payload)
