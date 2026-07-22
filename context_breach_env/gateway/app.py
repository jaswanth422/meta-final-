from __future__ import annotations

import os
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import ValidationError

from context_breach_env.gateway.auth import (
    AuthenticationError,
    HMACIdentityKey,
    HMACRequestAuthenticator,
    SignedRequestCredentials,
)
from context_breach_env.gateway.models import (
    AuthorizationAuditRecord,
    AuthorizationRequest,
    AuthorizationResponse,
)
from context_breach_env.gateway.service import AuthorizationService


def _service_from_environment() -> AuthorizationService:
    policy_path = os.getenv("CONTEXT_BREACH_POLICY_FILE")
    if not policy_path:
        return AuthorizationService()
    return AuthorizationService.from_policy_file(policy_path)


def _authenticator_from_environment() -> HMACRequestAuthenticator:
    values = {
        "key_id": os.getenv("CONTEXT_BREACH_HMAC_KEY_ID"),
        "secret": os.getenv("CONTEXT_BREACH_HMAC_SECRET"),
        "tenant_id": os.getenv("CONTEXT_BREACH_HMAC_TENANT_ID"),
        "user_id": os.getenv("CONTEXT_BREACH_HMAC_USER_ID"),
        "agent_id": os.getenv("CONTEXT_BREACH_HMAC_AGENT_ID"),
    }
    if not all(values.values()):
        return HMACRequestAuthenticator()
    key = HMACIdentityKey(
        key_id=str(values["key_id"]),
        secret=str(values["secret"]).encode("utf-8"),
        tenant_id=str(values["tenant_id"]),
        user_id=str(values["user_id"]),
        agent_id=str(values["agent_id"]),
    )
    return HMACRequestAuthenticator([key])


def _signed_credentials(
    key_id: Annotated[str | None, Header(alias="X-Context-Key-Id")] = None,
    issued_at: Annotated[str | None, Header(alias="X-Context-Issued-At")] = None,
    expires_at: Annotated[str | None, Header(alias="X-Context-Expires-At")] = None,
    nonce: Annotated[str | None, Header(alias="X-Context-Nonce")] = None,
    signature: Annotated[str | None, Header(alias="X-Context-Signature")] = None,
) -> SignedRequestCredentials:
    if None in {key_id, issued_at, expires_at, nonce, signature}:
        raise HTTPException(status_code=401, detail="authentication_required")
    try:
        return SignedRequestCredentials(
            key_id=key_id,
            issued_at=issued_at,
            expires_at=expires_at,
            nonce=nonce,
            signature=signature,
        )
    except ValidationError as error:
        raise HTTPException(status_code=401, detail="malformed_authentication_headers") from error


def create_app(
    service: AuthorizationService | None = None,
    authenticator: HMACRequestAuthenticator | None = None,
) -> FastAPI:
    resolved_service = service or _service_from_environment()
    resolved_authenticator = authenticator or _authenticator_from_environment()
    application = FastAPI(
        title="Context Breach Authorization Gateway",
        version="0.1.0",
    )

    @application.get("/health")
    def health() -> dict[str, str]:
        authentication = "configured" if resolved_authenticator.configured else "unconfigured"
        return {"status": "ok", "authentication": authentication}

    @application.post("/v1/authorize", response_model=AuthorizationResponse)
    def authorize(
        request: AuthorizationRequest,
        credentials: Annotated[SignedRequestCredentials, Depends(_signed_credentials)],
    ) -> AuthorizationResponse:
        try:
            resolved_authenticator.verify_authorization(request, credentials)
        except AuthenticationError as error:
            raise HTTPException(status_code=401, detail=error.reason) from error
        return resolved_service.authorize(request)

    @application.get("/v1/audit/{audit_id}", response_model=AuthorizationAuditRecord)
    def audit_record(
        audit_id: str,
        credentials: Annotated[SignedRequestCredentials, Depends(_signed_credentials)],
    ) -> AuthorizationAuditRecord:
        try:
            identity = resolved_authenticator.verify_audit_access(audit_id, credentials)
        except AuthenticationError as error:
            raise HTTPException(status_code=401, detail=error.reason) from error
        record = resolved_service.audit_record(audit_id)
        if record is None or (
            record.tenant_id != identity.tenant_id
            or record.user_id != identity.user_id
            or record.agent_id != identity.agent_id
        ):
            raise HTTPException(status_code=404, detail="audit record not found")
        return record

    application.state.authorization_service = resolved_service
    application.state.request_authenticator = resolved_authenticator
    return application


app = create_app()
