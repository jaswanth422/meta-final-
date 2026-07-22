from __future__ import annotations

import logging
import os
import secrets
import time
from typing import Annotated
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import JSONResponse, PlainTextResponse
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
from context_breach_env.gateway.observability import (
    GatewayMetrics,
    gateway_logger,
    operation_name,
    structured_log,
)
from context_breach_env.gateway.service import AuthorizationService
from context_breach_env.gateway.stores import (
    GatewayStateError,
    GatewayStateStore,
    SQLiteGatewayStateStore,
)


def _state_store_from_environment() -> GatewayStateStore | None:
    database_path = os.getenv("CONTEXT_BREACH_DATABASE_PATH")
    if not database_path:
        return None
    return SQLiteGatewayStateStore(database_path)


def _service_from_environment(state_store: GatewayStateStore | None = None) -> AuthorizationService:
    policy_path = os.getenv("CONTEXT_BREACH_POLICY_FILE")
    if not policy_path:
        return AuthorizationService(audit_store=state_store)
    return AuthorizationService.from_policy_file(policy_path, audit_store=state_store)


def _authenticator_from_environment(
    state_store: GatewayStateStore | None = None,
) -> HMACRequestAuthenticator:
    values = {
        "key_id": os.getenv("CONTEXT_BREACH_HMAC_KEY_ID"),
        "secret": os.getenv("CONTEXT_BREACH_HMAC_SECRET"),
        "tenant_id": os.getenv("CONTEXT_BREACH_HMAC_TENANT_ID"),
        "user_id": os.getenv("CONTEXT_BREACH_HMAC_USER_ID"),
        "agent_id": os.getenv("CONTEXT_BREACH_HMAC_AGENT_ID"),
    }
    if not all(values.values()):
        return HMACRequestAuthenticator(nonce_store=state_store)
    key = HMACIdentityKey(
        key_id=str(values["key_id"]),
        secret=str(values["secret"]).encode("utf-8"),
        tenant_id=str(values["tenant_id"]),
        user_id=str(values["user_id"]),
        agent_id=str(values["agent_id"]),
    )
    return HMACRequestAuthenticator([key], nonce_store=state_store)


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
    state_store: GatewayStateStore | None = None,
    metrics: GatewayMetrics | None = None,
    metrics_token: str | None = None,
) -> FastAPI:
    resolved_state_store = state_store
    if resolved_state_store is None and (service is None or authenticator is None):
        resolved_state_store = _state_store_from_environment()
    resolved_service = service or _service_from_environment(resolved_state_store)
    resolved_authenticator = authenticator or _authenticator_from_environment(resolved_state_store)
    resolved_metrics = metrics or GatewayMetrics()
    resolved_metrics_token = (
        os.getenv("CONTEXT_BREACH_METRICS_TOKEN") if metrics_token is None else metrics_token
    )
    if resolved_metrics_token is not None and len(resolved_metrics_token) < 32:
        raise ValueError("metrics bearer token must contain at least 32 characters")
    logger = gateway_logger()
    application = FastAPI(
        title="Context Breach Authorization Gateway",
        version="0.1.0",
    )

    @application.middleware("http")
    async def observe_request(request: Request, call_next):
        request_id = str(uuid4())
        started = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            route = request.scope.get("route")
            route_path = getattr(route, "path", "unmatched")
            duration = time.perf_counter() - started
            resolved_metrics.record_request(
                method=request.method,
                route=route_path,
                status_code=status_code,
                duration_seconds=duration,
            )
            structured_log(
                logger,
                logging.INFO,
                "gateway_request",
                request_id=request_id,
                method=request.method,
                operation=operation_name(route_path),
                status_code=status_code,
                duration_ms=round(duration * 1000, 3),
            )

    @application.exception_handler(HTTPException)
    async def observed_http_error_handler(request: Request, error: HTTPException):
        if error.status_code == 401:
            route = request.scope.get("route")
            route_path = getattr(route, "path", "unmatched")
            resolved_metrics.record_authentication_failure(
                operation=route_path,
                reason=str(error.detail),
            )
        return await http_exception_handler(request, error)

    @application.exception_handler(GatewayStateError)
    async def gateway_state_error_handler(
        request: Request,
        __: GatewayStateError,
    ) -> JSONResponse:
        route = request.scope.get("route")
        route_path = getattr(route, "path", "unmatched")
        resolved_metrics.record_state_failure(operation=route_path)
        return JSONResponse(status_code=503, content={"detail": "gateway_state_unavailable"})

    @application.get("/health")
    def health() -> dict[str, str]:
        if resolved_state_store is not None:
            resolved_state_store.health_check()
        authentication = "configured" if resolved_authenticator.configured else "unconfigured"
        storage = "sqlite" if isinstance(resolved_state_store, SQLiteGatewayStateStore) else "memory"
        return {"status": "ok", "authentication": authentication, "storage": storage}

    @application.get("/metrics", response_class=PlainTextResponse)
    def prometheus_metrics(
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    ) -> PlainTextResponse:
        if resolved_metrics_token is None:
            raise HTTPException(status_code=503, detail="metrics_not_configured")
        expected = f"Bearer {resolved_metrics_token}"
        if authorization is None:
            raise HTTPException(status_code=401, detail="metrics_authentication_required")
        if not secrets.compare_digest(authorization, expected):
            raise HTTPException(status_code=401, detail="invalid_metrics_token")
        return PlainTextResponse(
            resolved_metrics.render_prometheus(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @application.post("/v1/authorize", response_model=AuthorizationResponse)
    def authorize(
        request: AuthorizationRequest,
        credentials: Annotated[SignedRequestCredentials, Depends(_signed_credentials)],
    ) -> AuthorizationResponse:
        try:
            resolved_authenticator.verify_authorization(request, credentials)
        except AuthenticationError as error:
            raise HTTPException(status_code=401, detail=error.reason) from error
        response = resolved_service.authorize(request)
        resolved_metrics.record_decision(
            decision=response.decision.value,
            reason=response.reason,
        )
        return response

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
    application.state.gateway_state_store = resolved_state_store
    application.state.gateway_metrics = resolved_metrics
    return application


app = create_app()
