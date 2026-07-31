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
    AuthenticationMaterial,
    AuthenticationError,
    AuthenticationUnavailableError,
    CompositeRequestAuthenticator,
    HMACIdentityKey,
    HMACRequestAuthenticator,
    OIDCJWTAuthenticator,
    SignedRequestCredentials,
)
from context_breach_env.gateway.models import (
    AuthorizationAuditRecord,
    AuthorizationRequest,
    AuthorizationResponse,
    MCPAuthorizationRequest,
    MCPExecutionAuditRecord,
    MCPProxyResponse,
    RAGRetrievalAuditRecord,
    RAGSearchRequest,
    RAGSearchResponse,
)
from context_breach_env.gateway.observability import (
    GatewayMetrics,
    gateway_logger,
    operation_name,
    structured_log,
)
from context_breach_env.gateway.service import AuthorizationService
from context_breach_env.gateway.proxy import (
    DefaultMCPResultScanner,
    MCPDownstreamRegistry,
    MCPProxy,
)
from context_breach_env.gateway.rag import (
    PermissionAwareRAGRetriever,
    RAGCorpusRegistry,
    RAGRetrievalError,
)
from context_breach_env.gateway.stores import (
    GatewayStateError,
    GatewayStateStore,
    InMemoryExecutionAuditStore,
    InMemoryRetrievalAuditStore,
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


def _hmac_authenticator_from_environment(
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
        groups=frozenset(
            group.strip()
            for group in os.getenv("CONTEXT_BREACH_HMAC_GROUPS", "").split(",")
            if group.strip()
        ),
    )
    return HMACRequestAuthenticator([key], nonce_store=state_store)


def _environment_flag(name: str, *, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes"}:
        return True
    if normalized in {"0", "false", "no"}:
        return False
    raise ValueError(f"{name} must be one of true, false, 1, 0, yes, or no")


def _oidc_authenticator_from_environment() -> OIDCJWTAuthenticator | None:
    values = {
        "issuer": os.getenv("CONTEXT_BREACH_OIDC_ISSUER"),
        "audience": os.getenv("CONTEXT_BREACH_OIDC_AUDIENCE"),
        "jwks_url": os.getenv("CONTEXT_BREACH_OIDC_JWKS_URL"),
        "agent_id": os.getenv("CONTEXT_BREACH_OIDC_AGENT_ID"),
    }
    if not any(values.values()):
        return None
    if not all(values.values()):
        missing = sorted(name for name, value in values.items() if not value)
        raise ValueError(f"incomplete OIDC configuration: {', '.join(missing)}")
    allow_insecure_http = _environment_flag(
        "CONTEXT_BREACH_OIDC_ALLOW_INSECURE_HTTP",
        default=False,
    )
    return OIDCJWTAuthenticator(
        issuer=str(values["issuer"]),
        audience=str(values["audience"]),
        jwks_url=str(values["jwks_url"]),
        agent_id=str(values["agent_id"]),
        tenant_claim=os.getenv("CONTEXT_BREACH_OIDC_TENANT_CLAIM", "tenant_id"),
        user_claim=os.getenv("CONTEXT_BREACH_OIDC_USER_CLAIM", "sub"),
        groups_claim=os.getenv("CONTEXT_BREACH_OIDC_GROUPS_CLAIM", "groups"),
        scope_claim=os.getenv("CONTEXT_BREACH_OIDC_SCOPE_CLAIM", "scope"),
        allow_insecure_http=allow_insecure_http,
    )


def _authenticator_from_environment(
    state_store: GatewayStateStore | None = None,
) -> CompositeRequestAuthenticator:
    return CompositeRequestAuthenticator(
        _hmac_authenticator_from_environment(state_store),
        _oidc_authenticator_from_environment(),
    )


def _mcp_downstreams_from_environment() -> MCPDownstreamRegistry:
    path = os.getenv("CONTEXT_BREACH_MCP_DOWNSTREAMS_FILE")
    if not path:
        return MCPDownstreamRegistry()
    return MCPDownstreamRegistry.from_file(path)


def _rag_corpora_from_environment() -> RAGCorpusRegistry:
    path = os.getenv("CONTEXT_BREACH_RAG_CORPUS_FILE")
    if not path:
        return RAGCorpusRegistry()
    return RAGCorpusRegistry.from_file(path)


def _authentication_material(
    key_id: Annotated[str | None, Header(alias="X-Context-Key-Id")] = None,
    issued_at: Annotated[str | None, Header(alias="X-Context-Issued-At")] = None,
    expires_at: Annotated[str | None, Header(alias="X-Context-Expires-At")] = None,
    nonce: Annotated[str | None, Header(alias="X-Context-Nonce")] = None,
    signature: Annotated[str | None, Header(alias="X-Context-Signature")] = None,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> AuthenticationMaterial:
    signed_values = (key_id, issued_at, expires_at, nonce, signature)
    has_any_signed = any(value is not None for value in signed_values)
    has_all_signed = all(value is not None for value in signed_values)
    if has_any_signed and not has_all_signed:
        raise HTTPException(status_code=401, detail="malformed_authentication_headers")
    if has_any_signed and authorization is not None:
        raise HTTPException(status_code=401, detail="ambiguous_authentication")

    if has_all_signed:
        try:
            signed = SignedRequestCredentials(
                key_id=key_id,
                issued_at=issued_at,
                expires_at=expires_at,
                nonce=nonce,
                signature=signature,
            )
        except ValidationError as error:
            raise HTTPException(
                status_code=401,
                detail="malformed_authentication_headers",
            ) from error
        return AuthenticationMaterial(signed=signed)

    if authorization is None:
        raise HTTPException(status_code=401, detail="authentication_required")
    scheme, separator, token = authorization.partition(" ")
    if (
        not separator
        or scheme.lower() != "bearer"
        or not token
        or len(token) > 16_384
        or any(character.isspace() for character in token)
    ):
        raise HTTPException(status_code=401, detail="malformed_bearer_token")
    return AuthenticationMaterial(bearer_token=token)


def create_app(
    service: AuthorizationService | None = None,
    authenticator: HMACRequestAuthenticator | CompositeRequestAuthenticator | None = None,
    state_store: GatewayStateStore | None = None,
    metrics: GatewayMetrics | None = None,
    metrics_token: str | None = None,
    mcp_proxy: MCPProxy | None = None,
    rag_retriever: PermissionAwareRAGRetriever | None = None,
) -> FastAPI:
    resolved_state_store = state_store
    if resolved_state_store is None and (service is None or authenticator is None):
        resolved_state_store = _state_store_from_environment()
    resolved_service = service or _service_from_environment(resolved_state_store)
    if authenticator is None:
        resolved_authenticator = _authenticator_from_environment(resolved_state_store)
    elif isinstance(authenticator, CompositeRequestAuthenticator):
        resolved_authenticator = authenticator
    else:
        resolved_authenticator = CompositeRequestAuthenticator(authenticator)
    resolved_metrics = metrics or GatewayMetrics()
    resolved_metrics_token = (
        os.getenv("CONTEXT_BREACH_METRICS_TOKEN") if metrics_token is None else metrics_token
    )
    resolved_execution_store = (
        resolved_state_store
        if resolved_state_store is not None
        else InMemoryExecutionAuditStore()
    )
    resolved_mcp_proxy = mcp_proxy or MCPProxy(
        authorization_service=resolved_service,
        downstreams=_mcp_downstreams_from_environment(),
        execution_store=resolved_execution_store,
        result_scanner=DefaultMCPResultScanner(),
    )
    resolved_retrieval_store = (
        resolved_state_store
        if resolved_state_store is not None
        else InMemoryRetrievalAuditStore()
    )
    resolved_rag_retriever = rag_retriever or PermissionAwareRAGRetriever(
        authorization_service=resolved_service,
        corpora=_rag_corpora_from_environment(),
        retrieval_store=resolved_retrieval_store,
        result_scanner=DefaultMCPResultScanner(),
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

    @application.exception_handler(RAGRetrievalError)
    async def rag_retrieval_error_handler(
        request: Request,
        __: RAGRetrievalError,
    ) -> JSONResponse:
        route = request.scope.get("route")
        route_path = getattr(route, "path", "unmatched")
        resolved_metrics.record_state_failure(operation=route_path)
        return JSONResponse(status_code=503, content={"detail": "rag_retrieval_unavailable"})

    @application.exception_handler(AuthenticationUnavailableError)
    async def authentication_unavailable_error_handler(
        request: Request,
        error: AuthenticationUnavailableError,
    ) -> JSONResponse:
        route = request.scope.get("route")
        route_path = getattr(route, "path", "unmatched")
        resolved_metrics.record_state_failure(operation=route_path)
        return JSONResponse(status_code=503, content={"detail": error.reason})

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
        material: Annotated[AuthenticationMaterial, Depends(_authentication_material)],
    ) -> AuthorizationResponse:
        try:
            resolved_authenticator.verify_authorization(request, material)
        except AuthenticationError as error:
            raise HTTPException(status_code=401, detail=error.reason) from error
        response = resolved_service.authorize(request)
        resolved_metrics.record_decision(
            decision=response.decision.value,
            reason=response.reason,
        )
        return response

    @application.post("/v1/mcp/authorize", response_model=AuthorizationResponse)
    def authorize_mcp(
        request: MCPAuthorizationRequest,
        material: Annotated[AuthenticationMaterial, Depends(_authentication_material)],
    ) -> AuthorizationResponse:
        try:
            resolved_authenticator.verify_mcp_authorization(request, material)
        except AuthenticationError as error:
            raise HTTPException(status_code=401, detail=error.reason) from error
        response = resolved_service.authorize_mcp(request)
        resolved_metrics.record_decision(
            decision=response.decision.value,
            reason=response.reason,
        )
        return response

    @application.post("/v1/mcp/proxy", response_model=MCPProxyResponse)
    def proxy_mcp(
        request: MCPAuthorizationRequest,
        material: Annotated[AuthenticationMaterial, Depends(_authentication_material)],
    ) -> MCPProxyResponse:
        try:
            resolved_authenticator.verify_mcp_proxy(request, material)
        except AuthenticationError as error:
            raise HTTPException(status_code=401, detail=error.reason) from error
        response = resolved_mcp_proxy.execute(request)
        resolved_metrics.record_decision(
            decision=response.authorization.decision.value,
            reason=response.authorization.reason,
        )
        return response

    @application.post("/v1/rag/search", response_model=RAGSearchResponse)
    def search_rag(
        request: RAGSearchRequest,
        material: Annotated[AuthenticationMaterial, Depends(_authentication_material)],
    ) -> RAGSearchResponse:
        try:
            identity = resolved_authenticator.verify_rag_search(request, material)
        except AuthenticationError as error:
            raise HTTPException(status_code=401, detail=error.reason) from error
        response = resolved_rag_retriever.search(request, identity)
        resolved_metrics.record_decision(
            decision=response.authorization.decision.value,
            reason=response.authorization.reason,
        )
        return response

    @application.get("/v1/audit/{audit_id}", response_model=AuthorizationAuditRecord)
    def audit_record(
        audit_id: str,
        material: Annotated[AuthenticationMaterial, Depends(_authentication_material)],
    ) -> AuthorizationAuditRecord:
        try:
            identity = resolved_authenticator.verify_audit_access(audit_id, material)
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

    @application.get(
        "/v1/mcp/executions/{execution_id}",
        response_model=MCPExecutionAuditRecord,
    )
    def execution_record(
        execution_id: str,
        material: Annotated[AuthenticationMaterial, Depends(_authentication_material)],
    ) -> MCPExecutionAuditRecord:
        try:
            identity = resolved_authenticator.verify_execution_access(
                execution_id,
                material,
            )
        except AuthenticationError as error:
            raise HTTPException(status_code=401, detail=error.reason) from error
        record = resolved_mcp_proxy.execution_store.get_execution(execution_id)
        if record is None or (
            record.tenant_id != identity.tenant_id
            or record.user_id != identity.user_id
            or record.agent_id != identity.agent_id
        ):
            raise HTTPException(status_code=404, detail="MCP execution record not found")
        return record

    @application.get(
        "/v1/rag/retrievals/{retrieval_id}",
        response_model=RAGRetrievalAuditRecord,
    )
    def retrieval_record(
        retrieval_id: str,
        material: Annotated[AuthenticationMaterial, Depends(_authentication_material)],
    ) -> RAGRetrievalAuditRecord:
        try:
            identity = resolved_authenticator.verify_retrieval_access(
                retrieval_id,
                material,
            )
        except AuthenticationError as error:
            raise HTTPException(status_code=401, detail=error.reason) from error
        record = resolved_rag_retriever.retrieval_store.get_retrieval(retrieval_id)
        if record is None or (
            record.tenant_id != identity.tenant_id
            or record.user_id != identity.user_id
            or record.agent_id != identity.agent_id
        ):
            raise HTTPException(status_code=404, detail="RAG retrieval record not found")
        return record

    application.state.authorization_service = resolved_service
    application.state.request_authenticator = resolved_authenticator
    application.state.gateway_state_store = resolved_state_store
    application.state.gateway_metrics = resolved_metrics
    application.state.mcp_proxy = resolved_mcp_proxy
    application.state.rag_retriever = resolved_rag_retriever
    return application


app = create_app()
