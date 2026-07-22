from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException

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


def create_app(service: AuthorizationService | None = None) -> FastAPI:
    resolved_service = service or _service_from_environment()
    application = FastAPI(
        title="Context Breach Authorization Gateway",
        version="0.1.0",
    )

    @application.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @application.post("/v1/authorize", response_model=AuthorizationResponse)
    def authorize(request: AuthorizationRequest) -> AuthorizationResponse:
        return resolved_service.authorize(request)

    @application.get("/v1/audit/{audit_id}", response_model=AuthorizationAuditRecord)
    def audit_record(audit_id: str) -> AuthorizationAuditRecord:
        record = resolved_service.audit_record(audit_id)
        if record is None:
            raise HTTPException(status_code=404, detail="audit record not found")
        return record

    application.state.authorization_service = resolved_service
    return application


app = create_app()
