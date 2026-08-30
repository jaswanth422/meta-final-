from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import jwt
from pydantic import BaseModel, Field

from context_breach_env.gateway.models import (
    AuthorizationRequest,
    MCPAuthorizationRequest,
    RAGSearchRequest,
)
from context_breach_env.gateway.stores import InMemoryNonceStore, NonceStore


class SignedRequestCredentials(BaseModel):
    key_id: str = Field(min_length=1, max_length=128)
    issued_at: int = Field(ge=0)
    expires_at: int = Field(ge=0)
    nonce: str = Field(pattern=r"^[A-Za-z0-9._~-]{16,128}$")
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")

    def as_http_headers(self) -> dict[str, str]:
        return {
            "X-Context-Key-Id": self.key_id,
            "X-Context-Issued-At": str(self.issued_at),
            "X-Context-Expires-At": str(self.expires_at),
            "X-Context-Nonce": self.nonce,
            "X-Context-Signature": self.signature,
        }


@dataclass(frozen=True)
class HMACIdentityKey:
    key_id: str
    secret: bytes
    tenant_id: str
    user_id: str
    agent_id: str
    groups: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.key_id or not self.tenant_id or not self.user_id or not self.agent_id:
            raise ValueError("key identity fields must be non-empty")
        if len(self.secret) < 32:
            raise ValueError("HMAC key secret must contain at least 32 bytes")
        if any(not group or len(group) > 128 for group in self.groups):
            raise ValueError(
                "identity groups must contain non-empty values of at most 128 characters"
            )


@dataclass(frozen=True)
class AuthenticatedIdentity:
    key_id: str
    tenant_id: str
    user_id: str
    agent_id: str
    groups: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class AuthenticationMaterial:
    signed: SignedRequestCredentials | None = None
    bearer_token: str | None = None

    def __post_init__(self) -> None:
        if (self.signed is None) == (self.bearer_token is None):
            raise ValueError("exactly one authentication mechanism is required")


class AuthenticationError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class AuthenticationUnavailableError(RuntimeError):
    def __init__(self, reason: str = "identity_provider_unavailable") -> None:
        super().__init__(reason)
        self.reason = reason


OIDC_REQUIRED_SCOPE = {
    "authorize": "context:authorize",
    "audit": "context:audit:read",
    "mcp_authorize": "context:mcp:authorize",
    "mcp_proxy": "context:mcp:proxy",
    "mcp_execution": "context:mcp:audit:read",
    "rag_search": "context:rag:search",
    "rag_retrieval": "context:rag:audit:read",
}


class OIDCJWTAuthenticator:
    """Validates asymmetric JWT access tokens and derives trusted identity claims."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_url: str,
        agent_id: str,
        tenant_claim: str = "tenant_id",
        user_claim: str = "sub",
        groups_claim: str = "groups",
        scope_claim: str = "scope",
        algorithms: tuple[str, ...] = ("RS256",),
        leeway_seconds: int = 30,
        allow_insecure_http: bool = False,
        signing_key_resolver: Callable[[str], Any] | None = None,
    ) -> None:
        _validate_oidc_url(issuer, allow_insecure_http=allow_insecure_http)
        _validate_oidc_url(jwks_url, allow_insecure_http=allow_insecure_http)
        if not audience or not agent_id:
            raise ValueError("OIDC audience and agent ID must be non-empty")
        claim_names = (tenant_claim, user_claim, groups_claim, scope_claim)
        if any(not claim or len(claim) > 128 for claim in claim_names):
            raise ValueError("OIDC claim names must contain 1 to 128 characters")
        if not algorithms or any(algorithm != "RS256" for algorithm in algorithms):
            raise ValueError("only the RS256 OIDC signing algorithm is supported")
        if leeway_seconds < 0 or leeway_seconds > 300:
            raise ValueError("OIDC leeway must be between 0 and 300 seconds")

        self.issuer = issuer
        self.audience = audience
        self.agent_id = agent_id
        self.tenant_claim = tenant_claim
        self.user_claim = user_claim
        self.groups_claim = groups_claim
        self.scope_claim = scope_claim
        self.algorithms = algorithms
        self.leeway_seconds = leeway_seconds
        if signing_key_resolver is None:
            jwks_client = jwt.PyJWKClient(
                jwks_url,
                cache_keys=True,
                lifespan=300,
                timeout=5,
            )
            self._signing_key_resolver = (
                lambda token: jwks_client.get_signing_key_from_jwt(token).key
            )
        else:
            self._signing_key_resolver = signing_key_resolver

    @property
    def configured(self) -> bool:
        return True

    def verify(self, purpose: str, token: str) -> AuthenticatedIdentity:
        required_scope = OIDC_REQUIRED_SCOPE.get(purpose)
        if required_scope is None:
            raise AuthenticationError("unsupported_authentication_purpose")
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") not in self.algorithms:
                raise AuthenticationError("invalid_bearer_token")
            signing_key = self._signing_key_resolver(token)
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=list(self.algorithms),
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway_seconds,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except AuthenticationError:
            raise
        except jwt.exceptions.PyJWKClientConnectionError as error:
            raise AuthenticationUnavailableError() from error
        except jwt.PyJWTError as error:
            raise AuthenticationError("invalid_bearer_token") from error
        except (OSError, TimeoutError) as error:
            raise AuthenticationUnavailableError() from error
        except Exception as error:
            raise AuthenticationError("invalid_bearer_token") from error

        tenant_id = _required_string_claim(claims, self.tenant_claim)
        user_id = _required_string_claim(claims, self.user_claim)
        groups = _groups_claim(claims.get(self.groups_claim))
        scopes = _scopes_claim(claims.get(self.scope_claim))
        if required_scope not in scopes:
            raise AuthenticationError("insufficient_token_scope")

        stable_subject = f"{claims['iss']}|{claims['sub']}".encode("utf-8")
        return AuthenticatedIdentity(
            key_id=f"oidc:{hashlib.sha256(stable_subject).hexdigest()}",
            tenant_id=tenant_id,
            user_id=user_id,
            agent_id=self.agent_id,
            groups=groups,
        )


class HMACRequestAuthenticator:
    """Verifies request integrity, bound identity, expiry, and one-time use."""

    def __init__(
        self,
        keys: list[HMACIdentityKey] | None = None,
        *,
        max_ttl_seconds: int = 300,
        clock_skew_seconds: int = 30,
        time_source: Callable[[], float] = time.time,
        nonce_store: NonceStore | None = None,
    ) -> None:
        if max_ttl_seconds <= 0 or clock_skew_seconds < 0:
            raise ValueError("authentication timing limits must be non-negative")
        resolved_keys = keys or []
        if len({key.key_id for key in resolved_keys}) != len(resolved_keys):
            raise ValueError("HMAC key IDs must be unique")
        self._keys = {key.key_id: key for key in resolved_keys}
        self._max_ttl_seconds = max_ttl_seconds
        self._clock_skew_seconds = clock_skew_seconds
        self._time_source = time_source
        self._nonce_store = nonce_store if nonce_store is not None else InMemoryNonceStore()

    @property
    def configured(self) -> bool:
        return bool(self._keys)

    def verify_authorization(
        self,
        request: AuthorizationRequest,
        credentials: SignedRequestCredentials,
    ) -> AuthenticatedIdentity:
        identity = self._verify("authorize", canonical_authorization_payload(request), credentials)
        if (
            request.tenant_id != identity.tenant_id
            or request.user_id != identity.user_id
            or request.agent_id != identity.agent_id
        ):
            raise AuthenticationError("credential_identity_mismatch")
        return identity

    def verify_audit_access(
        self,
        audit_id: str,
        credentials: SignedRequestCredentials,
    ) -> AuthenticatedIdentity:
        payload = canonical_json({"audit_id": audit_id})
        return self._verify("audit", payload, credentials)

    def verify_execution_access(
        self,
        execution_id: str,
        credentials: SignedRequestCredentials,
    ) -> AuthenticatedIdentity:
        payload = canonical_json({"execution_id": execution_id})
        return self._verify("mcp_execution", payload, credentials)

    def verify_retrieval_access(
        self,
        retrieval_id: str,
        credentials: SignedRequestCredentials,
    ) -> AuthenticatedIdentity:
        payload = canonical_json({"retrieval_id": retrieval_id})
        return self._verify("rag_retrieval", payload, credentials)

    def verify_mcp_authorization(
        self,
        request: MCPAuthorizationRequest,
        credentials: SignedRequestCredentials,
    ) -> AuthenticatedIdentity:
        identity = self._verify(
            "mcp_authorize",
            canonical_mcp_authorization_payload(request),
            credentials,
        )
        if (
            request.tenant_id != identity.tenant_id
            or request.user_id != identity.user_id
            or request.agent_id != identity.agent_id
        ):
            raise AuthenticationError("credential_identity_mismatch")
        return identity

    def verify_mcp_proxy(
        self,
        request: MCPAuthorizationRequest,
        credentials: SignedRequestCredentials,
    ) -> AuthenticatedIdentity:
        identity = self._verify(
            "mcp_proxy",
            canonical_mcp_authorization_payload(request),
            credentials,
        )
        if (
            request.tenant_id != identity.tenant_id
            or request.user_id != identity.user_id
            or request.agent_id != identity.agent_id
        ):
            raise AuthenticationError("credential_identity_mismatch")
        return identity

    def verify_rag_search(
        self,
        request: RAGSearchRequest,
        credentials: SignedRequestCredentials,
    ) -> AuthenticatedIdentity:
        identity = self._verify(
            "rag_search",
            canonical_rag_search_payload(request),
            credentials,
        )
        if (
            request.tenant_id != identity.tenant_id
            or request.user_id != identity.user_id
            or request.agent_id != identity.agent_id
        ):
            raise AuthenticationError("credential_identity_mismatch")
        return identity

    def _verify(
        self,
        purpose: str,
        payload: bytes,
        credentials: SignedRequestCredentials,
    ) -> AuthenticatedIdentity:
        key = self._keys.get(credentials.key_id)
        if key is None:
            raise AuthenticationError("unknown_signing_key")

        now = int(self._time_source())
        if credentials.expires_at < credentials.issued_at:
            raise AuthenticationError("invalid_credential_lifetime")
        if credentials.expires_at - credentials.issued_at > self._max_ttl_seconds:
            raise AuthenticationError("credential_lifetime_too_long")
        if credentials.issued_at > now + self._clock_skew_seconds:
            raise AuthenticationError("credential_not_yet_valid")
        if credentials.expires_at <= now:
            raise AuthenticationError("credential_expired")

        expected = _signature(key.secret, purpose, payload, credentials)
        if not hmac.compare_digest(expected, credentials.signature):
            raise AuthenticationError("invalid_request_signature")

        consumed = self._nonce_store.consume_nonce(
            key_id=credentials.key_id,
            nonce=credentials.nonce,
            expires_at=credentials.expires_at,
            now=now,
        )
        if not consumed:
            raise AuthenticationError("credential_replayed")

        return AuthenticatedIdentity(
            key_id=key.key_id,
            tenant_id=key.tenant_id,
            user_id=key.user_id,
            agent_id=key.agent_id,
            groups=key.groups,
        )


class CompositeRequestAuthenticator:
    """Selects one unambiguous authentication mechanism for every request."""

    def __init__(
        self,
        hmac_authenticator: HMACRequestAuthenticator,
        oidc_authenticator: OIDCJWTAuthenticator | None = None,
    ) -> None:
        self.hmac = hmac_authenticator
        self.oidc = oidc_authenticator

    @property
    def configured(self) -> bool:
        return self.hmac.configured or self.oidc is not None

    @property
    def methods(self) -> tuple[str, ...]:
        methods = []
        if self.hmac.configured:
            methods.append("hmac")
        if self.oidc is not None:
            methods.append("oidc")
        return tuple(methods)

    def verify_authorization(
        self,
        request: AuthorizationRequest,
        material: AuthenticationMaterial,
    ) -> AuthenticatedIdentity:
        identity = self._verify(
            "authorize",
            material,
            lambda credentials: self.hmac.verify_authorization(request, credentials),
        )
        _require_request_identity(request, identity)
        return identity

    def verify_audit_access(
        self,
        audit_id: str,
        material: AuthenticationMaterial,
    ) -> AuthenticatedIdentity:
        return self._verify(
            "audit",
            material,
            lambda credentials: self.hmac.verify_audit_access(audit_id, credentials),
        )

    def verify_execution_access(
        self,
        execution_id: str,
        material: AuthenticationMaterial,
    ) -> AuthenticatedIdentity:
        return self._verify(
            "mcp_execution",
            material,
            lambda credentials: self.hmac.verify_execution_access(
                execution_id,
                credentials,
            ),
        )

    def verify_retrieval_access(
        self,
        retrieval_id: str,
        material: AuthenticationMaterial,
    ) -> AuthenticatedIdentity:
        return self._verify(
            "rag_retrieval",
            material,
            lambda credentials: self.hmac.verify_retrieval_access(
                retrieval_id,
                credentials,
            ),
        )

    def verify_mcp_authorization(
        self,
        request: MCPAuthorizationRequest,
        material: AuthenticationMaterial,
    ) -> AuthenticatedIdentity:
        identity = self._verify(
            "mcp_authorize",
            material,
            lambda credentials: self.hmac.verify_mcp_authorization(request, credentials),
        )
        _require_request_identity(request, identity)
        return identity

    def verify_mcp_proxy(
        self,
        request: MCPAuthorizationRequest,
        material: AuthenticationMaterial,
    ) -> AuthenticatedIdentity:
        identity = self._verify(
            "mcp_proxy",
            material,
            lambda credentials: self.hmac.verify_mcp_proxy(request, credentials),
        )
        _require_request_identity(request, identity)
        return identity

    def verify_rag_search(
        self,
        request: RAGSearchRequest,
        material: AuthenticationMaterial,
    ) -> AuthenticatedIdentity:
        identity = self._verify(
            "rag_search",
            material,
            lambda credentials: self.hmac.verify_rag_search(request, credentials),
        )
        _require_request_identity(request, identity)
        return identity

    def _verify(
        self,
        purpose: str,
        material: AuthenticationMaterial,
        verify_hmac: Callable[[SignedRequestCredentials], AuthenticatedIdentity],
    ) -> AuthenticatedIdentity:
        if material.signed is not None:
            return verify_hmac(material.signed)
        if self.oidc is None or material.bearer_token is None:
            raise AuthenticationError("oidc_not_configured")
        return self.oidc.verify(purpose, material.bearer_token)


class HMACRequestSigner:
    """Client-side helper used by integrations and local tests."""

    def __init__(self, key: HMACIdentityKey, *, time_source: Callable[[], float] = time.time) -> None:
        self._key = key
        self._time_source = time_source

    def sign_authorization(
        self,
        request: AuthorizationRequest,
        *,
        ttl_seconds: int = 60,
        nonce: str | None = None,
        issued_at: int | None = None,
    ) -> SignedRequestCredentials:
        return self._sign(
            "authorize",
            canonical_authorization_payload(request),
            ttl_seconds=ttl_seconds,
            nonce=nonce,
            issued_at=issued_at,
        )

    def sign_audit_access(
        self,
        audit_id: str,
        *,
        ttl_seconds: int = 60,
        nonce: str | None = None,
        issued_at: int | None = None,
    ) -> SignedRequestCredentials:
        return self._sign(
            "audit",
            canonical_json({"audit_id": audit_id}),
            ttl_seconds=ttl_seconds,
            nonce=nonce,
            issued_at=issued_at,
        )

    def sign_execution_access(
        self,
        execution_id: str,
        *,
        ttl_seconds: int = 60,
        nonce: str | None = None,
        issued_at: int | None = None,
    ) -> SignedRequestCredentials:
        return self._sign(
            "mcp_execution",
            canonical_json({"execution_id": execution_id}),
            ttl_seconds=ttl_seconds,
            nonce=nonce,
            issued_at=issued_at,
        )

    def sign_retrieval_access(
        self,
        retrieval_id: str,
        *,
        ttl_seconds: int = 60,
        nonce: str | None = None,
        issued_at: int | None = None,
    ) -> SignedRequestCredentials:
        return self._sign(
            "rag_retrieval",
            canonical_json({"retrieval_id": retrieval_id}),
            ttl_seconds=ttl_seconds,
            nonce=nonce,
            issued_at=issued_at,
        )

    def sign_mcp_authorization(
        self,
        request: MCPAuthorizationRequest,
        *,
        ttl_seconds: int = 60,
        nonce: str | None = None,
        issued_at: int | None = None,
    ) -> SignedRequestCredentials:
        return self._sign(
            "mcp_authorize",
            canonical_mcp_authorization_payload(request),
            ttl_seconds=ttl_seconds,
            nonce=nonce,
            issued_at=issued_at,
        )

    def sign_mcp_proxy(
        self,
        request: MCPAuthorizationRequest,
        *,
        ttl_seconds: int = 60,
        nonce: str | None = None,
        issued_at: int | None = None,
    ) -> SignedRequestCredentials:
        return self._sign(
            "mcp_proxy",
            canonical_mcp_authorization_payload(request),
            ttl_seconds=ttl_seconds,
            nonce=nonce,
            issued_at=issued_at,
        )

    def sign_rag_search(
        self,
        request: RAGSearchRequest,
        *,
        ttl_seconds: int = 60,
        nonce: str | None = None,
        issued_at: int | None = None,
    ) -> SignedRequestCredentials:
        return self._sign(
            "rag_search",
            canonical_rag_search_payload(request),
            ttl_seconds=ttl_seconds,
            nonce=nonce,
            issued_at=issued_at,
        )

    def _sign(
        self,
        purpose: str,
        payload: bytes,
        *,
        ttl_seconds: int,
        nonce: str | None,
        issued_at: int | None,
    ) -> SignedRequestCredentials:
        if ttl_seconds <= 0:
            raise ValueError("credential TTL must be positive")
        resolved_issued_at = int(self._time_source()) if issued_at is None else issued_at
        unsigned = SignedRequestCredentials(
            key_id=self._key.key_id,
            issued_at=resolved_issued_at,
            expires_at=resolved_issued_at + ttl_seconds,
            nonce=nonce or secrets.token_urlsafe(18),
            signature="0" * 64,
        )
        return unsigned.model_copy(
            update={"signature": _signature(self._key.secret, purpose, payload, unsigned)}
        )


def canonical_authorization_payload(request: AuthorizationRequest) -> bytes:
    return canonical_json(request.model_dump(mode="json"))


def canonical_mcp_authorization_payload(request: MCPAuthorizationRequest) -> bytes:
    return canonical_json(request.model_dump(mode="json"))


def canonical_rag_search_payload(request: RAGSearchRequest) -> bytes:
    return canonical_json(request.model_dump(mode="json"))


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _signature(
    secret: bytes,
    purpose: str,
    payload: bytes,
    credentials: SignedRequestCredentials,
) -> str:
    payload_hash = hashlib.sha256(payload).hexdigest()
    signing_input = "\n".join(
        (
            "context-breach-hmac-v1",
            purpose,
            credentials.key_id,
            str(credentials.issued_at),
            str(credentials.expires_at),
            credentials.nonce,
            payload_hash,
        )
    ).encode("utf-8")
    return hmac.new(secret, signing_input, hashlib.sha256).hexdigest()


def _validate_oidc_url(value: str, *, allow_insecure_http: bool) -> None:
    parsed = urlsplit(value)
    loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    allowed_scheme = parsed.scheme == "https" or (
        allow_insecure_http and parsed.scheme == "http" and loopback
    )
    if (
        not allowed_scheme
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("OIDC issuer and JWKS URL must use canonical HTTPS URLs")


def _required_string_claim(claims: Mapping[str, Any], claim_name: str) -> str:
    value = claims.get(claim_name)
    if not isinstance(value, str) or not value or len(value) > 256:
        raise AuthenticationError("invalid_bearer_token_claims")
    return value


def _groups_claim(value: Any) -> frozenset[str]:
    if value is None:
        return frozenset()
    if (
        not isinstance(value, list)
        or len(value) > 1_000
        or any(not isinstance(group, str) or not group or len(group) > 128 for group in value)
    ):
        raise AuthenticationError("invalid_bearer_token_claims")
    return frozenset(value)


def _scopes_claim(value: Any) -> frozenset[str]:
    if isinstance(value, str):
        scopes = value.split()
    elif isinstance(value, list):
        scopes = value
    else:
        raise AuthenticationError("invalid_bearer_token_claims")
    if (
        len(scopes) > 100
        or any(not isinstance(scope, str) or not scope or len(scope) > 128 for scope in scopes)
    ):
        raise AuthenticationError("invalid_bearer_token_claims")
    return frozenset(scopes)


def _require_request_identity(
    request: AuthorizationRequest | MCPAuthorizationRequest | RAGSearchRequest,
    identity: AuthenticatedIdentity,
) -> None:
    if (
        request.tenant_id != identity.tenant_id
        or request.user_id != identity.user_id
        or request.agent_id != identity.agent_id
    ):
        raise AuthenticationError("credential_identity_mismatch")
