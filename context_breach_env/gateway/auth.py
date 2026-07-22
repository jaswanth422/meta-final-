from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from pydantic import BaseModel, Field

from context_breach_env.gateway.models import AuthorizationRequest


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

    def __post_init__(self) -> None:
        if not self.key_id or not self.tenant_id or not self.user_id or not self.agent_id:
            raise ValueError("key identity fields must be non-empty")
        if len(self.secret) < 32:
            raise ValueError("HMAC key secret must contain at least 32 bytes")


@dataclass(frozen=True)
class AuthenticatedIdentity:
    key_id: str
    tenant_id: str
    user_id: str
    agent_id: str


class AuthenticationError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class HMACRequestAuthenticator:
    """Verifies request integrity, bound identity, expiry, and one-time use."""

    def __init__(
        self,
        keys: list[HMACIdentityKey] | None = None,
        *,
        max_ttl_seconds: int = 300,
        clock_skew_seconds: int = 30,
        time_source: Callable[[], float] = time.time,
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
        self._used_nonces: dict[tuple[str, str], int] = {}
        self._nonce_lock = threading.Lock()

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

        nonce_key = (credentials.key_id, credentials.nonce)
        with self._nonce_lock:
            self._used_nonces = {
                existing: expiry
                for existing, expiry in self._used_nonces.items()
                if expiry >= now
            }
            if nonce_key in self._used_nonces:
                raise AuthenticationError("credential_replayed")
            self._used_nonces[nonce_key] = credentials.expires_at

        return AuthenticatedIdentity(
            key_id=key.key_id,
            tenant_id=key.tenant_id,
            user_id=key.user_id,
            agent_id=key.agent_id,
        )


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
