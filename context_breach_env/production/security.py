from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Iterable

from context_breach_env.production.models import ArtifactEnvelope, ScanFinding


DEFAULT_INJECTION_PATTERNS = (
    r"ignore (?:all |any )?(?:previous|prior) instructions?",
    r"ignore (?:the )?policy",
    r"system prompt",
    r"bypass (?:the )?(?:security|policy|review)",
    r"legally binding offer",
    r"(?:include|reveal|send).{0,40}(?:token|password|secret|service[- ]key|risk[_ -]score)",
    r"(?:acct-token|service-key|root-password)",
    r"attacker\.[a-z]{2,}",
    r"assistant instruction",
    r"when you summarize.+(?:instruct|conclude)",
)


class HMACSigner:
    """Integrity and origin authentication for artifact envelopes.

    HMAC does not assert that content is safe; it only detects envelope tampering.
    Production deployments should load the secret from a managed key service.
    """

    def __init__(self, secret: bytes, key_id: str = "local-hmac-v1") -> None:
        if len(secret) < 32:
            raise ValueError("HMAC secret must contain at least 32 bytes")
        self._secret = secret
        self.key_id = key_id

    def sign(self, envelope: ArtifactEnvelope) -> ArtifactEnvelope:
        signed = envelope.model_copy(update={"key_id": self.key_id, "signature": ""})
        signature = hmac.new(
            self._secret,
            signed.signing_payload(),
            hashlib.sha256,
        ).hexdigest()
        return signed.model_copy(update={"signature": signature})

    def verify(self, envelope: ArtifactEnvelope) -> bool:
        # The signature authenticates the stored content hash, so verification
        # must also bind that hash to the content currently in the envelope.
        # Otherwise an attacker could replace ``content`` while retaining the
        # original signed ``content_hash`` and signature.
        if not hmac.compare_digest(sha256_content(envelope.content), envelope.content_hash):
            return False
        if envelope.key_id != self.key_id:
            return False
        unsigned = envelope.model_copy(update={"signature": ""})
        expected = hmac.new(
            self._secret,
            unsigned.signing_payload(),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, envelope.signature)


class StaticInjectionScanner:
    def __init__(self, patterns: Iterable[str] = DEFAULT_INJECTION_PATTERNS) -> None:
        self._patterns = tuple(re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in patterns)

    def scan(self, content: str) -> ScanFinding:
        matches = [pattern.pattern for pattern in self._patterns if pattern.search(content)]
        score = min(1.0, len(matches) * 0.34)
        return ScanFinding(detector="static", score=score, matches=matches)


class SemanticHeuristicScanner:
    """Dependency-free semantic fallback with an interface replaceable by a classifier."""

    SUSPICIOUS_CONCEPTS = {
        "override",
        "instruction",
        "instructions",
        "secret",
        "password",
        "token",
        "acct-token",
        "service-key",
        "root-password",
        "risk_score",
        "credential",
        "admin",
        "approve",
        "waive",
        "execute",
        "curl",
    }

    def scan(self, content: str) -> ScanFinding:
        tokens = set(re.findall(r"[a-z0-9_-]+", content.lower()))
        matches = sorted(tokens & self.SUSPICIOUS_CONCEPTS)
        score = min(1.0, len(matches) / 4.0)
        return ScanFinding(detector="semantic-heuristic", score=score, matches=matches)


def sha256_content(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
