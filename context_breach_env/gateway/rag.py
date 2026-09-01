from __future__ import annotations

import hashlib
import json
import re
import threading
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

from context_breach_env.gateway.models import (
    AuthorizationDecision,
    AuthorizationRequest,
    RAGChunk,
    RAGCorporaDocument,
    RAGRetrievalAuditRecord,
    RAGSearchHit,
    RAGSearchRequest,
    RAGSearchResponse,
)
from context_breach_env.gateway.proxy import MCPResultScanner
from context_breach_env.gateway.service import AuthorizationService
from context_breach_env.gateway.stores import RetrievalAuditStore

if TYPE_CHECKING:
    from context_breach_env.gateway.auth import AuthenticatedIdentity


TOKEN = re.compile(r"[A-Za-z0-9]+")


class RAGRetrievalError(RuntimeError):
    """Fail-closed configuration or retrieval failure."""


class RAGCorpusRegistry:
    """Server-owned, atomically replaceable corpora with per-corpus revisions."""

    def __init__(self, corpora: RAGCorporaDocument | None = None) -> None:
        document = corpora or RAGCorporaDocument()
        names = [corpus.corpus_name for corpus in document.corpora]
        if len(set(names)) != len(names):
            raise ValueError("RAG corpus names must be unique")

        resolved: dict[str, tuple[RAGChunk, ...]] = {}
        for corpus in document.corpora:
            chunk_keys = [
                (chunk.tenant_id, chunk.document_id, chunk.document_version, chunk.chunk_id)
                for chunk in corpus.chunks
            ]
            if len(set(chunk_keys)) != len(chunk_keys):
                raise ValueError(
                    f"RAG chunk identities must be unique in corpus {corpus.corpus_name}"
                )
            resolved[corpus.corpus_name] = tuple(
                chunk.model_copy(deep=True) for chunk in corpus.chunks
            )
        self._corpora = resolved
        self._revisions = {name: 1 for name in resolved}
        self._lock = threading.RLock()
        self._invalidators: list[Callable[[frozenset[str]], None]] = []

    @classmethod
    def from_file(cls, path: str | Path) -> RAGCorpusRegistry:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(RAGCorporaDocument.model_validate(payload))

    def chunks(self, corpus_name: str) -> tuple[RAGChunk, ...]:
        chunks, _ = self.chunks_with_revision(corpus_name)
        return chunks

    def chunks_with_revision(
        self,
        corpus_name: str,
    ) -> tuple[tuple[RAGChunk, ...], int]:
        """Return one coherent content/ACL snapshot and its revision."""
        with self._lock:
            chunks = self._corpora.get(corpus_name)
            if chunks is None:
                raise RAGRetrievalError("rag_corpus_unavailable")
            revision = self._revisions[corpus_name]
            return (
                tuple(chunk.model_copy(deep=True) for chunk in chunks),
                revision,
            )

    def revision(self, corpus_name: str) -> int:
        with self._lock:
            if corpus_name not in self._corpora:
                raise RAGRetrievalError("rag_corpus_unavailable")
            return self._revisions[corpus_name]

    def register_invalidator(
        self,
        callback: Callable[[frozenset[str]], None],
    ) -> None:
        with self._lock:
            self._invalidators.append(callback)

    def replace_corpora(
        self,
        document: RAGCorporaDocument,
        *,
        replace_names: frozenset[str] | None = None,
    ) -> frozenset[str]:
        """Atomically replace authoritative corpora and invalidate their caches."""
        incoming = RAGCorpusRegistry(document)
        names = replace_names or frozenset(incoming._corpora)
        if not set(incoming._corpora).issubset(names):
            raise ValueError("replace_names must include every incoming corpus")

        changed: set[str] = set()
        with self._lock:
            for name in names:
                replacement = incoming._corpora.get(name, ())
                if self._corpora.get(name) != replacement:
                    self._corpora[name] = tuple(
                        chunk.model_copy(deep=True) for chunk in replacement
                    )
                    self._revisions[name] = self._revisions.get(name, 0) + 1
                    changed.add(name)
            callbacks = tuple(self._invalidators)

        changed_names = frozenset(changed)
        if changed_names:
            for callback in callbacks:
                callback(changed_names)
        return changed_names


@dataclass
class PermissionAwareRAGRetriever:
    """Filters by trusted identity and ACLs before performing lexical retrieval."""

    authorization_service: AuthorizationService
    corpora: RAGCorpusRegistry
    retrieval_store: RetrievalAuditStore
    result_scanner: MCPResultScanner
    cache_max_entries: int = 1_024
    _cache: OrderedDict[tuple[object, ...], tuple[tuple[float, RAGChunk], ...]] = field(
        init=False,
        default_factory=OrderedDict,
        repr=False,
    )
    _cache_lock: threading.Lock = field(
        init=False,
        default_factory=threading.Lock,
        repr=False,
    )

    def __post_init__(self) -> None:
        if self.cache_max_entries < 0:
            raise ValueError("RAG cache size cannot be negative")
        self.corpora.register_invalidator(self._invalidate_corpora)

    def search(
        self,
        request: RAGSearchRequest,
        identity: AuthenticatedIdentity,
    ) -> RAGSearchResponse:
        snapshot = request.model_copy(deep=True)
        if (
            snapshot.tenant_id != identity.tenant_id
            or snapshot.user_id != identity.user_id
            or snapshot.agent_id != identity.agent_id
        ):
            raise RAGRetrievalError("rag_identity_mismatch")

        authorization = self.authorization_service.authorize(
            AuthorizationRequest(
                tenant_id=snapshot.tenant_id,
                user_id=snapshot.user_id,
                agent_id=snapshot.agent_id,
                user_intent=snapshot.user_intent,
                tool_name="search_documents",
                resource=f"rag://{snapshot.corpus_name}",
                arguments={"query": snapshot.query, "top_k": snapshot.top_k},
            )
        )
        if authorization.decision != AuthorizationDecision.PERMIT:
            return RAGSearchResponse(
                authorization=authorization,
                status="not_executed",
            )

        selected, corpus_revision = self._select(snapshot, identity)
        hits = [
            RAGSearchHit(
                document_id=chunk.document_id,
                document_version=chunk.document_version,
                chunk_id=chunk.chunk_id,
                content=chunk.content,
                classification=chunk.classification,
                relevance_score=score,
            )
            for score, chunk in selected
        ]

        retrieval_id = str(uuid4())
        safe, reason = self.result_scanner.scan(
            [hit.model_dump(mode="json") for hit in hits]
        )
        # A revocation may race an in-flight ranking or scan. Never release a result
        # produced from a snapshot that was superseded before response release.
        if self.corpora.revision(snapshot.corpus_name) != corpus_revision:
            selected, corpus_revision = self._select(snapshot, identity)
            hits = [
                RAGSearchHit(
                    document_id=chunk.document_id,
                    document_version=chunk.document_version,
                    chunk_id=chunk.chunk_id,
                    content=chunk.content,
                    classification=chunk.classification,
                    relevance_score=score,
                )
                for score, chunk in selected
            ]
            safe, reason = self.result_scanner.scan(
                [hit.model_dump(mode="json") for hit in hits]
            )
            if self.corpora.revision(snapshot.corpus_name) != corpus_revision:
                raise RAGRetrievalError("rag_corpus_changed_during_retrieval")
        if not safe:
            self._record(
                retrieval_id=retrieval_id,
                request=snapshot,
                authorization_audit_id=authorization.audit_id,
                selected=selected,
                status="response_blocked",
                failure_reason=reason,
            )
            return RAGSearchResponse(
                authorization=authorization,
                retrieval_id=retrieval_id,
                status="response_blocked",
            )

        self._record(
            retrieval_id=retrieval_id,
            request=snapshot,
            authorization_audit_id=authorization.audit_id,
            selected=selected,
            status="succeeded",
        )
        return RAGSearchResponse(
            authorization=authorization,
            retrieval_id=retrieval_id,
            status="succeeded",
            results=hits,
        )

    def _select(
        self,
        request: RAGSearchRequest,
        identity: AuthenticatedIdentity,
    ) -> tuple[list[tuple[float, RAGChunk]], int]:
        chunks, revision = self.corpora.chunks_with_revision(request.corpus_name)
        cache_key = (
            request.corpus_name,
            revision,
            identity.tenant_id,
            identity.user_id,
            identity.agent_id,
            tuple(sorted(identity.groups)),
            request.query,
            request.top_k,
        )
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached, revision

        # ACL filtering deliberately happens before relevance scoring. Unauthorized
        # content is never provided to the ranker or returned as result metadata.
        permitted_chunks = [
            chunk
            for chunk in chunks
            if chunk.tenant_id == identity.tenant_id
            and _identity_can_read(chunk, identity)
        ]
        query_tokens = _tokens(request.query)
        ranked: list[tuple[float, RAGChunk]] = []
        for chunk in permitted_chunks:
            score = _lexical_score(query_tokens, _tokens(chunk.content))
            if score > 0:
                ranked.append((score, chunk))
        ranked.sort(
            key=lambda item: (
                -item[0],
                item[1].document_id,
                item[1].document_version,
                item[1].chunk_id,
            )
        )
        selected = ranked[: request.top_k]
        # Do not insert results from a snapshot invalidated during ranking.
        if self.corpora.revision(request.corpus_name) == revision:
            self._cache_put(cache_key, selected)
        return selected, revision

    def _cache_get(
        self,
        key: tuple[object, ...],
    ) -> list[tuple[float, RAGChunk]] | None:
        if self.cache_max_entries == 0:
            return None
        with self._cache_lock:
            value = self._cache.get(key)
            if value is None:
                return None
            self._cache.move_to_end(key)
            return [(score, chunk.model_copy(deep=True)) for score, chunk in value]

    def _cache_put(
        self,
        key: tuple[object, ...],
        value: list[tuple[float, RAGChunk]],
    ) -> None:
        if self.cache_max_entries == 0:
            return
        copied = tuple(
            (score, chunk.model_copy(deep=True)) for score, chunk in value
        )
        with self._cache_lock:
            self._cache[key] = copied
            self._cache.move_to_end(key)
            while len(self._cache) > self.cache_max_entries:
                self._cache.popitem(last=False)

    def _invalidate_corpora(self, corpus_names: frozenset[str]) -> None:
        with self._cache_lock:
            stale_keys = [
                key for key in self._cache if str(key[0]) in corpus_names
            ]
            for key in stale_keys:
                del self._cache[key]

    def _record(
        self,
        *,
        retrieval_id: str,
        request: RAGSearchRequest,
        authorization_audit_id: str,
        selected: list[tuple[float, RAGChunk]],
        status: str,
        failure_reason: str | None = None,
    ) -> None:
        chunks = [chunk for _, chunk in selected]
        self.retrieval_store.append_retrieval(
            RAGRetrievalAuditRecord(
                retrieval_id=retrieval_id,
                authorization_audit_id=authorization_audit_id,
                tenant_id=request.tenant_id,
                user_id=request.user_id,
                agent_id=request.agent_id,
                corpus_name=request.corpus_name,
                query_sha256=hashlib.sha256(request.query.encode("utf-8")).hexdigest(),
                status=status,
                returned_document_ids=sorted({chunk.document_id for chunk in chunks}),
                returned_document_versions=sorted(
                    {chunk.document_version for chunk in chunks}
                ),
                returned_chunk_ids=[chunk.chunk_id for chunk in chunks],
                acl_versions=sorted({chunk.acl_version for chunk in chunks}),
                failure_reason=failure_reason,
            )
        )


def _identity_can_read(chunk: RAGChunk, identity: AuthenticatedIdentity) -> bool:
    if chunk.classification == "public":
        return True
    if identity.user_id in chunk.allowed_users:
        return True
    return bool(identity.groups.intersection(chunk.allowed_groups))


def _tokens(value: str) -> frozenset[str]:
    return frozenset(token.lower() for token in TOKEN.findall(value))


def _lexical_score(query: frozenset[str], content: frozenset[str]) -> float:
    if not query:
        return 0.0
    return len(query.intersection(content)) / len(query)
