from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from context_breach_env.gateway.auth import AuthenticatedIdentity
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


TOKEN = re.compile(r"[A-Za-z0-9]+")


class RAGRetrievalError(RuntimeError):
    """Fail-closed configuration or retrieval failure."""


class RAGCorpusRegistry:
    """Immutable, server-owned corpora with ACL metadata on every chunk."""

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

    @classmethod
    def from_file(cls, path: str | Path) -> RAGCorpusRegistry:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(RAGCorporaDocument.model_validate(payload))

    def chunks(self, corpus_name: str) -> tuple[RAGChunk, ...]:
        chunks = self._corpora.get(corpus_name)
        if chunks is None:
            raise RAGRetrievalError("rag_corpus_unavailable")
        return tuple(chunk.model_copy(deep=True) for chunk in chunks)


@dataclass(frozen=True)
class PermissionAwareRAGRetriever:
    """Filters by trusted identity and ACLs before performing lexical retrieval."""

    authorization_service: AuthorizationService
    corpora: RAGCorpusRegistry
    retrieval_store: RetrievalAuditStore
    result_scanner: MCPResultScanner

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

        # ACL filtering deliberately happens before relevance scoring. Unauthorized
        # content is never provided to the ranker or returned as result metadata.
        permitted_chunks = [
            chunk
            for chunk in self.corpora.chunks(snapshot.corpus_name)
            if chunk.tenant_id == identity.tenant_id
            and _identity_can_read(chunk, identity)
        ]
        query_tokens = _tokens(snapshot.query)
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
        selected = ranked[: snapshot.top_k]
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
