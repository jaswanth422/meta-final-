from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from context_breach_env.gateway.models import RAGChunk, RAGCorporaDocument, RAGCorpus
from context_breach_env.gateway.rag import RAGCorpusRegistry, RAGRetrievalError


class RAGSyncError(RuntimeError):
    """The authoritative source snapshot could not be loaded safely."""


class LocalSourceDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=128)
    document_id: str = Field(min_length=1, max_length=256)
    document_version: str = Field(min_length=1, max_length=128)
    content_path: str | None = Field(default=None, max_length=1_024)
    classification: Literal["public", "internal", "confidential", "restricted"]
    allowed_users: frozenset[str] = Field(default_factory=frozenset, max_length=1_000)
    allowed_groups: frozenset[str] = Field(default_factory=frozenset, max_length=1_000)
    acl_version: str = Field(min_length=1, max_length=128)
    deleted: bool = False

    @model_validator(mode="after")
    def validate_content_reference(self) -> LocalSourceDocument:
        if not self.deleted and not self.content_path:
            raise ValueError("active source documents require content_path")
        return self


class LocalSourceCorpus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    corpus_name: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    documents: list[LocalSourceDocument] = Field(default_factory=list, max_length=100_000)

    @model_validator(mode="after")
    def validate_document_identities(self) -> LocalSourceCorpus:
        identities = [
            (document.tenant_id, document.document_id)
            for document in self.documents
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("source document identities must be unique within a corpus")
        return self


class LocalACLManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(min_length=1, max_length=128)
    corpora: list[LocalSourceCorpus] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_corpus_names(self) -> LocalACLManifest:
        names = [corpus.corpus_name for corpus in self.corpora]
        if len(names) != len(set(names)):
            raise ValueError("source corpus names must be unique")
        return self


@dataclass(frozen=True)
class LocalManifestSnapshot:
    source_id: str
    corpora: RAGCorporaDocument
    fingerprint: str


@dataclass(frozen=True)
class RAGSyncReport:
    source_id: str
    changed_corpora: frozenset[str]
    total_documents: int
    total_chunks: int
    fingerprint: str


class LocalACLManifestConnector:
    """Build an authoritative ACL-bearing chunk snapshot from local files."""

    def __init__(
        self,
        manifest_path: str | Path,
        source_root: str | Path,
        *,
        chunk_size: int = 2_000,
        maximum_document_bytes: int = 5_000_000,
    ) -> None:
        if chunk_size < 128 or chunk_size > 100_000:
            raise ValueError("chunk_size must be between 128 and 100000")
        if maximum_document_bytes <= 0:
            raise ValueError("maximum_document_bytes must be positive")
        self.manifest_path = Path(manifest_path).expanduser().resolve()
        self.source_root = Path(source_root).expanduser().resolve()
        self.chunk_size = chunk_size
        self.maximum_document_bytes = maximum_document_bytes

    def load_snapshot(self) -> LocalManifestSnapshot:
        try:
            root = self.source_root.resolve(strict=True)
            if not root.is_dir():
                raise RAGSyncError("RAG source root is not a directory")
            payload = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            manifest = LocalACLManifest.model_validate(payload)
            corpora: list[RAGCorpus] = []
            for source_corpus in manifest.corpora:
                chunks: list[RAGChunk] = []
                for document in source_corpus.documents:
                    if document.deleted:
                        continue
                    content = self._read_content(root, str(document.content_path))
                    chunks.extend(self._derive_chunks(document, content))
                corpora.append(
                    RAGCorpus(corpus_name=source_corpus.corpus_name, chunks=chunks)
                )
            document = RAGCorporaDocument(corpora=corpora)
            fingerprint = hashlib.sha256(
                document.model_dump_json().encode("utf-8")
            ).hexdigest()
            return LocalManifestSnapshot(
                source_id=manifest.source_id,
                corpora=document,
                fingerprint=fingerprint,
            )
        except RAGSyncError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError, ValidationError) as error:
            raise RAGSyncError("failed to load authoritative RAG ACL manifest") from error

    def sync(self, registry: RAGCorpusRegistry) -> RAGSyncReport:
        snapshot = self.load_snapshot()
        names = frozenset(corpus.corpus_name for corpus in snapshot.corpora.corpora)
        changed = registry.replace_corpora(snapshot.corpora, replace_names=names)
        document_count = sum(
            len({(chunk.tenant_id, chunk.document_id) for chunk in corpus.chunks})
            for corpus in snapshot.corpora.corpora
        )
        return RAGSyncReport(
            source_id=snapshot.source_id,
            changed_corpora=changed,
            total_documents=document_count,
            total_chunks=sum(len(corpus.chunks) for corpus in snapshot.corpora.corpora),
            fingerprint=snapshot.fingerprint,
        )

    def _read_content(self, root: Path, relative_path: str) -> str:
        path = Path(relative_path)
        if path.is_absolute():
            raise RAGSyncError("source content paths must be relative")
        try:
            resolved = (root / path).resolve(strict=True)
        except OSError as error:
            raise RAGSyncError("source content file is unavailable") from error
        if not resolved.is_relative_to(root) or not resolved.is_file():
            raise RAGSyncError("source content path escapes the configured root")
        if resolved.stat().st_size > self.maximum_document_bytes:
            raise RAGSyncError("source document exceeds maximum size")
        content = resolved.read_text(encoding="utf-8").strip()
        if not content:
            raise RAGSyncError("source documents cannot be empty")
        return content

    def _derive_chunks(
        self,
        document: LocalSourceDocument,
        content: str,
    ) -> list[RAGChunk]:
        content_chunks = _split_content(content, self.chunk_size)
        identity_hash = hashlib.sha256(
            f"{document.tenant_id}\0{document.document_id}".encode("utf-8")
        ).hexdigest()[:20]
        return [
            RAGChunk(
                tenant_id=document.tenant_id,
                document_id=document.document_id,
                document_version=document.document_version,
                chunk_id=f"{identity_hash}-{index:05d}",
                content=chunk,
                allowed_users=document.allowed_users,
                allowed_groups=document.allowed_groups,
                classification=document.classification,
                acl_version=document.acl_version,
            )
            for index, chunk in enumerate(content_chunks, start=1)
        ]


class LocalManifestRAGCorpusRegistry(RAGCorpusRegistry):
    """Refresh a local authoritative snapshot before each retrieval operation."""

    def __init__(self, connector: LocalACLManifestConnector) -> None:
        super().__init__()
        self.connector = connector
        self._source_fingerprint: str | None = None
        self._managed_names: frozenset[str] = frozenset()
        self._sync_lock = threading.Lock()
        self.refresh()

    def refresh(self) -> RAGSyncReport:
        with self._sync_lock:
            try:
                snapshot = self.connector.load_snapshot()
            except RAGSyncError as error:
                raise RAGRetrievalError("rag_acl_sync_unavailable") from error
            names = frozenset(
                corpus.corpus_name for corpus in snapshot.corpora.corpora
            )
            if snapshot.fingerprint == self._source_fingerprint:
                return RAGSyncReport(
                    source_id=snapshot.source_id,
                    changed_corpora=frozenset(),
                    total_documents=sum(
                        len({(chunk.tenant_id, chunk.document_id) for chunk in corpus.chunks})
                        for corpus in snapshot.corpora.corpora
                    ),
                    total_chunks=sum(
                        len(corpus.chunks) for corpus in snapshot.corpora.corpora
                    ),
                    fingerprint=snapshot.fingerprint,
                )
            replace_names = self._managed_names.union(names)
            changed = self.replace_corpora(
                snapshot.corpora,
                replace_names=replace_names,
            )
            self._managed_names = names
            self._source_fingerprint = snapshot.fingerprint
            return RAGSyncReport(
                source_id=snapshot.source_id,
                changed_corpora=changed,
                total_documents=sum(
                    len({(chunk.tenant_id, chunk.document_id) for chunk in corpus.chunks})
                    for corpus in snapshot.corpora.corpora
                ),
                total_chunks=sum(
                    len(corpus.chunks) for corpus in snapshot.corpora.corpora
                ),
                fingerprint=snapshot.fingerprint,
            )

    def chunks_with_revision(
        self,
        corpus_name: str,
    ) -> tuple[tuple[RAGChunk, ...], int]:
        self.refresh()
        return super().chunks_with_revision(corpus_name)

    def revision(self, corpus_name: str) -> int:
        self.refresh()
        return super().revision(corpus_name)


def _split_content(content: str, chunk_size: int) -> list[str]:
    paragraphs = [
        paragraph.strip()
        for paragraph in re.split(r"\n\s*\n", content)
        if paragraph.strip()
    ]
    chunks: list[str] = []
    current = ""
    for paragraph in paragraphs:
        pieces = [
            paragraph[index : index + chunk_size]
            for index in range(0, len(paragraph), chunk_size)
        ]
        for piece in pieces:
            candidate = f"{current}\n\n{piece}" if current else piece
            if len(candidate) <= chunk_size:
                current = candidate
            else:
                if current:
                    chunks.append(current)
                current = piece
    if current:
        chunks.append(current)
    return chunks
