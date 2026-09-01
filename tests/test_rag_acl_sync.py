from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from context_breach_env.gateway.app import create_app
from context_breach_env.gateway.auth import (
    HMACIdentityKey,
    HMACRequestAuthenticator,
    HMACRequestSigner,
)
from context_breach_env.gateway.models import AuthorizationGrant, RAGSearchRequest
from context_breach_env.gateway.proxy import DefaultMCPResultScanner
from context_breach_env.gateway.rag import PermissionAwareRAGRetriever
from context_breach_env.gateway.rag_sync import (
    LocalACLManifestConnector,
    LocalManifestRAGCorpusRegistry,
    RAGSyncError,
)
from context_breach_env.gateway.service import AuthorizationService
from context_breach_env.gateway.stores import InMemoryGatewayStateStore


FINANCE_KEY = HMACIdentityKey(
    key_id="acl-sync-finance-v1",
    secret=b"acl-sync-finance-secret-at-least-32-bytes",
    tenant_id="tenant-1",
    user_id="alice",
    agent_id="research-agent",
    groups=frozenset({"finance"}),
)
ENGINEERING_KEY = HMACIdentityKey(
    key_id="acl-sync-engineering-v1",
    secret=b"acl-sync-engineering-secret-at-least-32-bytes",
    tenant_id="tenant-1",
    user_id="bob",
    agent_id="research-agent",
    groups=frozenset({"engineering"}),
)
OTHER_TENANT_KEY = HMACIdentityKey(
    key_id="acl-sync-other-tenant-v1",
    secret=b"acl-sync-other-tenant-secret-at-least-32-bytes",
    tenant_id="tenant-2",
    user_id="mallory",
    agent_id="research-agent",
    groups=frozenset({"finance"}),
)


def _document(
    *,
    tenant_id: str = "tenant-1",
    document_id: str = "finance-plan",
    document_version: str = "v1",
    content_path: str | None = "finance.txt",
    allowed_groups: list[str] | None = None,
    allowed_users: list[str] | None = None,
    acl_version: str = "acl-v1",
    deleted: bool = False,
) -> dict[str, object]:
    return {
        "tenant_id": tenant_id,
        "document_id": document_id,
        "document_version": document_version,
        "content_path": content_path,
        "classification": "confidential",
        "allowed_users": allowed_users or [],
        "allowed_groups": allowed_groups or ["finance"],
        "acl_version": acl_version,
        "deleted": deleted,
    }


def _write_manifest(path: Path, documents: list[dict[str, object]]) -> None:
    path.write_text(
        json.dumps(
            {
                "source_id": "local-company-files",
                "corpora": [
                    {
                        "corpus_name": "company-documents",
                        "documents": documents,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def _gateway(
    manifest: Path,
    source_root: Path,
) -> tuple[TestClient, dict[str, HMACRequestSigner], PermissionAwareRAGRetriever]:
    keys = [FINANCE_KEY, ENGINEERING_KEY, OTHER_TENANT_KEY]
    store = InMemoryGatewayStateStore()
    service = AuthorizationService(
        [
            AuthorizationGrant(
                tenant_id=key.tenant_id,
                user_id=key.user_id,
                agent_id=key.agent_id,
                allowed_tools={"search_documents"},
                resource_patterns=("rag://company-documents",),
            )
            for key in keys
        ],
        audit_store=store,
    )
    registry = LocalManifestRAGCorpusRegistry(
        LocalACLManifestConnector(manifest, source_root, chunk_size=128)
    )
    retriever = PermissionAwareRAGRetriever(
        authorization_service=service,
        corpora=registry,
        retrieval_store=store,
        result_scanner=DefaultMCPResultScanner(),
    )
    application = create_app(
        service,
        HMACRequestAuthenticator(keys, nonce_store=store),
        state_store=store,
        rag_retriever=retriever,
    )
    return (
        TestClient(application),
        {key.key_id: HMACRequestSigner(key) for key in keys},
        retriever,
    )


def _search(
    client: TestClient,
    signer: HMACRequestSigner,
    key: HMACIdentityKey,
    query: str = "quarterly forecast",
):
    request = RAGSearchRequest(
        tenant_id=key.tenant_id,
        user_id=key.user_id,
        agent_id=key.agent_id,
        user_intent="Search authorized company documents",
        corpus_name="company-documents",
        query=query,
        top_k=20,
    )
    credentials = signer.sign_rag_search(request)
    return client.post(
        "/v1/rag/search",
        json=request.model_dump(mode="json"),
        headers=credentials.as_http_headers(),
    )


def test_connector_derives_acl_on_every_chunk(tmp_path: Path) -> None:
    content = "Quarterly forecast. " * 40
    (tmp_path / "finance.txt").write_text(content, encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    _write_manifest(manifest, [_document(acl_version="acl-finance-v7")])

    snapshot = LocalACLManifestConnector(
        manifest,
        tmp_path,
        chunk_size=128,
    ).load_snapshot()

    chunks = snapshot.corpora.corpora[0].chunks
    assert len(chunks) > 1
    assert {chunk.allowed_groups for chunk in chunks} == {frozenset({"finance"})}
    assert {chunk.acl_version for chunk in chunks} == {"acl-finance-v7"}
    assert {chunk.document_version for chunk in chunks} == {"v1"}
    assert len({chunk.chunk_id for chunk in chunks}) == len(chunks)


def test_acl_revocation_removes_cached_results_before_next_response(
    tmp_path: Path,
) -> None:
    (tmp_path / "finance.txt").write_text(
        "Quarterly forecast contains the private operating margin.",
        encoding="utf-8",
    )
    manifest = tmp_path / "manifest.json"
    _write_manifest(manifest, [_document()])
    client, signers, retriever = _gateway(manifest, tmp_path)

    permitted = _search(client, signers[FINANCE_KEY.key_id], FINANCE_KEY)
    assert [hit["document_id"] for hit in permitted.json()["results"]] == [
        "finance-plan"
    ]
    assert retriever._cache

    _write_manifest(
        manifest,
        [_document(allowed_groups=["legal"], acl_version="acl-v2")],
    )
    revoked = _search(client, signers[FINANCE_KEY.key_id], FINANCE_KEY)

    assert revoked.status_code == 200
    assert revoked.json()["results"] == []
    assert "operating margin" not in revoked.text
    assert all(
        "operating margin" not in chunk.content
        for entries in retriever._cache.values()
        for _, chunk in entries
    )


def test_tombstone_removes_every_derived_chunk(tmp_path: Path) -> None:
    (tmp_path / "finance.txt").write_text(
        ("Quarterly forecast section. " * 40),
        encoding="utf-8",
    )
    manifest = tmp_path / "manifest.json"
    _write_manifest(manifest, [_document()])
    client, signers, _ = _gateway(manifest, tmp_path)
    assert len(
        _search(client, signers[FINANCE_KEY.key_id], FINANCE_KEY).json()["results"]
    ) > 1

    _write_manifest(
        manifest,
        [_document(content_path=None, acl_version="acl-v2", deleted=True)],
    )
    response = _search(client, signers[FINANCE_KEY.key_id], FINANCE_KEY)

    assert response.status_code == 200
    assert response.json()["results"] == []


def test_cross_tenant_group_match_never_releases_document(tmp_path: Path) -> None:
    (tmp_path / "finance.txt").write_text(
        "Quarterly forecast belongs only to tenant one.",
        encoding="utf-8",
    )
    manifest = tmp_path / "manifest.json"
    _write_manifest(manifest, [_document()])
    client, signers, _ = _gateway(manifest, tmp_path)

    response = _search(
        client,
        signers[OTHER_TENANT_KEY.key_id],
        OTHER_TENANT_KEY,
    )

    assert response.status_code == 200
    assert response.json()["results"] == []
    assert "tenant one" not in response.text


def test_invalid_source_update_fails_closed_instead_of_serving_stale_acl(
    tmp_path: Path,
) -> None:
    (tmp_path / "finance.txt").write_text(
        "Quarterly forecast contains confidential numbers.",
        encoding="utf-8",
    )
    manifest = tmp_path / "manifest.json"
    _write_manifest(manifest, [_document()])
    client, signers, _ = _gateway(manifest, tmp_path)
    assert _search(
        client,
        signers[FINANCE_KEY.key_id],
        FINANCE_KEY,
    ).status_code == 200

    manifest.write_text("{broken", encoding="utf-8")
    response = _search(client, signers[FINANCE_KEY.key_id], FINANCE_KEY)

    assert response.status_code == 503
    assert response.json() == {"detail": "rag_retrieval_unavailable"}
    assert "confidential numbers" not in response.text


def test_connector_rejects_paths_outside_source_root(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    _write_manifest(manifest, [_document(content_path="../outside.txt")])

    with pytest.raises(RAGSyncError, match="escapes"):
        LocalACLManifestConnector(manifest, source_root).load_snapshot()


def test_document_content_and_version_update_atomically(tmp_path: Path) -> None:
    content = tmp_path / "finance.txt"
    content.write_text("Old quarterly forecast value.", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    _write_manifest(manifest, [_document()])
    registry = LocalManifestRAGCorpusRegistry(
        LocalACLManifestConnector(manifest, tmp_path)
    )
    old_chunks, old_revision = registry.chunks_with_revision("company-documents")

    content.write_text("New quarterly forecast value.", encoding="utf-8")
    _write_manifest(
        manifest,
        [_document(document_version="v2", acl_version="acl-v2")],
    )
    new_chunks, new_revision = registry.chunks_with_revision("company-documents")

    assert new_revision > old_revision
    assert {chunk.document_version for chunk in new_chunks} == {"v2"}
    assert {chunk.acl_version for chunk in new_chunks} == {"acl-v2"}
    assert "Old" in old_chunks[0].content
    assert all("Old" not in chunk.content for chunk in new_chunks)
