# Permission-aware RAG retrieval

## Implemented boundary

`POST /v1/rag/search` is a self-hosted retrieval foundation that prevents
unauthorized chunks from entering relevance ranking or model context. It combines
four independent controls:

1. either a purpose-separated, replay-resistant `rag_search` HMAC signature or
   an OIDC/OAuth bearer token with `context:rag:search`;
2. the existing `search_documents` tool and `rag://<corpus>` resource policy;
3. server-owned user/group claims matched against chunk ACL metadata before ranking;
4. result scanning and an append-only, content-free retrieval audit.

This is intentionally a lexical reference retriever. It proves where authorization
must occur; it is not presented as a production vector search engine or a new RAG
model.

## Trusted corpus format

Set `CONTEXT_BREACH_RAG_CORPUS_FILE` to a JSON file matching
`config/rag-corpus.example.json`. Every chunk must carry:

- `tenant_id`
- `document_id`, `document_version`, and unique `chunk_id`
- `classification`
- `allowed_users` and `allowed_groups`
- `acl_version`
- `content`

An authenticated user can read a non-public chunk only when the server-owned user
ID is in `allowed_users` or at least one trusted group claim is in
`allowed_groups`. A `public` chunk is visible to any authenticated identity in the
same tenant. The corpus file is trusted configuration: clients cannot submit ACLs,
groups, document contents, or an alternate storage endpoint in a search request.

`CONTEXT_BREACH_HMAC_GROUPS` is a comma-separated development-only source of group
claims. With OIDC enabled, groups come from a verified JWT claim instead. Neither
mechanism accepts groups in the request body.

## Local ACL synchronization

For an automatically refreshed local source, configure the manifest connector
instead of `CONTEXT_BREACH_RAG_CORPUS_FILE`:

```bash
export CONTEXT_BREACH_RAG_ACL_MANIFEST_FILE=config/rag-acl-manifest.example.json
export CONTEXT_BREACH_RAG_SOURCE_ROOT=config/rag-source-documents
```

The manifest is authoritative for every corpus it names. Each source document
provides its tenant, stable document ID, content version, relative content path,
classification, users/groups, and ACL version. The connector:

1. resolves content only below the configured root and rejects absolute paths,
   traversal, escaping symlinks, oversized files, invalid UTF-8, and empty files;
2. derives deterministic chunks and copies the source ACL and versions onto every
   chunk;
3. constructs the complete replacement snapshot before atomically publishing it;
4. increments the corpus revision and invalidates cached retrievals when content,
   versions, or permissions change;
5. excludes tombstoned or omitted documents from the new snapshot; and
6. reloads before retrieval and fails closed if the authoritative manifest or any
   referenced source file cannot be validated.

The search cache is keyed by the exact authenticated tenant, user, agent, group
set, query, corpus revision, and result limit. Before releasing content, retrieval
rechecks the revision and retries once; a second concurrent change fails closed.
This prevents a completed ACL refresh from leaving an old cached result accessible.

To revoke a document, either remove it from the corpus's `documents` list or set
`"deleted": true` and increase `acl_version`. To revoke a user or group, remove it
from the manifest and increase `acl_version`. The next search observes the new
snapshot without restarting the gateway.

## Local smoke run

Use a secret of at least 32 bytes. The example identity is a member of `finance`,
so it can retrieve the confidential finance chunk:

```bash
export CONTEXT_BREACH_POLICY_FILE=config/authorization-policy.example.json
export CONTEXT_BREACH_RAG_CORPUS_FILE=config/rag-corpus.example.json
export CONTEXT_BREACH_DATABASE_PATH=./var/day9-gateway.sqlite3
export CONTEXT_BREACH_HMAC_KEY_ID=local-demo-v1
export CONTEXT_BREACH_HMAC_SECRET="$(openssl rand -hex 32)"
export CONTEXT_BREACH_HMAC_TENANT_ID=demo-tenant
export CONTEXT_BREACH_HMAC_USER_ID=analyst-1
export CONTEXT_BREACH_HMAC_AGENT_ID=research-agent
export CONTEXT_BREACH_HMAC_GROUPS=employees,finance
context-breach-gateway
```

In a second terminal, export the same HMAC values and run:

```bash
python3 scripts/smoke_rag_gateway.py \
  --base-url http://127.0.0.1:8081 \
  --query "quarterly revenue forecast" \
  --expect-document finance-forecast
```

The response includes only authorized hits. A valid search that has no authorized
matches returns `status: succeeded` with an empty `results` list, without exposing
whether a matching restricted document exists.

## Request contract

The signed body contains:

```json
{
  "tenant_id": "demo-tenant",
  "user_id": "analyst-1",
  "agent_id": "research-agent",
  "user_intent": "Search authorized company documents",
  "corpus_name": "company-documents",
  "query": "quarterly revenue forecast",
  "top_k": 5
}
```

The gateway translates this into a separate policy request for the
`search_documents` tool and `rag://company-documents` resource. A normal
`authorize` or MCP signature cannot be replayed as a RAG search signature.

## Retrieval audits

Each executed search appends a `gateway_rag_retrieval_records` row. The record
contains the query SHA-256, returned document IDs and versions, chunk IDs, ACL
versions, decision link, identity, and status. It excludes the raw query and chunk
content.

`GET /v1/rag/retrievals/{retrieval_id}` requires a fresh `rag_retrieval`
signature and returns a record only to the exact tenant/user/agent identity that
created it. SQLite schema version 3 makes authorization, MCP execution, and RAG
retrieval audit tables append-only.

## Security tests

`tests/test_rag_gateway.py` verifies:

- group and direct-user ACL permits;
- cross-user and cross-tenant isolation;
- ACL filtering before ranking;
- rejection of client-supplied group claims;
- signature purpose separation and replay protection;
- fail-closed missing-corpus behavior;
- blocking of prompt injection found in an authorized result;
- privacy-limited, identity-bound, append-only retrieval audits.

## Explicit production gaps

This implementation does **not** provide:

- automatic OIDC discovery, interactive login, multi-issuer routing, or opaque
  access-token introspection;
- live identity-provider group resolution;
- SharePoint, Google Drive, or Confluence connectors and their change feeds;
- vector, hybrid, semantic, or reranker retrieval;
- scalable background ingestion, incremental indexing, or multi-source ownership
  of one corpus—the local manifest connector rebuilds its complete snapshot;
- semantic prompt-injection or DLP guarantees;
- network isolation preventing direct access to the corpus;
- authorization-aware generation or citation verification.

The local connector proves ACL inheritance, atomic replacement, tombstones,
revocation, cache invalidation, path confinement, and fail-closed source errors.
It is still a reference connector, not an enterprise content integration. The next
production milestone is one real provider adapter—SharePoint or Google Drive—with
incremental change tokens and revocation tests against the provider's actual ACLs.
