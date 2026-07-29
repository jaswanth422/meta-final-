# Permission-aware RAG retrieval

## Implemented boundary

`POST /v1/rag/search` is a self-hosted retrieval foundation that prevents
unauthorized chunks from entering relevance ranking or model context. It combines
four independent controls:

1. a purpose-separated, replay-resistant `rag_search` HMAC signature;
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
claims. It is loaded with the signing key on the server and is not accepted in the
request body.

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
contains the query SHA-256, returned document/chunk IDs, ACL versions, decision
link, identity, and status. It excludes the raw query and chunk content.

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

- OIDC, SAML, Entra ID, Okta, or Keycloak identity verification;
- live group resolution or source ACL synchronization;
- SharePoint, Google Drive, Confluence, or filesystem connectors;
- vector, hybrid, semantic, or reranker retrieval;
- revocation-driven cache invalidation;
- chunk derivation and ACL inheritance during ingestion;
- semantic prompt-injection or DLP guarantees;
- network isolation preventing direct access to the corpus;
- authorization-aware generation or citation verification.

The next production milestone is an OIDC identity adapter plus an ACL-sync
connector whose revocation tests prove that permission changes reach every derived
chunk and cache. Until that exists, the JSON corpus is a controlled security test
fixture, not an enterprise document system.
