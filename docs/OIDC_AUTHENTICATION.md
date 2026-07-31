# OIDC/OAuth JWT access-token authentication

## Implemented boundary

The gateway accepts two mutually exclusive authentication mechanisms:

- the existing short-lived, purpose-bound HMAC request signature; or
- an `Authorization: Bearer <token>` JWT access token issued by one configured
  OAuth 2.0/OpenID Provider.

The bearer path is intended to replace client-supplied development identities
with signed tenant, user, and group claims. It validates the JWT through the
issuer's JWKS endpoint and then requires the request body's `tenant_id`,
`user_id`, and `agent_id` to match the trusted identity.

Use an **access token**, not an OpenID Connect ID token. The gateway is an API
resource server and requires API-specific scopes.

## Validation rules

The OIDC/OAuth authenticator:

- accepts only RS256;
- resolves the signing key through the fixed server-owned JWKS URL;
- validates signature, exact issuer, audience, expiration, issued-at, and
  required subject claims;
- derives tenant, user, and group values only from signed claims;
- obtains `agent_id` from server configuration rather than the request;
- limits claim sizes and rejects malformed group/scope types;
- requires an endpoint-specific scope;
- returns a sanitized `503 identity_provider_unavailable` when JWKS resolution
  fails;
- rejects requests containing both HMAC and bearer credentials.

The stable OIDC audit identity is a SHA-256 fingerprint of the exact `iss` and
`sub` pair. Raw access tokens are never placed in authorization or retrieval
audit records.

## Required scopes

| Operation | Required scope |
|---|---|
| `POST /v1/authorize` | `context:authorize` |
| `GET /v1/audit/{id}` | `context:audit:read` |
| `POST /v1/mcp/authorize` | `context:mcp:authorize` |
| `POST /v1/mcp/proxy` | `context:mcp:proxy` |
| `GET /v1/mcp/executions/{id}` | `context:mcp:audit:read` |
| `POST /v1/rag/search` | `context:rag:search` |
| `GET /v1/rag/retrievals/{id}` | `context:rag:audit:read` |

A token issued for search cannot be reused to execute an MCP tool or read an
audit. Identity-bound audit endpoints still return `404` when a valid caller
requests another user's record.

## Configuration

Copy the non-secret names from `config/oidc.example.env` into the deployment
environment:

```bash
export CONTEXT_BREACH_OIDC_ISSUER=https://identity.example.com/realms/company
export CONTEXT_BREACH_OIDC_AUDIENCE=context-breach-gateway
export CONTEXT_BREACH_OIDC_JWKS_URL=https://identity.example.com/realms/company/protocol/openid-connect/certs
export CONTEXT_BREACH_OIDC_AGENT_ID=research-agent
export CONTEXT_BREACH_OIDC_TENANT_CLAIM=tenant_id
export CONTEXT_BREACH_OIDC_USER_CLAIM=sub
export CONTEXT_BREACH_OIDC_GROUPS_CLAIM=groups
export CONTEXT_BREACH_OIDC_SCOPE_CLAIM=scope
```

If any required OIDC setting is present, all four required settings must be
present or startup fails. Issuer and JWKS URLs must use HTTPS. For a
loopback-only local provider, explicitly set
`CONTEXT_BREACH_OIDC_ALLOW_INSECURE_HTTP=true`; non-loopback HTTP remains
rejected.

HMAC and OIDC can be configured simultaneously during migration. An individual
request still must use exactly one mechanism.

## Identity-provider requirements

Configure the provider to issue an RS256 JWT access token whose:

- `iss` exactly matches `CONTEXT_BREACH_OIDC_ISSUER`;
- `aud` contains `CONTEXT_BREACH_OIDC_AUDIENCE`;
- `sub` identifies the employee or workload subject;
- tenant and group claims use the configured names;
- `scope` contains only the operations granted to that client/user;
- lifetime is short enough for the organization's revocation requirement.

The authorization policy must contain a grant for the resulting
tenant/user/agent tuple. For RAG, group claims are additionally matched against
the document chunk ACLs before ranking.

## Smoke request

Obtain an access token from the configured provider without printing or
committing it:

```bash
export CONTEXT_BREACH_OIDC_ACCESS_TOKEN='replace-with-short-lived-access-token'

python3 scripts/smoke_oidc_gateway.py \
  --base-url http://127.0.0.1:8081 \
  --mode rag \
  --tenant-id demo-tenant \
  --user-id analyst-1 \
  --agent-id research-agent

unset CONTEXT_BREACH_OIDC_ACCESS_TOKEN
```

The token needs `context:rag:search` for this example.

## Explicit limits

This is an identity-verification foundation, not a complete enterprise identity
deployment. It does not yet provide:

- automatic OIDC discovery or dynamic multi-issuer routing;
- interactive login, authorization-code exchange, or refresh-token handling;
- opaque-token introspection;
- immediate revocation of an already issued bearer token;
- DPoP or mTLS sender-constrained access tokens;
- automatic identity-provider group provisioning;
- workload identity propagation to downstream MCP servers;
- a distinct dynamically verified agent/workload claim—the current agent ID is
  fixed by trusted gateway configuration.

Bearer tokens are reusable until expiry, unlike the one-time HMAC credentials.
Use short access-token lifetimes, TLS, strict scopes, and the provider's
revocation controls. The next milestone remains source-document ACL
synchronization and revocation propagation through every derived RAG chunk and
cache.
