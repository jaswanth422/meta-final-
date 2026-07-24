# Gateway request authentication

The authorization gateway uses an offline-capable HMAC request credential. A
server-owned key record binds each `key_id` to exactly one tenant, user, and
agent. The signature covers the complete authorization request, so changing the
intent, identity, tool, resource, arguments, or artifact IDs invalidates it.

This protocol is an integration MVP, not a replacement for workload identity or
OIDC. The current environment loader supports one active key; the underlying
authenticator accepts multiple key IDs for rotation.

## Required headers

Every `POST /v1/authorize` request must include:

- `X-Context-Key-Id`
- `X-Context-Issued-At` as Unix seconds
- `X-Context-Expires-At` as Unix seconds
- `X-Context-Nonce`, 16–128 URL-safe characters
- `X-Context-Signature`, lowercase HMAC-SHA256 hex

Credentials may live for at most 300 seconds by default. The server allows 30
seconds of future clock skew and consumes a valid nonce exactly once, including
when the authorization policy ultimately denies the request. With
`CONTEXT_BREACH_DATABASE_PATH` configured, consumption is atomic across local
workers and survives restarts.

## Canonical payload

Serialize the validated JSON body as UTF-8 JSON with:

- object keys sorted recursively;
- separators `,` and `:` with no additional whitespace;
- Unicode emitted directly rather than ASCII escaped.

Python equivalent:

```python
json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

Compute the SHA-256 hex digest of that canonical payload. Construct the signing
input as these newline-separated fields with no trailing newline:

```text
context-breach-hmac-v1
authorize
<key_id>
<issued_at>
<expires_at>
<nonce>
<canonical_payload_sha256>
```

`X-Context-Signature` is the lowercase hex digest of HMAC-SHA256 over that input.
`HMACRequestSigner` in `context_breach_env.gateway.auth` is the reference client
implementation.

Audit lookup uses the same construction with purpose `audit` and the canonical
payload `{"audit_id":"<audit-id>"}`. It requires a fresh nonce and only returns
records from the signing key's tenant.

MCP authorization uses purpose `mcp_authorize` and the canonical validated
`MCPAuthorizationRequest` body. Its signature covers the identity, intent, MCP server,
complete JSON-RPC `tools/call`, arguments, and artifact IDs. It uses the same expiry,
identity binding, and one-time nonce rules.

## Fail-closed behavior

The gateway rejects:

- missing or malformed authentication headers;
- unknown key IDs or invalid signatures;
- credentials that are expired, issued too far in the future, or valid for too long;
- reuse of a consumed key-ID/nonce pair;
- tenant, user, or agent values that differ from the key's bound identity.

## Remaining production work

SQLite now provides single-host durable nonce and audit state. Artifact
assessments remain process-local, and multi-host deployments require a shared
database such as PostgreSQL. Production deployments also need managed secret
storage and rotation, TLS termination, rate limiting, and preferably OIDC or
workload-identity verification at the ingress boundary.
