# MCP tool-call interception

The gateway can authorize MCP JSON-RPC `tools/call` requests before a client invokes
the downstream tool. The integration uses server-owned bindings to translate an MCP
server/tool pair and one designated argument into the existing deterministic identity,
tool, resource, provenance, and sensitive-data policy engine.

This is an authorization adapter and reference execution guard. It is not yet a
transparent MCP proxy.

## Configure server-owned bindings

Bindings live beside identity grants in the trusted policy document:

```json
{
  "grants": [
    {
      "tenant_id": "demo-tenant",
      "user_id": "analyst-1",
      "agent_id": "research-agent",
      "allowed_tools": ["read_document"],
      "review_tools": ["send_email"],
      "resource_patterns": ["documents/*", "mailto:*"]
    }
  ],
  "mcp_bindings": [
    {
      "server_name": "filesystem",
      "mcp_tool_name": "read_document",
      "policy_tool_name": "read_document",
      "resource_argument": "path",
      "resource_kind": "path",
      "resource_prefix": "documents"
    }
  ]
}
```

The client cannot choose `policy_tool_name`, `resource_argument`, resource kind, or
prefix. Duplicate bindings and unknown policy fields fail application startup.

Supported resource derivations are deliberately narrow:

- `path`: exact canonical relative POSIX path; rejects absolute paths, traversal,
  alternate separators, query/fragment syntax, percent encoding, and control bytes;
- `url`: HTTP(S) URL with a hostname; rejects user information, query strings,
  fragments, and other schemes;
- `email`: one conservative mailbox value, converted to `mailto:<address>`.

Only top-level MCP arguments can be designated as the resource in this version.

## Signed authorization request

Send `POST /v1/mcp/authorize` with the same five HMAC headers used by
`POST /v1/authorize`. The body is strict: unknown fields, non-`2.0` JSON-RPC versions,
and methods other than `tools/call` are rejected.

```json
{
  "tenant_id": "demo-tenant",
  "user_id": "analyst-1",
  "agent_id": "research-agent",
  "user_intent": "Read the quarterly report",
  "server_name": "filesystem",
  "call": {
    "jsonrpc": "2.0",
    "id": "call-1",
    "method": "tools/call",
    "params": {
      "name": "read_document",
      "arguments": {"path": "quarterly-report.pdf", "page": 1}
    }
  },
  "artifact_ids": []
}
```

The HMAC purpose is `mcp_authorize`, and the signature covers the complete validated
body. Identity remains bound to the signing key, and the nonce is consumed exactly
once. Unknown tools and invalid resources produce durable, sanitized denial audits;
attacker-controlled tool names and argument names are excluded from those records.

## Execute only after permit

`context_breach_env.gateway.mcp.execute_if_permitted` is the reference client guard.
It takes a deep snapshot, authorizes a separate copy, invokes the supplied downstream
executor exactly once only for `permit`, and returns without execution for `deny` or
`require_review`. The snapshot prevents request mutation between check and use.

The included smoke client exercises both paths:

```bash
PYTHONPATH=. python scripts/smoke_mcp_gateway.py \
  --base-url http://127.0.0.1:8081 --mode permit

PYTHONPATH=. python scripts/smoke_mcp_gateway.py \
  --base-url http://127.0.0.1:8081 --mode deny
```

## Security boundary and remaining work

The endpoint does not stop a compromised or incorrectly configured client from calling
an MCP server directly. A real deployment must place MCP server network access and
credentials behind an enforcement proxy or workload boundary so bypass is impossible.

This version does not proxy MCP initialization, capability negotiation, tool listing,
notifications, streaming, cancellation, or downstream responses. It does not propagate
OAuth/workload identity to MCP servers, attest tool servers, scan tool results, bind a
permit cryptographically to one downstream execution, or record downstream success.
Policy configuration, the gateway process, and the client-side execution guard remain
trusted. Those gaps must be closed before claiming complete MCP containment.
