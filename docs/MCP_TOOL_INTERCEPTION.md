# MCP tool-call interception

The gateway can authorize MCP JSON-RPC `tools/call` requests before a client invokes
the downstream tool. The integration uses server-owned bindings to translate an MCP
server/tool pair and one designated argument into the existing deterministic identity,
tool, resource, provenance, and sensitive-data policy engine.

The repository now has two paths:

- `/v1/mcp/authorize` is an authorization-only adapter.
- `/v1/mcp/proxy` is a server-side `tools/call` execution foundation with fixed
  downstream targets, result scanning, and execution audits.

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

## Server-side proxy execution

Configure downstream MCP servers in a trusted file rather than accepting a URL or
credential from the caller:

```bash
export CONTEXT_BREACH_MCP_DOWNSTREAMS_FILE=config/mcp-downstreams.example.json
export FILESYSTEM_MCP_BEARER_TOKEN="$(openssl rand -hex 32)"
```

Each server definition fixes the `server_name`, endpoint, timeout, maximum response
size, and optional environment-variable name containing its bearer token. HTTPS is
required except when `allow_loopback_http` is explicitly enabled for a loopback
development server.

`POST /v1/mcp/proxy` requires credentials signed for the separate `mcp_proxy`
purpose. An `mcp_authorize` signature is rejected, preventing an authorize-only
credential from being upgraded into execution authority. The proxy:

1. deep-copies and authorizes the signed request;
2. refuses to call downstream for `deny` or `require_review`;
3. sends the original JSON-RPC `tools/call` to the configured fixed endpoint;
4. validates the JSON-RPC version, ID, and result/error shape;
5. blocks oversized, non-JSON, secret-bearing, or injection-bearing results; and
6. appends an execution record containing status and a result hash, never raw output.

Signed, identity-bound execution records are available at
`GET /v1/mcp/executions/{execution_id}`.

With the gateway and a compatible downstream MCP server running, exercise the path:

```bash
PYTHONPATH=. python scripts/smoke_mcp_proxy.py \
  --base-url http://127.0.0.1:8081 --mode permit

PYTHONPATH=. python scripts/smoke_mcp_proxy.py \
  --base-url http://127.0.0.1:8081 --mode deny
```

## Security boundary and remaining work

The proxy keeps the configured downstream URL and credential out of the client
request. This becomes non-bypassable only when deployment networking prevents the
agent workload from reaching the MCP server directly and only the proxy possesses
the downstream credential.

This version does not proxy MCP initialization, capability negotiation, tool listing,
notifications, Streamable HTTP/SSE, or cancellation. It does not yet propagate
OAuth/workload identity, attest tool servers, provide per-tool result policies, or
create an OS-level workload boundary. Policy configuration, the gateway process,
downstream configuration, and deployment network remain trusted. Those gaps must be
closed before claiming complete MCP containment.
