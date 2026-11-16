# MCP protocol decision

**Status:** draft for review
**Checked on:** 2026-11-16
**Applies to:** the planned standard MCP front door for Context Breach (see `docs/IMPLEMENTATION_ROADMAP.md`)

## Decision

1. **Use the official Python SDK, `mcp` 2.x, for all MCP protocol handling.** Pin `mcp>=2.3,<3`. Do not hand-write protocol messages.
2. **Serve every protocol revision the SDK supports**, from `2024-11-05` to `2026-07-28`. Do not pick one revision and reject the rest.
3. **Design the front door as stateless.** Keep no per-connection state. This is required by `2026-07-28` and also works for older clients that use the `initialize` handshake.
4. **Transport order:** stdio first, Streamable HTTP second. Do not implement the legacy HTTP+SSE transport.
5. **Feature scope:** tools only (`tools/list`, `tools/call`).

## Evidence

### Specification

Source: the `2026-07-28` changelog on modelcontextprotocol.io.

- `2026-07-28` is the current revision. The previous one is `2025-11-25`.
- It removes the `initialize` handshake and the `Mcp-Session-Id` header. Every request carries its protocol version and client capabilities in `_meta`.
- Servers must implement `server/discover`. Clients may use it as a backward-compatibility probe on stdio.
- Server-initiated requests are replaced by Multi Round-Trip Requests (MRTR): the server returns `resultType: "input_required"` and the client retries with the answers.
- Streamable HTTP POST requests must carry `Mcp-Method` and `Mcp-Name` headers.
- `tools/list` results must carry `ttlMs` and `cacheScope`.
- Deprecated, with a minimum twelve-month window: Roots, Sampling, Logging, the HTTP+SSE transport, and OAuth Dynamic Client Registration.

### Python SDK

Verified by installing it on 2026-11-16.

| Fact | Value | How it was checked |
| --- | --- | --- |
| Latest version on PyPI | `mcp` 2.3.0 | `pip index versions mcp` |
| Python requirement | `>=3.10` | Package metadata. Matches this project |
| Revisions supported | `2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25`, `2026-07-28` | `mcp_types.version.SUPPORTED_PROTOCOL_VERSIONS` |
| Handshake-era revisions | the first four above | `HANDSHAKE_PROTOCOL_VERSIONS` |
| Server API | `mcp.server.mcpserver` and `mcp.server.lowlevel` import; `mcp.server.fastmcp` does not exist in 2.x | Import test |
| Transports present | `mcp.server.stdio`, `mcp.client.stdio`, `mcp.client.streamable_http` | Import test |
| Compatibility with this project | No dependency conflicts; all 154 tests pass with `mcp` 2.3.0 installed | `pip check`, `pytest` |

From the SDK release notes (not re-tested here): v2 is a rewrite in which `FastMCP` became `MCPServer`; v1.x receives security fixes only; the tasks extension is not included; Streamable HTTP rejects request bodies over 4 MiB by default.

### Editors and agents

Read from each product's own documentation on 2026-11-16. **None of the four pages states which protocol revision the client speaks.**

| Client | Config file | Top-level key | Local stdio server | Remote server | Tool approval control |
| --- | --- | --- | --- | --- | --- |
| Kiro | `.kiro/settings/mcp.json` (workspace), `~/.kiro/settings/mcp.json` (user) | `mcpServers` | `command`, `args`, `env` | `url`, `headers`; OAuth, with Dynamic Client Registration as the default | `autoApprove`, `disabledTools` |
| VS Code | `.mcp.json` at the workspace root; `~/.copilot/mcp-config.json` for the user. The docs label `.vscode/mcp.json` as editor-managed and deprecated | `mcpServers` (`servers` in the older editor-managed files) | `type: "stdio"`, `command`, `args`, `env` | `type: "http"` for Streamable HTTP, `"sse"` for legacy | Approvals are separate from configuration |
| Cursor | `.cursor/mcp.json` (project), `~/.cursor/mcp.json` (global) | `mcpServers` | `command`, `args`, `env`, `envFile` | `url`, `headers`; stdio, SSE and Streamable HTTP all listed | Asks before using MCP tools by default |
| Cline | Settings JSON opened from the Cline panel; `~/.cline/data/settings/cline_mcp_settings.json` for the CLI | `mcpServers` | `command`, `args`, `env` | `url`, `type: "streamableHttp"` or `"sse"` | `autoApprove` |

All four can launch a local server from a command over stdio. That is the one transport common to every target.

## Why this decision

- **The clients' revisions are unknown.** Because no editor documents its revision, choosing a single revision risks building for one that a target client does not speak. The SDK serves both the handshake and the stateless model, so one implementation covers both.
- **Stateless is the safe common design.** A front door with no per-connection state satisfies `2026-07-28` and loses nothing for older clients. Context Breach already keeps its state in the policy, the store and the audit tables.
- **stdio is universal.** It is the only transport all four clients support identically, and it needs no network authentication on a developer's machine.
- **Deprecated features are skipped.** Building Roots, Sampling, Logging or HTTP+SSE now would be work with a removal date.

## Out of scope for now

| Item | Reason |
| --- | --- |
| Prompts and resources | The product controls tool calls; retrieval has its own endpoint |
| `subscriptions/listen` and list-changed notifications | Not needed until downstream tool lists change at runtime |
| Roots, Sampling, Logging, HTTP+SSE | Deprecated in `2026-07-28` |
| Tasks extension | Not in the SDK |
| MRTR and elicitation for approvals | A `require_review` decision will first be returned as an error that names the pending review. MRTR is the likely long-term mechanism and is revisited with the review flow |
| OAuth for a remote front door | The existing HMAC and OIDC authentication stay on the HTTP endpoints. A remote MCP front door is a later step |

## Consequences for the existing code

1. **Add `mcp>=2.3,<3` to `pyproject.toml`** when the front door is implemented, not before.
2. **The current downstream client in `gateway/proxy.py` is probably not compatible with real MCP servers.** It sends a bare JSON-RPC `tools/call` with `Accept: application/json`, with no handshake, no protocol-version field and no `Mcp-Method` or `Mcp-Name` headers. It has only been run against the project's own fixtures. Plan to replace its transport with the SDK's client while keeping the authorization, snapshot, scanning and audit logic.
3. **`tools/list` must be filtered by policy** and returned in a deterministic order, with the cache fields the SDK requires.
4. **Local stdio mode needs an identity decision**, because a stdio client cannot send an HMAC signature or a JWT. This is settled in the front-door design document.

## Open questions

Answer these on Day 5 by connecting real clients to a plain MCP server and saving the messages:

1. Which protocol revision do Kiro and VS Code actually send?
2. Do they call `server/discover` or `initialize` first?
3. How does each client display a tool-call error, and is an error clear enough for "denied" and "waiting for review"?
4. Does VS Code read `.mcp.json` by default, or only with the experimental setting its docs mention?

## Sources

- MCP specification changelog, revision 2026-07-28: https://modelcontextprotocol.io/specification/2026-07-28/changelog
- MCP Python SDK releases: https://github.com/modelcontextprotocol/python-sdk/releases
- VS Code MCP configuration reference: https://code.visualstudio.com/docs/agents/reference/mcp-configuration
- Kiro MCP configuration: https://kiro.dev/docs/mcp/configuration/
- Cursor MCP documentation: https://cursor.com/docs/mcp
- Cline, adding and configuring servers: https://docs.cline.bot/mcp/adding-and-configuring-servers
