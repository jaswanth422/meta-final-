#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import urllib.request

from context_breach_env.gateway.auth import HMACIdentityKey, HMACRequestSigner
from context_breach_env.gateway.models import MCPAuthorizationRequest


REQUIRED_ENV = (
    "CONTEXT_BREACH_HMAC_KEY_ID",
    "CONTEXT_BREACH_HMAC_SECRET",
    "CONTEXT_BREACH_HMAC_TENANT_ID",
    "CONTEXT_BREACH_HMAC_USER_ID",
    "CONTEXT_BREACH_HMAC_AGENT_ID",
)


def _required_environment() -> dict[str, str]:
    values = {name: os.getenv(name, "") for name in REQUIRED_ENV}
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise SystemExit(f"Missing required environment variables: {', '.join(missing)}")
    return values


def main() -> None:
    parser = argparse.ArgumentParser(description="Send a signed MCP tool authorization request")
    parser.add_argument("--base-url", default="http://127.0.0.1:8081")
    parser.add_argument("--mode", choices=("permit", "deny"), default="permit")
    args = parser.parse_args()

    values = _required_environment()
    key = HMACIdentityKey(
        key_id=values["CONTEXT_BREACH_HMAC_KEY_ID"],
        secret=values["CONTEXT_BREACH_HMAC_SECRET"].encode("utf-8"),
        tenant_id=values["CONTEXT_BREACH_HMAC_TENANT_ID"],
        user_id=values["CONTEXT_BREACH_HMAC_USER_ID"],
        agent_id=values["CONTEXT_BREACH_HMAC_AGENT_ID"],
    )
    if args.mode == "permit":
        server_name = "filesystem"
        tool_name = "read_document"
        arguments = {"path": "quarterly-report.pdf", "page": 1}
        intent = "Read the quarterly report"
    else:
        server_name = "mail"
        tool_name = "send"
        arguments = {
            "recipient": "reviewer@example.com",
            "api_token": "synthetic-smoke-value",
        }
        intent = "Email the report summary"

    request = MCPAuthorizationRequest.model_validate(
        {
            "tenant_id": key.tenant_id,
            "user_id": key.user_id,
            "agent_id": key.agent_id,
            "user_intent": intent,
            "server_name": server_name,
            "call": {
                "jsonrpc": "2.0",
                "id": "smoke-call-1",
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments},
            },
        }
    )
    credentials = HMACRequestSigner(key).sign_mcp_authorization(request)
    outbound = urllib.request.Request(
        f"{args.base_url.rstrip('/')}/v1/mcp/authorize",
        data=json.dumps(request.model_dump(mode="json")).encode("utf-8"),
        headers={"Content-Type": "application/json", **credentials.as_http_headers()},
        method="POST",
    )
    with urllib.request.urlopen(outbound, timeout=10) as response:
        result = json.loads(response.read().decode("utf-8"))

    print(json.dumps(result, indent=2))
    if result.get("decision") != args.mode:
        raise SystemExit(f"Expected decision={args.mode}, received {result.get('decision')}")


if __name__ == "__main__":
    main()
