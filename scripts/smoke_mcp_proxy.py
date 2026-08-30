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
    parser = argparse.ArgumentParser(
        description="Send a signed MCP request through the server-side execution proxy"
    )
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
        path = "quarterly-report.pdf"
    else:
        path = "private/payroll.pdf"
    request = MCPAuthorizationRequest.model_validate(
        {
            "tenant_id": key.tenant_id,
            "user_id": key.user_id,
            "agent_id": key.agent_id,
            "user_intent": "Read a document through the MCP execution proxy",
            "server_name": "filesystem",
            "call": {
                "jsonrpc": "2.0",
                "id": "proxy-smoke-call-1",
                "method": "tools/call",
                "params": {
                    "name": "read_document",
                    "arguments": {"path": path},
                },
            },
        }
    )
    credentials = HMACRequestSigner(key).sign_mcp_proxy(request)
    outbound = urllib.request.Request(
        f"{args.base_url.rstrip('/')}/v1/mcp/proxy",
        data=json.dumps(request.model_dump(mode="json")).encode("utf-8"),
        headers={"Content-Type": "application/json", **credentials.as_http_headers()},
        method="POST",
    )
    with urllib.request.urlopen(outbound, timeout=15) as response:
        result = json.loads(response.read().decode("utf-8"))

    print(json.dumps(result, indent=2))
    expected_decision = "permit" if args.mode == "permit" else "deny"
    if result.get("authorization", {}).get("decision") != expected_decision:
        raise SystemExit(
            f"Expected decision={expected_decision}, "
            f"received {result.get('authorization', {}).get('decision')}"
        )
    expected_status = "succeeded" if args.mode == "permit" else "not_executed"
    if result.get("status") != expected_status:
        raise SystemExit(
            f"Expected status={expected_status}, received {result.get('status')}"
        )


if __name__ == "__main__":
    main()
