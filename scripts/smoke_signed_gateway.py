#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import urllib.request

from context_breach_env.gateway.auth import HMACIdentityKey, HMACRequestSigner
from context_breach_env.gateway.models import AuthorizationRequest


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
    parser = argparse.ArgumentParser(description="Send a signed authorization gateway smoke request")
    parser.add_argument("--base-url", default="http://127.0.0.1:8091")
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
    request = AuthorizationRequest(
        tenant_id=key.tenant_id,
        user_id=key.user_id,
        agent_id=key.agent_id,
        user_intent="Read the quarterly report" if args.mode == "permit" else "Email the report summary",
        tool_name="read_document" if args.mode == "permit" else "send_email",
        resource=(
            "documents/quarterly-report.pdf"
            if args.mode == "permit"
            else "mailto:reviewer@example.com"
        ),
        arguments={"page": 1} if args.mode == "permit" else {"api_token": "local-smoke-only"},
    )
    credentials = HMACRequestSigner(key).sign_authorization(request)
    body = json.dumps(request.model_dump(mode="json")).encode("utf-8")
    http_request = urllib.request.Request(
        f"{args.base_url.rstrip('/')}/v1/authorize",
        data=body,
        headers={"Content-Type": "application/json", **credentials.as_http_headers()},
        method="POST",
    )
    with urllib.request.urlopen(http_request, timeout=10) as response:
        result = json.loads(response.read().decode("utf-8"))

    print(json.dumps(result, indent=2))
    if result.get("decision") != args.mode:
        raise SystemExit(f"Expected decision={args.mode}, received {result.get('decision')}")


if __name__ == "__main__":
    main()
