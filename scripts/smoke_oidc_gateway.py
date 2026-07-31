#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

from context_breach_env.gateway.models import AuthorizationRequest, RAGSearchRequest


def _access_token() -> str:
    token = os.getenv("CONTEXT_BREACH_OIDC_ACCESS_TOKEN", "")
    if not token:
        raise SystemExit("CONTEXT_BREACH_OIDC_ACCESS_TOKEN is required")
    if any(character.isspace() for character in token):
        raise SystemExit("CONTEXT_BREACH_OIDC_ACCESS_TOKEN is malformed")
    return token


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Exercise the gateway with an externally issued JWT access token"
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8081")
    parser.add_argument("--mode", choices=("authorize", "rag"), default="rag")
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--user-id", required=True)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--corpus", default="company-documents")
    parser.add_argument("--query", default="quarterly revenue forecast")
    args = parser.parse_args()

    if args.mode == "authorize":
        path = "/v1/authorize"
        request = AuthorizationRequest(
            tenant_id=args.tenant_id,
            user_id=args.user_id,
            agent_id=args.agent_id,
            user_intent="Read an authorized company document",
            tool_name="read_document",
            resource="documents/quarterly-report.pdf",
        )
    else:
        path = "/v1/rag/search"
        request = RAGSearchRequest(
            tenant_id=args.tenant_id,
            user_id=args.user_id,
            agent_id=args.agent_id,
            user_intent="Search authorized company documents",
            corpus_name=args.corpus,
            query=args.query,
        )

    outbound = urllib.request.Request(
        f"{args.base_url.rstrip('/')}{path}",
        data=json.dumps(request.model_dump(mode="json")).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {_access_token()}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(outbound, timeout=15) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        raise SystemExit(f"Gateway returned HTTP {error.code}: {body}") from error

    print(json.dumps(result, indent=2))
    decision = (
        result.get("decision")
        if args.mode == "authorize"
        else result.get("authorization", {}).get("decision")
    )
    if decision != "permit":
        raise SystemExit(f"Expected permit; received {decision}")
    if args.mode == "rag" and result.get("status") != "succeeded":
        raise SystemExit(f"Expected succeeded; received {result.get('status')}")


if __name__ == "__main__":
    main()
