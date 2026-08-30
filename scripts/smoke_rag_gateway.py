#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import urllib.request

from context_breach_env.gateway.auth import HMACIdentityKey, HMACRequestSigner
from context_breach_env.gateway.models import RAGSearchRequest


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
        description="Send a signed permission-aware RAG search request"
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8081")
    parser.add_argument("--corpus", default="company-documents")
    parser.add_argument("--query", default="quarterly revenue forecast")
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--expect-document")
    parser.add_argument("--expect-empty", action="store_true")
    args = parser.parse_args()
    if args.expect_document and args.expect_empty:
        raise SystemExit("--expect-document and --expect-empty are mutually exclusive")

    values = _required_environment()
    key = HMACIdentityKey(
        key_id=values["CONTEXT_BREACH_HMAC_KEY_ID"],
        secret=values["CONTEXT_BREACH_HMAC_SECRET"].encode("utf-8"),
        tenant_id=values["CONTEXT_BREACH_HMAC_TENANT_ID"],
        user_id=values["CONTEXT_BREACH_HMAC_USER_ID"],
        agent_id=values["CONTEXT_BREACH_HMAC_AGENT_ID"],
    )
    request = RAGSearchRequest(
        tenant_id=key.tenant_id,
        user_id=key.user_id,
        agent_id=key.agent_id,
        user_intent="Search authorized company documents",
        corpus_name=args.corpus,
        query=args.query,
        top_k=args.top_k,
    )
    credentials = HMACRequestSigner(key).sign_rag_search(request)
    outbound = urllib.request.Request(
        f"{args.base_url.rstrip('/')}/v1/rag/search",
        data=json.dumps(request.model_dump(mode="json")).encode("utf-8"),
        headers={"Content-Type": "application/json", **credentials.as_http_headers()},
        method="POST",
    )
    with urllib.request.urlopen(outbound, timeout=15) as response:
        result = json.loads(response.read().decode("utf-8"))

    print(json.dumps(result, indent=2))
    if result.get("authorization", {}).get("decision") != "permit":
        raise SystemExit("RAG search was not authorized by the gateway policy")
    if result.get("status") != "succeeded":
        raise SystemExit(f"RAG search did not succeed: {result.get('status')}")

    document_ids = {
        hit.get("document_id")
        for hit in result.get("results", [])
        if isinstance(hit, dict)
    }
    if args.expect_document and args.expect_document not in document_ids:
        raise SystemExit(
            f"Expected document {args.expect_document!r}; received {sorted(document_ids)}"
        )
    if args.expect_empty and document_ids:
        raise SystemExit(f"Expected no authorized matches; received {sorted(document_ids)}")


if __name__ == "__main__":
    main()
