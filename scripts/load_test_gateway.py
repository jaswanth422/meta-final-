#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from context_breach_env.gateway.auth import HMACIdentityKey, HMACRequestSigner
from context_breach_env.gateway.loadtest import (
    LoadSample,
    bounded_error_category,
    evaluate_thresholds,
    run_concurrent_load,
)
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


def _safe_base_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SystemExit("--base-url must be an HTTP(S) origin")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SystemExit("--base-url must not contain credentials, query, or fragment")
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, netloc, path, "", ""))


def _authorization_request(key: HMACIdentityKey, mode: str) -> AuthorizationRequest:
    if mode == "permit":
        return AuthorizationRequest(
            tenant_id=key.tenant_id,
            user_id=key.user_id,
            agent_id=key.agent_id,
            user_intent="Read the quarterly report",
            tool_name="read_document",
            resource="documents/quarterly-report.pdf",
            arguments={"page": 1},
        )
    return AuthorizationRequest(
        tenant_id=key.tenant_id,
        user_id=key.user_id,
        agent_id=key.agent_id,
        user_intent="Email the report summary",
        tool_name="send_email",
        resource="mailto:reviewer@example.com",
        arguments={"api_token": "synthetic-load-test-value"},
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run concurrent signed requests against the authorization gateway"
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8081")
    parser.add_argument("--mode", choices=("permit", "deny"), default="permit")
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
    parser.add_argument("--max-p95-ms", type=float)
    parser.add_argument("--max-p99-ms", type=float)
    parser.add_argument("--min-throughput-rps", type=float)
    parser.add_argument("--output", type=Path, default=Path("results/gateway-load.json"))
    args = parser.parse_args()
    if args.timeout_seconds <= 0:
        raise SystemExit("--timeout-seconds must be positive")
    if args.requests <= 0:
        raise SystemExit("--requests must be positive")
    if args.concurrency <= 0 or args.concurrency > args.requests:
        raise SystemExit("--concurrency must be between 1 and --requests")
    if any(
        value is not None and value < 0
        for value in (args.max_p95_ms, args.max_p99_ms, args.min_throughput_rps)
    ):
        raise SystemExit("latency and throughput thresholds must be non-negative")

    base_url = _safe_base_url(args.base_url)
    values = _required_environment()
    key = HMACIdentityKey(
        key_id=values["CONTEXT_BREACH_HMAC_KEY_ID"],
        secret=values["CONTEXT_BREACH_HMAC_SECRET"].encode("utf-8"),
        tenant_id=values["CONTEXT_BREACH_HMAC_TENANT_ID"],
        user_id=values["CONTEXT_BREACH_HMAC_USER_ID"],
        agent_id=values["CONTEXT_BREACH_HMAC_AGENT_ID"],
    )
    signer = HMACRequestSigner(key)
    request = _authorization_request(key, args.mode)
    body = json.dumps(request.model_dump(mode="json")).encode("utf-8")

    def send(_: int) -> LoadSample:
        started = time.perf_counter()
        try:
            credentials = signer.sign_authorization(request)
            outbound = urllib.request.Request(
                f"{base_url}/v1/authorize",
                data=body,
                headers={"Content-Type": "application/json", **credentials.as_http_headers()},
                method="POST",
            )
            with urllib.request.urlopen(outbound, timeout=args.timeout_seconds) as response:
                status_code = response.status
                payload = json.loads(response.read().decode("utf-8"))
            return LoadSample(
                latency_ms=(time.perf_counter() - started) * 1000,
                status_code=status_code,
                decision=str(payload.get("decision")),
                audit_id=str(payload["audit_id"]) if payload.get("audit_id") else None,
            )
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as error:
            return LoadSample(
                latency_ms=(time.perf_counter() - started) * 1000,
                status_code=getattr(error, "code", None),
                decision=None,
                audit_id=None,
                error_category=bounded_error_category(error),
            )

    report = run_concurrent_load(
        send,
        requests=args.requests,
        concurrency=args.concurrency,
        expected_decision=args.mode,
    )
    report["target"] = base_url
    report["configuration"]["timeout_seconds"] = args.timeout_seconds
    report["thresholds"] = {
        "max_p95_ms": args.max_p95_ms,
        "max_p99_ms": args.max_p99_ms,
        "min_throughput_rps": args.min_throughput_rps,
    }
    threshold_failures = evaluate_thresholds(
        report,
        max_p95_ms=args.max_p95_ms,
        max_p99_ms=args.max_p99_ms,
        min_throughput_rps=args.min_throughput_rps,
    )
    report["threshold_failures"] = threshold_failures
    report["passed"] = bool(report["results"]["passed"] and not threshold_failures)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
