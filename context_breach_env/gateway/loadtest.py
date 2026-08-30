from __future__ import annotations

import math
import time
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from statistics import fmean
from typing import Any


@dataclass(frozen=True)
class LoadSample:
    latency_ms: float
    status_code: int | None
    decision: str | None
    audit_id: str | None
    error_category: str | None = None


def run_concurrent_load(
    send: Callable[[int], LoadSample],
    *,
    requests: int,
    concurrency: int,
    expected_decision: str,
    timer: Callable[[], float] = time.perf_counter,
) -> dict[str, Any]:
    if requests <= 0:
        raise ValueError("requests must be positive")
    if concurrency <= 0 or concurrency > requests:
        raise ValueError("concurrency must be between 1 and requests")
    if expected_decision not in {"permit", "deny", "require_review"}:
        raise ValueError("expected_decision is invalid")

    started = timer()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        samples = list(executor.map(send, range(requests)))
    elapsed_seconds = max(0.0, timer() - started)
    return summarize_load(
        samples,
        requests=requests,
        concurrency=concurrency,
        expected_decision=expected_decision,
        elapsed_seconds=elapsed_seconds,
    )


def summarize_load(
    samples: list[LoadSample],
    *,
    requests: int,
    concurrency: int,
    expected_decision: str,
    elapsed_seconds: float,
) -> dict[str, Any]:
    latencies = sorted(max(0.0, sample.latency_ms) for sample in samples)
    errors = Counter(sample.error_category for sample in samples if sample.error_category)
    http_successes = sum(sample.status_code == 200 for sample in samples)
    expected = sum(sample.decision == expected_decision for sample in samples)
    audit_ids = [sample.audit_id for sample in samples if sample.audit_id]
    unique_audits = len(set(audit_ids))
    successful = (
        len(samples) == requests
        and http_successes == requests
        and expected == requests
        and unique_audits == requests
        and not errors
    )

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "configuration": {
            "requests": requests,
            "concurrency": concurrency,
            "expected_decision": expected_decision,
        },
        "results": {
            "passed": successful,
            "completed": len(samples),
            "http_200": http_successes,
            "expected_decisions": expected,
            "unexpected_decisions": len(samples) - expected,
            "unique_audit_ids": unique_audits,
            "errors": dict(sorted((str(key), value) for key, value in errors.items())),
            "elapsed_seconds": round(max(0.0, elapsed_seconds), 6),
            "throughput_rps": round(len(samples) / elapsed_seconds, 3)
            if elapsed_seconds > 0
            else 0.0,
            "latency_ms": {
                "min": round(latencies[0], 3) if latencies else 0.0,
                "mean": round(fmean(latencies), 3) if latencies else 0.0,
                "p50": round(_percentile(latencies, 0.50), 3),
                "p95": round(_percentile(latencies, 0.95), 3),
                "p99": round(_percentile(latencies, 0.99), 3),
                "max": round(latencies[-1], 3) if latencies else 0.0,
            },
        },
    }


def bounded_error_category(error: BaseException) -> str:
    name = type(error).__name__
    allowed = {
        "ConnectionRefusedError": "connection_refused",
        "ConnectionResetError": "connection_reset",
        "HTTPError": "http_error",
        "TimeoutError": "timeout",
        "URLError": "url_error",
    }
    return allowed.get(name, "other")


def evaluate_thresholds(
    report: dict[str, Any],
    *,
    max_p95_ms: float | None = None,
    max_p99_ms: float | None = None,
    min_throughput_rps: float | None = None,
) -> list[str]:
    if any(
        value is not None and value < 0
        for value in (max_p95_ms, max_p99_ms, min_throughput_rps)
    ):
        raise ValueError("reliability thresholds must be non-negative")
    results = report["results"]
    failures: list[str] = []
    if max_p95_ms is not None and results["latency_ms"]["p95"] > max_p95_ms:
        failures.append("p95_latency_exceeded")
    if max_p99_ms is not None and results["latency_ms"]["p99"] > max_p99_ms:
        failures.append("p99_latency_exceeded")
    if min_throughput_rps is not None and results["throughput_rps"] < min_throughput_rps:
        failures.append("throughput_below_minimum")
    return failures


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    rank = max(0, math.ceil(fraction * len(values)) - 1)
    return values[rank]
