from __future__ import annotations

import hashlib
import json
import math
import platform
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import mean
from typing import Protocol

from context_breach_env.production.security import SemanticHeuristicScanner, StaticInjectionScanner


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    text: str
    is_injection: bool
    category: str = "unspecified"
    source: str = "unknown"


@dataclass(frozen=True)
class DetectorPrediction:
    is_injection: bool | None
    raw_output: str | None = None
    score: float | None = None


class Detector(Protocol):
    name: str

    def predict(self, text: str) -> bool | DetectorPrediction: ...


class HeuristicDetector:
    """The repository's current production fallback, exposed as a baseline."""

    name = "context-breach-heuristic"

    def __init__(self, threshold: float = 0.5) -> None:
        self.threshold = threshold
        self.static = StaticInjectionScanner()
        self.semantic = SemanticHeuristicScanner()

    def predict(self, text: str) -> DetectorPrediction:
        static = self.static.scan(text)
        semantic = self.semantic.scan(text)
        score = 0.4 * static.score + 0.6 * semantic.score
        return DetectorPrediction(
            is_injection=score >= self.threshold,
            raw_output=f"risk_score={score:.6f}",
            score=score,
        )


def load_jsonl(path: Path) -> list[BenchmarkCase]:
    cases: list[BenchmarkCase] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw_line.strip():
            continue
        item = json.loads(raw_line)
        missing = {"id", "text", "label"} - set(item)
        if missing:
            raise ValueError(f"{path}:{line_number}: missing fields {sorted(missing)}")
        label = item["label"]
        if not isinstance(label, bool):
            raise ValueError(f"{path}:{line_number}: label must be a JSON boolean")
        cases.append(
            BenchmarkCase(
                case_id=str(item["id"]),
                text=str(item["text"]),
                is_injection=label,
                category=str(item.get("category", "unspecified")),
                source=str(item.get("source", "unknown")),
            )
        )
    if not cases:
        raise ValueError(f"{path}: dataset is empty")
    if len({case.case_id for case in cases}) != len(cases):
        raise ValueError(f"{path}: case IDs must be unique")
    return cases


def dataset_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def percentile(values: Sequence[float], percentile_value: float) -> float:
    if not values:
        raise ValueError("cannot compute a percentile of an empty sequence")
    ordered = sorted(values)
    rank = (len(ordered) - 1) * percentile_value
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (rank - lower)


def _safe_ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _normalize_prediction(value: bool | DetectorPrediction) -> DetectorPrediction:
    if isinstance(value, DetectorPrediction):
        return value
    return DetectorPrediction(is_injection=bool(value))


def run_benchmark(
    cases: Sequence[BenchmarkCase],
    detector: Detector,
    *,
    warmup: int = 1,
    repeats: int = 1,
    hourly_cost_usd: float | None = None,
    timer: Callable[[], float] = time.perf_counter,
) -> dict[str, object]:
    if not cases:
        raise ValueError("at least one benchmark case is required")
    if warmup < 0 or repeats < 1:
        raise ValueError("warmup must be >= 0 and repeats must be >= 1")

    for _ in range(warmup):
        detector.predict(cases[0].text)

    latencies_ms: list[float] = []
    predictions: list[bool | None] = []
    case_results: list[dict[str, object]] = []
    for case in cases:
        repeated_predictions: list[DetectorPrediction] = []
        for _ in range(repeats):
            started = timer()
            prediction = _normalize_prediction(detector.predict(case.text))
            elapsed_ms = (timer() - started) * 1000.0
            latencies_ms.append(elapsed_ms)
            repeated_predictions.append(prediction)
        parsed = [prediction.is_injection for prediction in repeated_predictions if prediction.is_injection is not None]
        prediction = None if not parsed else sum(parsed) >= math.ceil(len(parsed) / 2)
        predictions.append(prediction)
        case_results.append(
            {
                **asdict(case),
                "prediction": prediction,
                "correct": prediction is not None and prediction == case.is_injection,
                "parse_failures": sum(item.is_injection is None for item in repeated_predictions),
                "raw_outputs": [item.raw_output for item in repeated_predictions],
                "scores": [item.score for item in repeated_predictions],
            }
        )

    tp = sum(prediction is True and case.is_injection for case, prediction in zip(cases, predictions))
    tn = sum(prediction is False and not case.is_injection for case, prediction in zip(cases, predictions))
    fp = sum(prediction is True and not case.is_injection for case, prediction in zip(cases, predictions))
    fn = sum(prediction is False and case.is_injection for case, prediction in zip(cases, predictions))
    parse_failure_cases = sum(prediction is None for prediction in predictions)
    parse_failure_samples = sum(
        int(result["parse_failures"])
        for result in case_results
    )
    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    elapsed_total_s = sum(latencies_ms) / 1000.0
    throughput = len(latencies_ms) / elapsed_total_s if elapsed_total_s else 0.0

    output: dict[str, object] = {
        "detector": detector.name,
        "cases": len(cases),
        "repeats": repeats,
        "metrics": {
            "accuracy": _safe_ratio(tp + tn, len(cases)),
            "precision": precision,
            "recall": recall,
            "f1": _safe_ratio(2 * precision * recall, precision + recall),
            "false_positive_rate": _safe_ratio(fp, fp + tn),
            "false_negative_rate": _safe_ratio(fn, fn + tp),
            "parse_failure_case_rate": _safe_ratio(parse_failure_cases, len(cases)),
            "parse_failure_sample_rate": _safe_ratio(parse_failure_samples, len(cases) * repeats),
            "evaluated_cases": len(cases) - parse_failure_cases,
            "parse_failure_cases": parse_failure_cases,
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
        },
        "latency_ms": {
            "mean": mean(latencies_ms),
            "p50": percentile(latencies_ms, 0.50),
            "p95": percentile(latencies_ms, 0.95),
            "p99": percentile(latencies_ms, 0.99),
            "samples": len(latencies_ms),
        },
        "throughput_requests_per_second": throughput,
        "runtime": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "processor": platform.processor(),
        },
        "results": case_results,
    }
    if hourly_cost_usd is not None:
        output["estimated_cost_usd_per_million"] = (
            hourly_cost_usd / (throughput * 3600.0) * 1_000_000 if throughput else None
        )
    return output
