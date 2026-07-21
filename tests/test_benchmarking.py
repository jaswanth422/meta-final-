from __future__ import annotations

import json

import pytest

from context_breach_env.benchmarking import BenchmarkCase, load_jsonl, percentile, run_benchmark


class MarkerDetector:
    name = "marker"

    def predict(self, text: str) -> bool:
        return "attack" in text


def test_benchmark_reports_confusion_matrix_and_latency() -> None:
    cases = [
        BenchmarkCase("a", "attack text", True),
        BenchmarkCase("b", "ordinary text", False),
    ]
    ticks = iter([0.0, 0.001, 0.001, 0.003])
    result = run_benchmark(cases, MarkerDetector(), warmup=0, timer=lambda: next(ticks))
    assert result["metrics"]["accuracy"] == 1.0
    assert result["metrics"]["tp"] == 1
    assert result["metrics"]["tn"] == 1
    assert result["latency_ms"]["p50"] == pytest.approx(1.5)


def test_load_jsonl_requires_boolean_labels_and_unique_ids(tmp_path) -> None:
    path = tmp_path / "data.jsonl"
    path.write_text(
        "\n".join(
            [
                json.dumps({"id": "same", "text": "one", "label": True}),
                json.dumps({"id": "same", "text": "two", "label": False}),
            ]
        )
    )
    with pytest.raises(ValueError, match="unique"):
        load_jsonl(path)

    path.write_text(json.dumps({"id": "one", "text": "text", "label": 1}))
    with pytest.raises(ValueError, match="boolean"):
        load_jsonl(path)


def test_percentile_interpolates() -> None:
    assert percentile([1.0, 2.0, 3.0], 0.5) == 2.0
