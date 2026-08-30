# Benchmark input contract

`scripts/benchmark_detectors.py` consumes normalized JSONL. Keep downloaded
benchmark datasets outside Git unless their licenses permit redistribution, and
commit the source URL, version and SHA-256 with every published result.

Each line must contain:

```json
{"id":"unique-id","text":"content to inspect","label":true,"category":"direct-injection","source":"PINT"}
```

- `label=true` means prompt injection.
- `label=false` means benign content.
- `category` and `source` are optional but should be populated for real runs.

Run the repository baseline:

```bash
python scripts/benchmark_detectors.py \
  --dataset benchmarks/smoke.jsonl \
  --backend heuristic \
  --repeats 10 \
  --output results/heuristic-smoke.json
```

Run a local, network-disabled Qwen checkpoint:

```bash
python scripts/benchmark_detectors.py \
  --dataset /data/pint-normalized.jsonl \
  --backend qwen \
  --model /models/context-breach-qwen3-0.6b \
  --device cuda --offline \
  --repeats 10 --hourly-cost-usd 0.75 \
  --output results/qwen-pint.json
```

The cost field is derived from measured sequential throughput and the supplied
machine hourly price. It is not a production-capacity estimate; concurrency and
load testing must be reported separately.

For the LLM Guard comparison:

```bash
pip install llm-guard
python scripts/benchmark_detectors.py \
  --dataset benchmarks/smoke.jsonl \
  --backend llm-guard --repeats 10 \
  --output results/llm-guard-smoke.json
```

Qwen reports preserve every raw generated label and expose parse-failure rates.
Unparseable outputs are not silently converted into positive classifications.

## S-Labs development run (2026-07-21)

`slabs-dev-100.jsonl` is a deterministic development sample from the `test`
split of [S-Labs/prompt-injection-dataset](https://huggingface.co/datasets/S-Labs/prompt-injection-dataset),
which is published under the MIT license. It contains 50 injection examples and
50 benign hard negatives selected with seed `20260721`. The normalized file's
SHA-256 is `21d76dd0e6c554528596adc594d7a713a9c78198a72bf376412f6ca5322413e6`.

This is a development comparison, not a final held-out claim. The tracked
outputs are `results/{heuristic,qwen,llm-guard}-slabs-100.json`, with full
per-case disagreements in `results/detector-disagreements.json`. Do not train
or tune on these 100 cases; doing so would invalidate them as evaluation data.
