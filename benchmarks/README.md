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
