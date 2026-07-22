# Gateway reliability and load testing

The gateway includes a dependency-free HTTP load harness that sends concurrent,
fully signed authorization requests. Every request uses a unique nonce and must
produce the expected policy decision plus a unique durable audit ID. A run fails on
any HTTP error, unexpected decision, duplicate/missing audit ID, bounded transport
error, or configured latency/throughput threshold.

## Run the harness

Start a configured gateway with SQLite enabled, then provide the same untracked HMAC
identity values to the load-test terminal:

```bash
PYTHONPATH=. python scripts/load_test_gateway.py \
  --base-url http://127.0.0.1:8081 \
  --mode permit \
  --requests 200 \
  --concurrency 8 \
  --max-p95-ms 100 \
  --max-p99-ms 100 \
  --min-throughput-rps 200 \
  --output results/gateway-load.json
```

The script reads the five `CONTEXT_BREACH_HMAC_*` variables documented in
[`GATEWAY_AUTHENTICATION.md`](GATEWAY_AUTHENTICATION.md). The report never stores
their values, request bodies, exception messages, nonces, or audit IDs. It stores only
the safe target origin, configuration, aggregate correctness counts, bounded error
categories, throughput, and latency percentiles.

Thresholds are deployment-specific and optional. A report marked `passed` without
thresholds proves request-level correctness for that run, not production fitness.

## Failure and concurrency guarantees under test

The automated suite verifies:

- 60 requests across two tenant/user/agent identities remain isolated and create 60
  unique SQLite audit records under eight-way concurrency;
- 16 concurrent submissions of one signed credential produce exactly one success and
  15 `credential_replayed` responses;
- a nonce-store outage returns `503` and accepts no request; after recovery, the same
  previously unconsumed credential may complete exactly once;
- an audit-store outage returns `503` after authentication has consumed the nonce;
  retry therefore requires a fresh signed credential;
- metric output does not expose tenant IDs even during concurrent sessions;
- load reports aggregate unique audit counts without retaining audit identifiers.

These tests prove fail-closed behavior for the exercised process and SQLite failure
modes. They do not prove recovery from disk corruption, process kill during every
transaction boundary, full filesystem, kernel failure, or network partition.

## Local measurement — 2026-07-22

The tracked raw aggregate report is
[`results/gateway-reliability-local-2026-07-22.json`](../results/gateway-reliability-local-2026-07-22.json).
It was measured on arm64 macOS 26.5.1 with Python 3.14.2, FastAPI 0.123.10,
Uvicorn 0.40.0, one server worker, HTTP loopback, SQLite on a local temporary
filesystem, structured request logging enabled, and raw access logging disabled.
Each trial made 200 permitted requests and one durable audit write per request.

| Concurrency | Correct decisions | Unique audits | Errors | Throughput | p50 | p95 | p99 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 200/200 | 200 | 0 | 412.5 req/s | 2.17 ms | 3.60 ms | 6.76 ms |
| 8, trial 1 | 200/200 | 200 | 0 | 268.2 req/s | 3.70 ms | 74.84 ms | 532.67 ms |
| 8, trial 2 | 200/200 | 200 | 0 | 292.0 req/s | 3.35 ms | 41.53 ms | 515.64 ms |

The correctness result is good; the scale result is not. Eight-way concurrency caused
repeatable 500 ms-plus p99 latency and lower throughput than the sequential run because
each request performs serialized durable SQLite writes. This confirms SQLite is a
single-host development backend, not a credible strict-tail or multi-host SaaS store.
PostgreSQL plus a separately measured deployment is required before making production
latency or scale claims.

## Measurement limits

This is a small local development measurement, not an audited benchmark. It has no TLS,
reverse proxy, container limit, network latency, multi-process worker pool, sustained
soak period, mixed read/write traffic, large policy document, backup activity, disk
pressure, or host contention. Run repeated trials in the intended deployment and
publish the environment, raw aggregate reports, and predeclared gates before using the
numbers in a product claim.
