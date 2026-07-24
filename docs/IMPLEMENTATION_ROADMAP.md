# Production implementation roadmap

## Phase 1 — Local security boundary

- [x] Signed artifact envelopes and tamper detection.
- [x] Rate, size, and duplicate ingestion gates.
- [x] Static and heuristic risk scoring.
- [x] Trust-tier permissions and strict tool schemas.
- [x] Idempotency and high-stakes dry-run gates.
- [x] Append-only audit and quarantine interfaces.
- [x] True training/holdout split.
- [x] Production CSI and confidence-bound utilities.

## Phase 2 — Durable service

- [ ] Add PostgreSQL audit/provenance adapter with migrations.
- [ ] Add object-lock quarantine adapter.
- [ ] Load HMAC/Ed25519 keys from a managed secret service and support rotation.
- [ ] Add authenticated administration and human-review APIs.
- [x] Add privacy-limited structured request logging, Prometheus metrics, and health checks.
- [ ] Add distributed tracing and production exporter integration.
- [x] Run local load, failure-recovery, replay-race, and concurrent-session tests.
- [ ] Run sustained multi-worker and PostgreSQL deployment load/chaos tests.
- [x] Add strict signed MCP `tools/call` authorization and execute-after-permit guard.
- [ ] Add a non-bypassable MCP proxy, workload identity propagation, and result scanning.

## Phase 3 — Model and benchmark validation

- [ ] Replace the heuristic semantic scanner with independently evaluated detectors.
- [ ] Expand to at least 500 frozen evaluation episodes.
- [ ] Add benign hard negatives, multilingual attacks, encoded attacks, memory
      poisoning, tool-result poisoning, and multi-turn attacks.
- [ ] Evaluate multiple current models and report repeated trials with confidence intervals.
- [ ] Compare against established agent-security benchmarks and managed guardrails.
- [ ] Publish raw traces, immutable dataset versions, and checkpoint hashes.

## Phase 4 — Controlled deployment

- [ ] Implement shadow inference with no execution authority.
- [ ] Add policy-controlled canary routing and automatic safety aborts.
- [ ] Add non-inferiority promotion gates with human approval.
- [ ] Add rollback automation and incident runbooks.
- [ ] Feed reviewed—not raw—production incidents into red-team generation.
