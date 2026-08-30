# Gateway observability

The authorization gateway emits privacy-limited JSON request logs and exposes a
Prometheus-compatible metrics endpoint. Observability is deliberately kept outside
authorization policy: a metrics or logging failure cannot change a policy decision.

## Metrics endpoint

Configure a dedicated bearer token containing at least 32 characters:

```bash
export CONTEXT_BREACH_METRICS_TOKEN="$(openssl rand -hex 32)"
```

Do not reuse the request-signing secret. With no metrics token configured,
`GET /metrics` fails closed with `503 metrics_not_configured`. Scrape configured
instances with:

```bash
curl --fail \
  -H "Authorization: Bearer ${CONTEXT_BREACH_METRICS_TOKEN}" \
  http://127.0.0.1:8081/metrics
```

The endpoint exports:

- `context_breach_gateway_requests_total` by method, operation, and HTTP status;
- `context_breach_authorization_decisions_total` by decision and policy reason;
- `context_breach_authentication_failures_total` by operation and rejection reason;
- `context_breach_gateway_state_failures_total` by operation;
- `context_breach_gateway_request_duration_seconds` as a fixed-bucket histogram.

Metric labels come only from bounded server-controlled sets. Tenant, user, agent,
tool, resource, audit ID, request ID, intent, arguments, credential values, arbitrary
paths, and exception messages are excluded. Unknown values collapse to `other`,
`unknown`, or `unmatched` to prevent high-cardinality and injection attacks.

## Structured request logs

Each completed request emits one compact JSON object through the
`context_breach.gateway` Python logger:

```json
{"duration_ms":2.41,"event":"gateway_request","method":"POST","operation":"authorize","request_id":"generated-uuid","status_code":200}
```

The generated request ID is also returned in the `X-Request-ID` response header.
Client-supplied request IDs are not trusted or logged. Logs contain route operations,
not dynamic URL values, and intentionally omit all identity and request-body fields.
The packaged `context-breach-gateway` command disables Uvicorn's raw access log so
dynamic audit paths do not bypass this restriction.

Production log collectors should preserve the JSON message, add infrastructure-owned
pod/host metadata, restrict access, define retention, and alert on repeated
authentication or state failures. Do not enable generic body/header access logging in
front of the gateway without an equivalent redaction policy.

## Deployment limits

The registry is dependency-free, in-memory, and process-local. Counters reset on
restart and separate Uvicorn workers do not share them. Prometheus should scrape each
pod or worker target directly and perform aggregation. A load-balanced `/metrics`
request that reaches an arbitrary worker is not a complete service view.

This implementation does not yet provide distributed traces, OpenTelemetry export,
durable metric history, alert rules, dashboards, or service-level objectives. Those
belong in the deployment stack rather than the SQLite security-state database.
