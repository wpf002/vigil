# ADR 0002 — Real-time ingest as data enters SIEM / S3 / data lake (Big Bet 2)

Status: Accepted (push + batch MVP shipped) · Date: 2026-05-30

## Context

All four SIEM connectors (`splunk_es`, `splunk_core`, `sentinel`, `elastic`)
are request/response pollers keyed on a `since` timestamp (`ingestor/main.py`
`_poll_loop`). "Real time" = the poll interval, and the polled data is
already-fired SIEM alerts, not raw telemetry. We want to ingest as data lands —
in the SIEM, an S3 bucket, or a data lake — at low latency.

## Decision

Add **push ingestion** alongside polling, landing on the same internal Kafka
backbone (`vigil.signals.raw`) which is already real-time:

Shipped (MVP):
- `POST /signals` — single-event webhook (API-key or JWT auth, tenant from
  credential, in-transit rule enrichment).
- `POST /signals/batch` — HEC / S3-micro-batch bulk endpoint: accept an array of
  CDM events (an S3→SQS landing fan-out), enrich + publish.

These cover the **agent-less push** and **data-lake micro-batch** patterns
without new infrastructure.

## Options considered

1. **S3-event-driven micro-batch (chosen first).** S3 `ObjectCreated` → SQS /
   Firehose → `POST /signals/batch`. Cheapest, near-real-time, fits the
   "data lake" framing. No streaming infra to operate.
2. **True streaming** (Kafka tap on the customer log bus / Kinesis / Splunk HEC
   forwarder fan-out). Lowest latency, higher ops cost. Deferred.

## Consequences

- New work is at the ingest **edge** only; the correlation/consumer side is
  already real-time, so latency is bounded by the producer + rule eval.
- A customer-side S3-notification → SQS → batch-POST shim (a small Lambda) is
  the integration the customer deploys — no agent on hosts.
- Backpressure/ordering for very high volume would push us toward option 2.

## Sequencing

Push webhook + batch endpoint (done) → customer S3/SQS shim + auth-scoped batch
keys → evaluate true streaming (Kinesis/Kafka tap) if a customer needs
sub-second latency at scale.
