# Ticket 18 — Production Deployment Runbooks & State Synchronization

Component: `docs/runbooks`, `deploy/manifests`, `pkg/ops`

Status: Phase 2A operational baseline.

Production invariant:

> A node may serve only if it can prove it is operating on an admissible runtime snapshot.

## Deployment Modes

Ticket 18 defines two supported operational topologies:

1. Governance sidecar model.
2. Central governance cluster model.

The sidecar model optimizes local latency and isolation. The central governance cluster optimizes coherence and operational centralization.

## Boot Protocol

Every Veraxis node must execute this boot sequence before accepting evaluation traffic:

1. Mount durable storage block.
2. Execute `ReplayGenesis` from byte zero.
3. Compile immutable runtime snapshot.
4. Atomically swap active snapshot pointer.
5. Open readiness boundary.

A node that fails replay, checksum validation, storage mounting, or snapshot compilation must not serve.

## Authority Serving Rule

A node is eligible to serve only when:

- durable WAL is readable;
- replay from genesis succeeds;
- active snapshot hash is non-zero;
- snapshot version is within configured lag tolerance;
- state distribution channel is reachable or still inside cooling window;
- no checksum or tamper fault is active.

## Fail-Closed Rule

If the node cannot prove snapshot admissibility, it must stop serving evaluation traffic.

In sidecar mode, if pub-sub connectivity is unavailable for longer than the configured stale cooling period, all incoming evaluations must fail closed or return hard-refuse behavior.

## Operational Alerts

| Alert | Severity | Trigger | Action |
|---|---:|---|---|
| `MAM_LEDGER_CHECKSUM_ERROR` | Critical | Replay detects corrupted or malformed record | Remove node from traffic and dump diagnostics |
| `MAM_SNAPSHOT_OUT_OF_SYNC` | High | Node lags primary by more than allowed versions | Mark readiness unhealthy and resync |
| `MAM_BOOT_REPLAY_TIMED_OUT` | High | Genesis replay exceeds startup budget | Restart node and inspect storage |
| `MAM_REVOCATION_FSYNC_FAILURE` | Critical | WAL fsync fails | Fail closed and isolate writer |
| `MAM_PUBSUB_UNREACHABLE` | High | Sidecar cannot reach NATS/Redis | Enter cooling lock, then fail closed |
| `MAM_RUNTIME_SNAPSHOT_ZERO` | Critical | No active snapshot hash/version | Do not serve |
