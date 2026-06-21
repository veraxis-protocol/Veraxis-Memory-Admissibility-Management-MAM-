# Governance Sidecar State Synchronization Runbook

## Purpose

Run Veraxis as a local sidecar next to each agent container while distributing revocation events through a pub-sub control plane.

## Standard Bus

Primary standard: NATS JetStream.

Authorized enterprise alternative: Redis Streams.

## Event Subject

`veraxis.mam.revocations`

## Ingestion Flow

1. Operator or security worker emits `RevocationEvent`.
2. Event is published to `veraxis.mam.revocations`.
3. Sidecar receives the message.
4. Sidecar appends the event to local durable WAL.
5. Sidecar calls `file.Sync()`.
6. Sidecar compiles immutable snapshot.
7. Sidecar atomically swaps active snapshot.
8. Sidecar publishes telemetry with version/hash.

## Catchup Protocol

A sidecar must stop serving and catch up when:

- snapshot version gap exceeds `max_version_lag`;
- snapshot age exceeds `max_snapshot_lag_ms`;
- missing sequence detected;
- pub-sub reconnect indicates missed events.

Catchup sequence:

1. Mark readiness unhealthy.
2. Query JetStream/Redis stream history from last applied sequence.
3. Apply missing events sequentially.
4. Append each event to local WAL.
5. Run snapshot compile.
6. Atomically swap.
7. Verify snapshot convergence with cluster baseline.
8. Mark readiness healthy.

## Genesis Resync

If local WAL corruption is detected:

1. Mark readiness unhealthy.
2. Stop evaluation serving.
3. Move corrupted WAL to quarantine path.
4. Stream canonical event history from primary storage node.
5. Rebuild local WAL from byte zero.
6. Replay genesis.
7. Compile snapshot.
8. Verify hash.
9. Resume serving.

## Fail-Closed Cooling Lock

If pub-sub is unreachable:

- enter stale read-only cooling lock for 30 seconds;
- continue serving only if snapshot lag is inside tolerance;
- after 30 seconds, fail closed.

## Health Probe Contract

Liveness: process responsive.

Readiness: process can prove active admissible snapshot, WAL availability, and lag tolerance.
