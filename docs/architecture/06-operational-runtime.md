# Operational Runtime Runbook

## Boot Protocol

Each node must execute:

1. Mount durable storage.
2. Replay the write-ahead ledger from byte zero.
3. Validate record framing and SHA-256 checksums.
4. Compile runtime snapshot.
5. Atomically swap active snapshot pointer.
6. Mark readiness healthy.
7. Open service boundary.

A node must not serve if replay fails.

## Ledger Corruption

If a WAL checksum error is detected:

1. Remove the node from traffic.
2. Preserve the corrupted WAL for analysis.
3. Rebuild from clean canonical history.
4. Replay genesis.
5. Verify snapshot hash.
6. Rejoin only after readiness passes.

## Sidecar State Sync

Sidecars receive revocation events through the distribution plane, append them locally to the durable WAL, sync, compile, and atomically swap.

Maximum ordinary lag:

```text
2 versions or 200 milliseconds
```

If lag exceeds tolerance, the sidecar becomes unready and performs catchup.

## Central Governance Cluster

The central cluster uses a primary writer and replaying followers.

Only the primary appends to the shared ledger. Followers tail and replay.

New nodes block traffic until replay completes and snapshot readiness is proven.

## Fail-Closed Rules

A node must fail closed when:

- WAL is unreadable;
- replay fails;
- snapshot hash is zero;
- snapshot version is too stale;
- pub-sub is unreachable beyond cooling lock;
- fsync fails;
- leadership lease is invalid for writer nodes.

## Alerts

Production alerts are defined in:

```text
deploy/manifests/alerts.yaml
```
