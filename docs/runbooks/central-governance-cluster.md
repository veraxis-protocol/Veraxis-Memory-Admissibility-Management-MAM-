# Central Governance Cluster Runbook

## Purpose

Run Veraxis as a shared governance service behind an enterprise load balancer.

## Storage Invariant

Use coordinated shared storage for WAL durability.

Recommended substrates:

- AWS EBS Multi-Attach where supported and configured safely.
- Ceph NVMe-oF SAN infrastructure.
- Enterprise block storage with strict write coordination.

## Write Coordination

Exactly one node holds the active write lease.

Only the Primary Coordinator may append to the shared WAL.

Followers mount read-only or treat WAL as replay-only.

## Primary Election

Use Raft, etcd lease bindings, or enterprise equivalent.

Primary heartbeat miss budget: 500 ms.

Failover sequence:

1. Detect primary lease failure.
2. Elect new primary.
3. New primary verifies final valid WAL offset.
4. New primary resumes writes from last valid boundary.
5. Followers continue tailing.

## Follower Replay

Followers:

1. Tail shared WAL.
2. Parse new records.
3. Validate magic and checksum.
4. Compile snapshot.
5. Atomic swap.
6. Update readiness state.

## Boot Replay

A new node must:

1. Block all external gRPC traffic.
2. Mount storage.
3. Replay WAL from byte zero.
4. Compile snapshot.
5. Verify snapshot hash.
6. Mark readiness healthy.
7. Accept traffic.

## Routing

Use Envoy, Kubernetes Service, or enterprise HTTP/2 gRPC load balancer.

Read/evaluate traffic may route to any ready node.

Revocation write traffic must route to the current primary or be forwarded to it.
