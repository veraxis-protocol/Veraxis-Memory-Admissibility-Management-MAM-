# Veraxis Admissible Memory Management (MAM) — v0.1.0-reference

## Production Reference Baseline Release

### Overview

Veraxis MAM v0.1.0-reference establishes the definitive production reference baseline for memory admissibility, runtime snapshot governance, and consequence lineage.

The system governs whether retrieved or transformed memory may influence future machine behavior. It operates directly at the deterministic authority layer rather than as a passive semantic enrichment layer.

This release secures the complete custody chain from pre-prompt context assembly to downstream machine consequence through Session MAP evidence and Machine Consequence Record lineage.

### Implemented Core Capabilities

1. **Phase 1A and Phase 2 — Evaluation Spine**

   Hard-coded register-level priority evaluation:

   ```text
   Tenant equality
      → domain equality
      → dynamic quarantine overrides
      → lifecycle validity
      → prohibited use blocks
      → allowed use classes
      → decision
   ```

2. **Phase 1B and Phase 5 — Evidence and Lineage Closure**

   Single-turn Session MAP generation with Merkle tree evidence, Ed25519 signatures, policy snapshot hash, runtime snapshot hash, runtime snapshot version, and Machine Consequence Record linkage to downstream `EEP_ID` and `AEP_ID`.

3. **Phase 1C — Gateway Edge Interceptors**

   Pre-prompt context window interception, deterministic tombstones, retrieved-versus-injected memory records, and provider adapter shapes for OpenAI and Anthropic-style payloads.

4. **Phase 2A — Durable Authority Storage**

   Local file-backed, length-prefixed write-ahead ledger with SHA-256 record checksums, synchronous `file.Sync()`, crash-resilient genesis replay, and lock-free atomic runtime snapshot swaps.

5. **Phase 3 and Phase 4 — Asynchronous Detection Loop**

   Out-of-band `DriftMonitorCoordinator` worker pools using 128-dimensional Axis subspace checks to detect structural memory mutation and emit durable quarantine events.

6. **Phase 4 — Multi-Agent Orchestrator Hook**

   Bounded synchronous handoff admission, fail-closed backpressure, pre-sub-agent context sanitization, Session MAP generation, inference block creation, and MCR sealing.

7. **Phase 4 Resilience — Adversarial Poison Drill**

   Active adversarial memory poisoning test proving:

   ```text
   clean memory passes
      → poisoned mutation is detected out-of-band
      → durable quarantine event is written
      → runtime snapshot swaps
      → next agent handoff strips memory before sub-agent exposure
   ```

### Core Performance Envelope

```text
BenchmarkEvaluateMemoryHotPath
~33 ns/op
0 B/op
0 allocs/op

BenchmarkCompileLineageRecord
~243 ns/op
32 B/op
1 alloc/op
```

The hot-path evaluation engine remains allocation-free. The MCR lineage compiler is out-of-band and incurs one allocation from SHA-256 construction.

### Dependency Footprint

The reference core remains standard-library only in this sandbox.

The gRPC/Protobuf transport boundary is defined by `schemas/mam.proto` and isolated under `pkg/rpc`. In connected CI/CD environments, official Google gRPC/Protobuf packages should be generated and bound at the transport edge only.

Core authority packages must not import transport packages.

### Enterprise Staging Acceptance Criteria

#### 1. Recovery Invariant Check

Validation strategy:

Seed 1,000 quarantine events into a test WAL, terminate the process ungracefully, reboot the daemon, and execute genesis replay.

Pass condition:

The restored node calculates a `RuntimeSnapshotHash` identical bit-for-bit to the pre-crash snapshot within a maximum initialization window of 2,000 milliseconds.

#### 2. Readiness Convergence Gate

Validation strategy:

In sidecar topology mode, broadcast 100 revocation updates through the pub-sub control plane.

Pass condition:

All active `/healthz/snapshot` endpoints converge to the same snapshot version and hash within 200 milliseconds.

#### 3. Boundary Leakage and Backpressure Test

Validation strategy:

Flood `HandoffCoordinator` with parallel handoffs exceeding bounded semaphore depth while injecting cross-tenant memory identifiers.

Pass condition:

Overflow requests fail closed with `ORCHESTRATOR_BACKPRESSURE`, and zero raw scratchpad content reaches the model provider.

#### 4. Adversarial Poison and Lineage Verification

Validation strategy:

Run the complete adversarial poisoning drill under maximum concurrency load.

Pass condition:

Axis workers detect the hidden subspace shift, write a durable quarantine event, trigger atomic snapshot swap, scrub the next handoff with a tombstone, and produce a verifiable MCR lineage token.

### Configuration Guardrails

#### Core Spine Immutable

The following packages are frozen as reference primitives:

```text
pkg/evaluate
pkg/bitmask
pkg/tenant
pkg/merkle
```

Changes require formal architecture review.

#### Transport Boundary Quarantined

Standard protocol modules belong at the `pkg/rpc` boundary only.

No transport, model SDK, database, queue, or vendor client may enter the core authority packages.

#### Orchestrator Fails Closed

The orchestrator must not fall back to direct sub-agent invocation under saturation.

Rejected handoffs must not expose raw context.

#### Runtime Snapshot Required

A node may serve only when it can prove it is operating on an admissible runtime snapshot.

### Release Status

```text
System Status: ARCHITECTURE SECURE
Reference Status: FROZEN
Release Tag: v0.1.0-reference
Classification: Production Reference Baseline
```

The reference engine is sealed for enterprise staging. Future provider clients, orchestration adapters, EEP/AEP integrations, and deployment-specific extensions should be developed outside the frozen reference spine.
