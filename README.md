# Veraxis Admissible Memory Management

Veraxis Admissible Memory Management (MAM) governs which machine memories may influence future machine behavior.

Memory is not passive context. Memory is delegated influence over future behavior. If memory changes what an agent may believe, output, or do, memory is part of the authority path.

## Production Invariants

- Tenant equality first.
- Lifecycle validity before policy discretion.
- Dynamic quarantine overrides before memory injection.
- No raw fallback under backpressure.
- No sub-agent handoff outside Veraxis.
- No consequence without lineage.
- A node may serve only if it can prove it is operating on an admissible runtime snapshot.
- The hot path must remain deterministic and allocation-free.

## Benchmark Envelope

Current benchmark envelope:

```text
BenchmarkEvaluateMemoryHotPath
~33 ns/op
0 B/op
0 allocs/op

BenchmarkCompileLineageRecord
~245 ns/op
32 B/op
1 alloc/op
```

The lineage compiler is out-of-band and may allocate once for SHA-256 construction. The hot memory admissibility path remains allocation-free.

## Repository Layout

```text
veraxis-memory-admissibility/
├── benchmarks/
│   └── axis_fixtures/
├── cmd/
│   ├── mam-bench/
│   ├── mam-harness/
│   └── mam-server/
├── deploy/
│   └── manifests/
├── docs/
│   ├── architecture/
│   └── runbooks/
├── pkg/
│   ├── audit/
│   ├── axis/
│   ├── bitmask/
│   ├── evaluate/
│   ├── gateway/
│   ├── merkle/
│   ├── ops/
│   ├── orchestrator/
│   ├── policy/
│   ├── quarantine/
│   ├── rpc/
│   ├── sessionmap/
│   └── tenant/
├── schemas/
└── tests/
    ├── adversarial/
    ├── integration/
    └── unit/
```

## Core Chain

```text
Memory → MAP → EEP → AEP → MCR
```

MAM produces Session MAP evidence. The MCR lineage primitive binds Session MAP evidence to downstream output reliance and action execution identifiers.

## Runtime Flow

```text
retrieved memory + scratchpad
        ↓
gateway / orchestrator handoff
        ↓
bitmask + runtime snapshot admissibility evaluation
        ↓
sanitized context window
        ↓
provider invocation
        ↓
Session MAP
        ↓
AdmissibleInferenceBlock
        ↓
MachineConsequenceRecord
```

## Packages

### `pkg/evaluate`

Deterministic evaluation spine.

Checks tenant, domain, lifecycle, dynamic safety state, prohibited use, and allowed use classes.

### `pkg/bitmask`

Register-level flags for memory lifecycle, use classes, prohibited uses, safety states, and tiers.

### `pkg/gateway`

Pre-prompt context window scrubber.

Outputs sanitized messages and Merkle leaf records.

### `pkg/sessionmap`

Builds signed Session MAP evidence.

Includes Merkle root, policy snapshot hash, runtime snapshot hash, runtime snapshot version, and Ed25519 signature.

### `pkg/quarantine`

Durable revocation/quarantine event plane.

Includes length-prefixed file WAL, SHA-256 record checksums, genesis replay, runtime snapshots, and atomic pointer swaps.

### `pkg/axis`

Subspace drift model and asynchronous worker pool.

Detects memory mutation across temporality, epistemic status, scope, trust, and mandate dimensions.

### `pkg/audit`

Session MAP verification and Machine Consequence Record lineage verification.

### `pkg/orchestrator`

Multi-agent handoff coordinator.

Enforces bounded synchronous admission and prevents raw scratchpad exposure under load.

### `pkg/rpc`

Transport-edge server core matching `schemas/mam.proto`.

Official gRPC bindings should be generated from the schema in a connected build environment.

### `pkg/ops`

Readiness and liveness logic for runtime snapshot admissibility.

## Documentation

Architecture references:

- `docs/architecture/01-core-invariants.md`
- `docs/architecture/02-axis-subspace-model.md`
- `docs/architecture/03-cryptographic-custody-chain.md`
- `docs/architecture/04-polyglot-integration.md`
- `docs/architecture/05-orchestrator-placement.md`
- `docs/architecture/06-operational-runtime.md`

Operational runbooks:

- `docs/runbooks/ticket-18-production-deployment.md`
- `docs/runbooks/sidecar-state-sync.md`
- `docs/runbooks/central-governance-cluster.md`

## Test Suites

Run:

```bash
go test ./...
```

Benchmark:

```bash
go test -bench=. -benchmem ./benchmarks
```

Adversarial drill:

```bash
go test ./tests/adversarial
```

## Deployment Modes

Supported topologies:

1. Governance sidecar.
2. Central governance cluster.

Manifests live in:

```text
deploy/manifests/
```

## Dependency Posture

The root module remains standard-library only in this sandbox.

The official gRPC/Protobuf packages should be added at the transport boundary in connected CI/CD environments when generating service bindings from `schemas/mam.proto`.

Core authority packages must not import the transport or orchestration edge.

## Release

Current frozen reference release:

```text
v0.1.0-reference
```

Release notes:

```text
RELEASE_NOTES_v0.1.0.md
```

This reference baseline should be treated as immutable. Future provider clients, deployment adapters, and staging integrations should be developed as extensions or downstream branches.


## Staging verification

The staging branch includes a single-command verification harness:

```bash
go run ./cmd/staging-verify
```

It writes:

```text
STAGING_VERIFICATION_REPORT_v0.1.0.json
```

The release candidate is accepted only if `final_status` is `STAGING_ACCEPTED` and `raw_context_bypass_detected` is `false`.


## Python SDK

The staging branch includes the Python edge adapter under:

```text
sdk/python/
```

The SDK validates byte shapes, delegates admissibility to the Veraxis daemon transport, and enforces returned decisions with local context scrubbing. It does not compute admissibility locally.


## TypeScript SDK

The staging branch includes the TypeScript edge adapter under:

```text
sdk/typescript/
```

The SDK validates `Uint8Array` byte shapes, delegates admissibility to a Veraxis daemon transport, and enforces returned decisions with local context scrubbing. It does not compute admissibility locally.


## Vector store interceptors

The repository includes vendor-neutral vector retrieval hooks under:

```text
pkg/integrations/vectorstore/
```

The interceptor returns retrieval results immediately and dispatches vector drift jobs to the Axis worker pool out-of-band. It introduces no direct Pinecone, Qdrant, Milvus, pgvector, or other vendor dependency into the core module.
