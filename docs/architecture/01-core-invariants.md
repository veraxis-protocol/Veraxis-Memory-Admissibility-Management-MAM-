# Veraxis MAM Core Invariants

## Purpose

Veraxis Admissible Memory Management (MAM) governs which machine memories may influence future machine behavior.

The governing premise is:

> Memory is delegated influence over future behavior.

Therefore, memory cannot be treated as passive context. When memory is retrieved, summarized, transformed, injected, or relied upon, it becomes part of the authority path.

## Core Evaluation Sequence

The hot path is implemented in `pkg/evaluate`.

The evaluation order is intentionally rigid:

1. Tenant equality.
2. Domain equality.
3. Lifecycle validity.
4. Dynamic safety state.
5. Prohibited use blocks.
6. Explicit allowed use classes.
7. Use or ignore.

This ordering is non-negotiable.

Tenant and domain boundaries are checked before policy discretion. Lifecycle state is checked before use-class interpretation. A deletion or revocation state cannot be overridden by downstream agent intent.

## Priority Model

The evaluation engine treats the following states as hard boundaries:

- deletion requested;
- expired memory;
- revoked memory;
- quarantine / poisoning suspicion;
- prohibited use class;
- absent allowed use class;
- tenant mismatch;
- domain mismatch.

The gateway then applies the result to the context window by either preserving, annotating, tombstoning, or refusing memory injection.

## Performance Envelope

The current benchmark envelope is:

```text
BenchmarkEvaluateMemoryHotPath
~33 ns/op
0 B/op
0 allocs/op
```

This benchmark defines the expected local primitive boundary. Network deserialization, provider invocation, ledger writes, and background Axis workers are not part of this hot path.

## Why This Matters

The core engine is not an AI model, classifier, or semantic policy layer. It is a deterministic authority prefilter.

It answers a narrower question:

> May this memory influence this execution context right now?

That answer must be fast, deterministic, and fail-closed.
