# Axis Subspace Drift Model

## Purpose

The Axis subsystem detects semantic mutation across memory transformations.

Standard global vector similarity can remain high even when a consequential governance property changes. A memory can look "similar" in topical space while drifting across an institutional invariant.

Examples:

- suspicion becomes fact;
- a temporary state becomes a stable trait;
- a context-bound instruction becomes global authority;
- low-trust source material becomes trusted institutional knowledge;
- a user preference becomes a machine mandate.

## Vector Layout

The prototype uses 128-dimensional structural vectors split into invariant subspaces:

| Invariant | Coordinate Range |
|---|---:|
| Temporality | 0–23 |
| Epistemic status | 24–47 |
| Scope | 48–71 |
| Source trust | 72–95 |
| Mandate / authority | 96–127 |

## Blindspot Condition

The Ticket 14 fixture generator intentionally scales down target subspace mass while preserving global vector mass elsewhere.

This creates the exploit condition:

```text
Global cosine similarity remains high.
Local governance-relevant subspace cosine distance trips.
```

That means ordinary semantic similarity remains blind while Axis detects a structural integrity violation.

## Drift Types

The engine maps detected subspace failures to drift classes:

- `TEMPORARY_STATE_PROMOTED_TO_STABLE_TRAIT`
- `INFERENCE_PROMOTED_TO_FACT`
- `CONTEXT_BOUND_MEMORY_REUSED_GLOBALLY`
- `LOW_TRUST_SOURCE_PROMOTED`
- `PREFERENCE_PROMOTED_TO_MANDATE`

## Operationalization

Ticket 19 turns Axis into an asynchronous detection plane.

The hot path does not call Axis. Axis workers run out-of-band, consume memory transformation jobs, evaluate drift, and emit durable quarantine events when structural integrity fails.

The runtime path continues to read only the active atomic snapshot.
