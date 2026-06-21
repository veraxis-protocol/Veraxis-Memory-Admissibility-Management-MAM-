# Polyglot Agent Integration Guide

## Purpose

Polyglot teams must integrate Veraxis at the context assembly boundary, not after model invocation.

The correct integration point is:

```text
retrieved memory + scratchpad + task state
        ↓
Veraxis admissibility check
        ↓
sanitized context window
        ↓
model/provider call
```

## gRPC Boundary

The canonical service schema lives at:

```text
schemas/mam.proto
```

The sandbox package includes a dependency-contained RPC core and schema. In a connected build environment, generate official gRPC bindings from `schemas/mam.proto` using the Google protobuf tooling.

## Python Client Shape

```python
request = EvaluateRequest(
    session_id=session_id,
    agent_id=agent_id,
    context=RuntimeContext(
        tenant_hash=tenant_hash_bytes,
        domain_hash=domain_hash_bytes,
        required_lifecycle=required_lifecycle,
        prohibited_safety=prohibited_safety,
        allowed_use_classes=allowed_use_classes,
        prohibited_use_blocks=prohibited_use_blocks,
    ),
    candidates=[
        MemoryCandidate(
            memory_id=memory_id_bytes,
            memory_hash=memory_hash_bytes,
            memory_flags=memory_flags,
        )
    ],
)

response = client.EvaluateMemoryUse(request)

for decision in response.decisions:
    if not decision.injected:
        scrub_context(decision.memory_id, decision.reason_code)
```

## TypeScript Client Shape

```typescript
const response = await client.evaluateMemoryUse({
  sessionId,
  agentId,
  context: {
    tenantHash,
    domainHash,
    requiredLifecycle,
    prohibitedSafety,
    allowedUseClasses,
    prohibitedUseBlocks
  },
  candidates
});

for (const decision of response.decisions) {
  if (!decision.injected) {
    scrubContext(decision.memoryId, decision.reasonCode);
  }
}
```

## Rust Client Shape

```rust
let response = client.evaluate_memory_use(request).await?;

for decision in response.decisions {
    if !decision.injected {
        scrub_context(decision.memory_id, decision.reason_code);
    }
}
```

## Context Scrubbing Rule

The caller must never pass raw memory to the model after a non-injected decision.

The caller must replace blocked content with the appropriate tombstone or remove it from the context window according to local policy.

The Go gateway already implements tombstoning for native integrations.

## Required Byte Sizes

Wire clients must enforce:

- tenant hash: exactly 32 bytes;
- domain hash: exactly 32 bytes;
- memory ID: exactly 16 bytes;
- memory hash: exactly 32 bytes;
- Merkle root: exactly 32 bytes.

Malformed inputs must fail closed.
