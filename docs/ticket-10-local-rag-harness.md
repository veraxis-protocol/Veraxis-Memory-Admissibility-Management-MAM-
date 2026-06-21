# Ticket 10 — Local RAG Behavioral Harness

Component: `cmd/mam-harness`

Status: implemented baseline.

Core principle:

Prove the behavioral invariant locally first. Add provider ergonomics second.

The harness simulates:

1. RAG retrieval with three candidate memories.
2. Gateway sanitization at the pre-prompt boundary.
3. Rogue cross-tenant memory stripping.
4. Qualified memory annotation.
5. Session MAP generation.
6. Independent audit replay verification.
7. Mock provider invocation that fails if inadmissible raw memory reaches provider payload.

Run:

```bash
go run ./cmd/mam-harness
```
