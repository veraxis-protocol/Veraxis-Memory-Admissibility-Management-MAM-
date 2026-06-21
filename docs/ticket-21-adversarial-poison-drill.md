# Ticket 21 — Adversarial Memory Poisoning Testbed

Component: `tests/adversarial`, `pkg/axis`, `pkg/quarantine`, `pkg/orchestrator`

Core invariant:

An exploit vector successfully injected into an agent memory store must be programmatically neutralized by the out-of-band detector before it can leak across an agent-to-agent handoff boundary.

Ticket 21 adds:

- adversarial poison drill test package;
- indirect prompt injection payload simulation;
- global cosine blindspot assertion;
- local subspace drift assertion;
- asynchronous Axis worker submission;
- durable poisoning event assertion;
- runtime snapshot atomic swap assertion;
- second-turn orchestrator handoff hard-scrub assertion;
- zero exploitation window check after snapshot swap.

The drill proves:

1. The poisoned memory passes before detection.
2. Axis detects subspace drift while global similarity remains high.
3. The drift worker writes to durable WAL.
4. The runtime monitor swaps snapshot state.
5. The next multi-agent handoff strips the poisoned memory before provider exposure.
