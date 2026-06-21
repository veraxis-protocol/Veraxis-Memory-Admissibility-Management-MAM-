# Ticket 20 — Multi-Agent Orchestrator Hook

Component: `pkg/orchestrator`, `pkg/gateway`

Core invariant:

No sub-agent may initialize or ingest historical scratchpad data outside the Veraxis gateway boundary.

Backpressure invariant:

Backpressure is safer than bypass.

Ticket 20 adds:

- `pkg/orchestrator.AgentIdentity`
- `pkg/orchestrator.HandoffCoordinator`
- bounded synchronous semaphore admission
- fail-closed backpressure rejection
- gateway sanitization before provider invocation
- Session MAP generation for every handoff
- AdmissibleInferenceBlock construction
- MCR construction through `audit.CompileLineageRecord`
- preserved message-order tests
- boundary leakage prevention tests
- backpressure rejection tests
- concurrency sequence test
- import isolation test

Rejected handoffs do not initialize sub-agents and do not expose raw scratchpad context.
