# Multi-Agent Orchestrator Placement

## Purpose

Veraxis must sit at the agent-to-agent handoff boundary.

The invariant is:

> Every agent-to-agent handoff must pass through Veraxis before context becomes behavioral input.

## Handoff Flow

```text
Supervisor builds scratchpad
        ↓
HandoffCoordinator admission gate
        ↓
Gateway sanitizes context
        ↓
Session MAP generated
        ↓
Sub-agent receives sanitized payload
        ↓
Inference block generated
        ↓
MCR sealed
```

## Backpressure

The HandoffCoordinator uses bounded synchronous admission.

If the coordinator is saturated, the handoff is refused.

It does not silently drop jobs. It does not allow direct fallback to the sub-agent.

The invariant is:

> Backpressure is safer than bypass.

Rejected handoffs do not initialize sub-agents and do not expose raw scratchpad content.

## Sub-Agent Isolation

No sub-agent should have direct access to retrieved memory, raw scratchpad arrays, or supervisor state before Veraxis sanitization.

This prevents cross-agent memory leakage and privilege escalation.
