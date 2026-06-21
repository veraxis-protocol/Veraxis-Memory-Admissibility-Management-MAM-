# Ticket 12 — Client Lifecycle & Evidence Binding

Component: `pkg/gateway`, `examples/clientloop`

Status: implemented baseline.

Core principle:

An LLM response is only auditable if it is permanently bound to the Session MAP that authorized its context.

Ticket 12 adds:

- `gateway.AdmissibleInferenceBlock`
- `gateway.TokenMetrics`
- `gateway.LifecycleRunner`
- `gateway.MockInferenceProvider`
- `examples/clientloop`
- inference lifecycle tests proving audit replay, zero contamination, payload isolation, and policy snapshot binding.

Run:

```bash
go run ./examples/clientloop
```
