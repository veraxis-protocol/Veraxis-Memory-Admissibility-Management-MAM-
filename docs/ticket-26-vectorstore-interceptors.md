# Ticket 26 — Vector Store Interceptors

Component: `pkg/integrations/vectorstore`

Core invariant:

Interceptors are non-blocking transport proxies. They do not compute admissibility, Merkle roots, or Axis drift on the live query path. They clone vector records and dispatch mutation jobs to `axis.DriftMonitorCoordinator` out-of-band.

Implemented assets:

- `pkg/integrations/vectorstore/interceptor.go`
- `tests/integration/vectorstore_interceptor_test.go`
- `benchmarks/vectorstore_interceptor_bench_test.go`

Behavior:

- returns retrieved vector records immediately;
- validates anchor/retrieved batch length;
- skips memory ID mismatches;
- clones vectors before background submission;
- uses `DriftMonitorCoordinator.SubmitNonBlocking`;
- drops jobs under queue saturation to preserve retrieval availability;
- exposes local submitted/dropped/skipped counters.

No vendor vector database client package is introduced.
