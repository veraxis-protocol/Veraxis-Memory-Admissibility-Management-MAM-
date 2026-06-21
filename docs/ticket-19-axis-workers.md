# Ticket 19 — Asynchronous Poison / Drift Monitor Workers

Component: `pkg/axis`, `pkg/quarantine`

Core invariant:

The hot path remains fast because detection runs entirely out-of-band.

Ticket 19 adds:

- `axis.MemoryTransformationJob`
- `axis.DriftMonitorCoordinator`
- bounded job queue
- non-blocking submit with drop counting
- async worker pool
- drift-to-quarantine event mapping
- durable ledger writes through `FileLedger.AppendEvent`
- runtime monitor append + compile-and-swap
- closed-loop integration test proving second gateway turn strips content after drift detection

The worker writes to the durable authority plane; the evaluation path still reads only the atomic runtime snapshot.
