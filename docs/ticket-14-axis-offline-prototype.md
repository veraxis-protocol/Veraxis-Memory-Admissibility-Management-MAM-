# Ticket 14 — Dual-Vector Axis Offline Prototype

Component: `pkg/axis`, `benchmarks/axis_fixtures`

Status: implemented baseline.

Core principle:

Standard semantic embeddings track topical similarity. Structural axis embeddings track truth, time, authority, and bounds.

Ticket 14 adds:

- deterministic vector subspace drift checks;
- temporality, epistemic, scope, trust, and mandate partitions;
- canonical synthetic fixture generator;
- `benchmarks/axis_fixtures/fixtures.json`;
- unit tests proving drift detection;
- import isolation tests ensuring hot-path packages do not import `pkg/axis`.

Run fixture generation:

```bash
go run ./benchmarks/axis_fixtures
```
