# Ticket 18 — Production Deployment Runbooks & State Synchronization

Component: `docs/runbooks`, `deploy/manifests`, `pkg/ops`

Core invariant:

A node may serve only if it can prove it is operating on an admissible runtime snapshot.

Implemented assets:

- `docs/runbooks/ticket-18-production-deployment.md`
- `docs/runbooks/sidecar-state-sync.md`
- `docs/runbooks/central-governance-cluster.md`
- `deploy/manifests/sidecar-deployment.yaml`
- `deploy/manifests/central-governance-cluster.yaml`
- `deploy/manifests/alerts.yaml`
- `pkg/ops/health.go`
- readiness/fail-closed unit tests

Ticket 18 stabilizes the authority distribution plane before asynchronous Axis workers are introduced.
