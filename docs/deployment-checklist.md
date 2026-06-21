# Veraxis MAM Enterprise Staging Checklist

## Preflight

- [ ] Durable WAL path mounted.
- [ ] WAL path readable and writable.
- [ ] ReplayGenesis succeeds.
- [ ] RuntimeSnapshotHash is non-zero.
- [ ] RuntimeSnapshotVersion is current.
- [ ] Readiness endpoint reports admissible runtime snapshot.
- [ ] Pub-sub connectivity verified for sidecar topology.
- [ ] Primary write lease verified for central cluster topology.
- [ ] Alerts deployed.
- [ ] HandoffCoordinator capacity configured.
- [ ] No direct sub-agent fallback path exists.

## Security

- [ ] Tenant and domain hashes are exactly 32 bytes.
- [ ] Memory IDs are exactly 16 bytes.
- [ ] Memory hashes are exactly 32 bytes.
- [ ] Any malformed request fails closed.
- [ ] Quarantine events fsync before confirmation.
- [ ] Session MAP signature verification is enabled for audit replay.
- [ ] MCR lineage verification is enabled for consequential actions.

## Tests

- [ ] `go test ./...`
- [ ] `go test ./tests/adversarial`
- [ ] `go test -bench=. -benchmem ./benchmarks`
