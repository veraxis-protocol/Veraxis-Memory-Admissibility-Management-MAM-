# Ticket 17 — Consequence Lineage Linker

Component: `pkg/audit`

Core invariant:

No consequence without lineage.

Ticket 17 adds:

- `MachineConsequenceRecord`
- `CompileLineageRecord`
- `ComputeLineageDigest`
- `VerifyLineageRecord`
- deterministic SHA-256 lineage binding
- big-endian serialization for runtime snapshot version and timestamp
- tamper tests across policy snapshot, runtime snapshot, Session MAP ID, Merkle root, EEP ID, AEP ID, timestamp, and digest
- lineage microbenchmark

The MCR digest binds:

- MCRID
- SessionMAPID
- MerkleRoot
- PolicySnapshotHash
- RuntimeSnapshotHash
- RuntimeSnapshotVersion
- EEPID
- AEPID
- LinkedAtUnix
