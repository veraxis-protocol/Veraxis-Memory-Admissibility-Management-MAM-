# Ticket 15 — Durable Revocation Ledger & Snapshot Replay

Component: `pkg/quarantine`, `pkg/audit` extensions.

Core invariant:

A Veraxis node may undergo crash recovery, failover, or restart, but its memory admissibility state must remain immutable and continuous.

Ticket 15 adds:

- length-prefixed durable revocation log;
- record magic number;
- SHA-256 record checksum;
- mandatory `file.Sync()` on append;
- genesis replay from byte zero;
- partial-write detection;
- tamper detection;
- restart recovery into atomic runtime snapshot;
- deterministic snapshot hash recovery;
- integration tests for persistence, tamper, truncation, and clear events.

No database or third-party dependency is introduced.
