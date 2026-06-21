# Ticket 13 — Active Quarantine State Machine

Component: `pkg/quarantine`, `pkg/gateway`, `pkg/sessionmap`, `pkg/audit`

Phase 2 maxim:

Ledger for truth. Snapshot for speed. Atomic swap for enforcement. Session MAP for proof.

Ticket 13 adds:

- append-only in-memory revocation ledger;
- immutable runtime snapshot compilation;
- atomic snapshot swap;
- lock-free runtime lookup;
- gateway dynamic-state override before static bitmask policy;
- Session MAP runtime snapshot hash/version binding;
- audit verification variant for policy + runtime snapshot;
- integration tests for dynamic quarantine, tombstone, revoked state, snapshot swap, and runtime snapshot mutation.

The active read path uses atomic snapshot loading. Writers append ledger events and compile a new immutable snapshot out-of-band.
