# Ticket 9 Evidence Closure

Ticket 9 closes the admissible memory evidence loop.

Gateway output emits `[]merkle.LeafRecord`.
`pkg/sessionmap` builds the deterministic Merkle root and signs one root per turn.
`pkg/audit` reconstructs the Merkle root, verifies the Ed25519 signature, and optionally validates the immutable policy snapshot hash.

Core principle:

If memory was admitted, qualified, stripped, refused, or quarantined, the system must be able to prove exactly what happened after the fact.
