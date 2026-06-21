# Cryptographic Custody Chain

## Purpose

The custody chain binds memory admissibility, output reliance, and machine action into one verifiable consequence lineage.

The chain is:

```text
Memory → MAP → EEP → AEP → MCR
```

## Session MAP

A Session MAP is generated for a single turn. It binds:

- session identity;
- agent identity;
- actor identity;
- task identity;
- tenant hash;
- policy snapshot hash;
- runtime snapshot hash;
- runtime snapshot version;
- Merkle root of memory decision leaves;
- Ed25519 signature.

The Merkle tree records whether each memory was retrieved and whether it was actually injected into the prompt context.

## EEP and AEP Linkage

The repository does not implement full EEP or AEP protocol storage. It implements the linkage primitive that makes EEP and AEP accountable to the Session MAP.

The Machine Consequence Record binds:

- MCR ID;
- Session MAP ID;
- Merkle root;
- policy snapshot hash;
- runtime snapshot hash;
- runtime snapshot version;
- EEP ID;
- AEP ID;
- linked Unix timestamp.

## Machine Consequence Record

`pkg/audit.MachineConsequenceRecord` is the out-of-band verifier for downstream machine consequence.

An auditor can verify that an action was anchored to the same memory admissibility state that shaped the model output.

This prevents a system from using a valid memory evaluation to justify a later action under changed runtime authority.

## Verification

`audit.VerifyLineageRecord` checks:

- Session MAP identity;
- Merkle root;
- policy snapshot hash;
- runtime snapshot hash;
- runtime snapshot version;
- recomputed lineage digest.

Any mismatch fails verification.
