# Ticket 25 — TypeScript Client SDK

Component: `sdk/typescript`

Core invariant:

The TypeScript SDK mirrors data structures and handles transport. It does not compute admissibility logic, vector similarity, or Merkle roots locally. It delegates authority to the core daemon and enforces returned decisions.

Implemented assets:

- `sdk/typescript/src/client.ts`
- `sdk/typescript/src/index.ts`
- `sdk/typescript/tests/client.test.mjs`
- `sdk/typescript/package.json`
- `sdk/typescript/tsconfig.json`
- `sdk/typescript/README.md`

The SDK includes typed interfaces, async wrapper logic, `Uint8Array` byte-size validation, returned-decision enforcement, canonical tombstone replacement, a mock transport for local tests, and a generated-gRPC transport seam for connected environments.

No math, tensor, vector, or agent framework dependency is introduced.
