# Veraxis MAM TypeScript SDK v0.1.0

This package is the TypeScript edge adapter for the frozen Veraxis MAM authority core.

It does not compute admissibility, Merkle roots, vector similarity, or policy logic locally. It validates `Uint8Array` byte shapes, calls the Veraxis daemon transport, and enforces returned decisions by scrubbing the context window before model provider invocation.

## Invariant

The spine governs. The edge adapts.

## Install

In a connected environment:

```bash
npm install @grpc/grpc-js google-protobuf
```

Generate JavaScript/TypeScript stubs from `schemas/mam.proto`, then bind them through a `MemoryAdmissibilityTransport`.

## Local tests

```bash
npm test
```

The local tests use a mock transport and require no network daemon.
