# Ticket 16 — gRPC/Protobuf Network Service

Component: `schemas`, `pkg/rpc`, `cmd/mam-server`

Status: implemented transport-core baseline.

Important environment note:

The official Google gRPC/Protobuf packages could not be fetched in this sandbox because outbound module resolution is blocked. This ticket therefore includes:

- canonical `schemas/mam.proto`;
- dependency-free server core matching the protobuf shape;
- fail-closed sizing validation;
- runtime snapshot evaluation;
- revocation event registration;
- concurrency tests;
- optional `grpc` build-tag seam for generated gRPC bindings when `google.golang.org/grpc` and `google.golang.org/protobuf` are available in a connected build environment.

Core invariant:

gRPC may wrap the engine. gRPC must never become the engine.

The runtime engine packages do not import `pkg/rpc`.
