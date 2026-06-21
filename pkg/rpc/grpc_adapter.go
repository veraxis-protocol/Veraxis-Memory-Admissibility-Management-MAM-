//go:build grpc

package rpc

// This file is intentionally isolated behind the `grpc` build tag.
// In a connected build environment, generate Go bindings from schemas/mam.proto
// with protoc-gen-go and protoc-gen-go-grpc, then bind AdmissibilityServer to
// the generated MemoryAdmissibilityServiceServer interface.
//
// The core runtime packages do not import this file or any gRPC package.
