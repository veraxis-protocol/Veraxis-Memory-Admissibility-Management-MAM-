package main

import (
	"fmt"

	"veraxis-memory-admissibility/pkg/quarantine"
	"veraxis-memory-admissibility/pkg/rpc"
)

func main() {
	server := rpc.AdmissibilityServer{
		Monitor: quarantine.NewRuntimeMonitor(),
	}
	if server.Monitor == nil {
		panic("runtime monitor unavailable")
	}
	fmt.Println("MAM server edge initialized. Build with official gRPC bindings when google.golang.org/grpc is available.")
}
