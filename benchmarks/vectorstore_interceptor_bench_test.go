package benchmarks

import (
	"context"
	"testing"

	"veraxis-memory-admissibility/pkg/axis"
	"veraxis-memory-admissibility/pkg/integrations/vectorstore"
	"veraxis-memory-admissibility/pkg/quarantine"
)

func BenchmarkVectorStoreInterceptorSubmit50(b *testing.B) {
	coord := axis.NewDriftMonitorCoordinator(nil, quarantine.NewRuntimeMonitor(), axis.DefaultDimensions, 0.35, 1024)
	wrapper := vectorstore.NewInterceptorWrapper(coord, "bench", "vectorstore", [32]byte{0x01})

	base := make(axis.StructuralVector, 128)
	for i := range base {
		base[i] = float32((i % 7) + 1)
	}

	anchors := make([]vectorstore.VectorRecord, 50)
	retrieved := make([]vectorstore.VectorRecord, 50)
	for i := 0; i < 50; i++ {
		id := [16]byte{byte(i)}
		anchors[i] = vectorstore.VectorRecord{MemoryID: id, Embedding: base}
		retrieved[i] = vectorstore.VectorRecord{MemoryID: id, Embedding: base}
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = wrapper.InterceptQueryResults(context.Background(), anchors, retrieved)
	}
}
