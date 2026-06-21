package benchmarks

import (
	"testing"

	"veraxis-memory-admissibility/pkg/audit"
	"veraxis-memory-admissibility/pkg/sessionmap"
)

func BenchmarkCompileLineageRecord(b *testing.B) {
	smap := sessionmap.SessionMAP{
		SessionMAPID:           [16]byte{1},
		MerkleRoot:             [32]byte{2},
		PolicySnapshotHash:     [32]byte{3},
		RuntimeSnapshotHash:    [32]byte{4},
		RuntimeSnapshotVersion: 42,
	}
	mcrID := [16]byte{5}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := audit.CompileLineageRecord(mcrID, smap, "eep_9921a", "aep_4410b", 1700000000); err != nil {
			b.Fatal(err)
		}
	}
}
