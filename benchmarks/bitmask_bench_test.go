package benchmarks

import (
	"testing"

	"veraxis-memory-admissibility/pkg/bitmask"
	"veraxis-memory-admissibility/pkg/evaluate"
	"veraxis-memory-admissibility/pkg/tenant"
)

func BenchmarkEvaluateMemoryHotPath(b *testing.B) {
	var tid tenant.IDHash
	var did tenant.IDHash
	tid[0] = 1
	did[0] = 2

	flags := bitmask.FlagLifecycleActive | bitmask.ClassUseToneAdjustment | bitmask.Tier1Preference
	mask := bitmask.EvaluationMask{
		AllowedUseClasses:   bitmask.RuntimeFlags(bitmask.ClassUseToneAdjustment),
		ProhibitedUseBlocks: bitmask.RuntimeFlags(bitmask.BlockUseAutomatedDenial),
		ProhibitedSafety:    bitmask.RuntimeFlags(bitmask.FlagSafetyQuarantined | bitmask.FlagSafetyPoisoningSuspected),
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = evaluate.EvaluateMemoryHotPath(tid, tid, did, did, flags, mask)
	}
}
