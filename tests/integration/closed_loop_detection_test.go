package integration

import (
	"context"
	"math"
	"testing"
	"time"

	"veraxis-memory-admissibility/pkg/axis"
	"veraxis-memory-admissibility/pkg/bitmask"
	"veraxis-memory-admissibility/pkg/evaluate"
	"veraxis-memory-admissibility/pkg/gateway"
	"veraxis-memory-admissibility/pkg/quarantine"
	"veraxis-memory-admissibility/pkg/tenant"
)

type closedLoopProfileCache map[[16]byte]gateway.MemoryProfile

func (c closedLoopProfileCache) GetProfile(id [16]byte) (gateway.MemoryProfile, bool) {
	p, ok := c[id]
	return p, ok
}

func closedLoopBaseVectorForTarget(start, end int) axis.StructuralVector {
	v := make(axis.StructuralVector, 128)
	var mag float64
	for i := 0; i < 128; i++ {
		if i >= start && i <= end {
			v[i] = 0.03 * float32(i%5+1)
		} else {
			v[i] = 0.30 * float32(i%5+1)
		}
		mag += float64(v[i] * v[i])
	}
	mag = math.Sqrt(mag)
	for i := 0; i < 128; i++ {
		v[i] = float32(float64(v[i]) / mag)
	}
	return v
}

func closedLoopMutateSubspace(base axis.StructuralVector, start, end int, factor float32) axis.StructuralVector {
	mutated := make(axis.StructuralVector, 128)
	copy(mutated, base)
	for i := start; i <= end; i++ {
		mutated[i] = mutated[i] * factor
	}
	var mag float64
	for i := 0; i < 128; i++ {
		mag += float64(mutated[i] * mutated[i])
	}
	mag = math.Sqrt(mag)
	for i := 0; i < 128; i++ {
		mutated[i] = float32(float64(mutated[i]) / mag)
	}
	return mutated
}

func TestClosedLoopAxisDetectionQuarantinesNextGatewayTurn(t *testing.T) {
	path := t.TempDir() + "/axis-revocation.vm"

	ledger, err := quarantine.NewFileLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()

	monitor := quarantine.NewRuntimeMonitor()

	memID := [16]byte{0x19}
	validTenant := tenant.IDHash{0x01}
	validDomain := tenant.IDHash{0x02}
	policyHash := [32]byte{0x03}

	cache := closedLoopProfileCache{
		memID: {
			MemoryID:   memID,
			TenantHash: validTenant,
			DomainHash: validDomain,
			Flags:      bitmask.FlagLifecycleActive | bitmask.ClassUseContextOnly,
		},
	}

	wrapper := gateway.ClientWrapper{
		Profiles:       cache,
		PolicyHash:     policyHash,
		RuntimeMonitor: monitor,
	}

	mask := bitmask.EvaluationMask{
		AllowedUseClasses: bitmask.RuntimeFlags(bitmask.ClassUseContextOnly),
	}

	firstMessages := []gateway.LLMMessage{{Role: "user", Content: "clean memory content"}}
	firstSanitized, firstLeaves, err := wrapper.SanitizeContextWindow(
		context.Background(),
		validTenant,
		validDomain,
		mask,
		firstMessages,
		[]gateway.MemoryContextBinding{{MemoryID: memID, MemoryHash: [32]byte{0xAA}, MessageIdx: 0}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if firstSanitized[0].Content != "clean memory content" {
		t.Fatal("expected first turn content to pass")
	}
	if !firstLeaves[0].Injected || firstLeaves[0].DecisionCode != uint8(evaluate.DecisionUse) {
		t.Fatalf("expected first turn DecisionUse, got leaf %#v", firstLeaves[0])
	}

	coordinator := axis.NewDriftMonitorCoordinator(
		ledger,
		monitor,
		axis.DefaultDimensions,
		0.35,
		8,
	)

	anchor := closedLoopBaseVectorForTarget(axis.DefaultDimensions.TemporalityStart, axis.DefaultDimensions.TemporalityEnd)
	mutated := closedLoopMutateSubspace(anchor, axis.DefaultDimensions.TemporalityStart, axis.DefaultDimensions.TemporalityEnd, -3.5)

	err = coordinator.ProcessJobForTest(axis.MemoryTransformationJob{
		MemoryID:       memID,
		AnchorVector:   anchor,
		MutatedVector:  mutated,
		OperatorID:     "axis_worker_test",
		SourcePipeline: "summary_compression_pipeline",
		PolicySnapshot: policyHash,
	})
	if err != nil {
		t.Fatal(err)
	}

	events, err := quarantine.ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected one durable quarantine event, got %d", len(events))
	}

	secondMessages := []gateway.LLMMessage{{Role: "user", Content: "same memory content after drift"}}
	secondSanitized, secondLeaves, err := wrapper.SanitizeContextWindow(
		context.Background(),
		validTenant,
		validDomain,
		mask,
		secondMessages,
		[]gateway.MemoryContextBinding{{MemoryID: memID, MemoryHash: [32]byte{0xAA}, MessageIdx: 0}},
	)
	if err != nil {
		t.Fatal(err)
	}

	if secondSanitized[0].Content != gateway.TombstoneQuarantine {
		t.Fatalf("expected quarantine tombstone after async drift, got %q", secondSanitized[0].Content)
	}
	if secondLeaves[0].Injected {
		t.Fatal("quarantined memory must not be injected")
	}
	if secondLeaves[0].DecisionCode != uint8(evaluate.DecisionQuarantine) {
		t.Fatalf("expected DecisionQuarantine, got %d", secondLeaves[0].DecisionCode)
	}
}

func TestDriftMonitorSubmitNonBlockingDropsWhenFull(t *testing.T) {
	coordinator := axis.NewDriftMonitorCoordinator(nil, nil, axis.DefaultDimensions, 0.35, 1)

	job := axis.MemoryTransformationJob{MemoryID: [16]byte{1}}
	if !coordinator.SubmitNonBlocking(job) {
		t.Fatal("first enqueue should succeed")
	}
	if coordinator.SubmitNonBlocking(job) {
		t.Fatal("second enqueue should drop when queue is full")
	}
	stats := coordinator.Stats()
	if stats.Dropped != 1 {
		t.Fatalf("expected one dropped job, got %d", stats.Dropped)
	}
}

func TestDriftMonitorAsyncWorkerProcessesQueue(t *testing.T) {
	path := t.TempDir() + "/axis-worker.vm"
	ledger, err := quarantine.NewFileLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()

	monitor := quarantine.NewRuntimeMonitor()
	coordinator := axis.NewDriftMonitorCoordinator(ledger, monitor, axis.DefaultDimensions, 0.35, 2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coordinator.Start(ctx, 1)

	anchor := closedLoopBaseVectorForTarget(axis.DefaultDimensions.EpistemicStart, axis.DefaultDimensions.EpistemicEnd)
	mutated := closedLoopMutateSubspace(anchor, axis.DefaultDimensions.EpistemicStart, axis.DefaultDimensions.EpistemicEnd, -3.5)

	if !coordinator.SubmitNonBlocking(axis.MemoryTransformationJob{
		MemoryID:       [16]byte{0x42},
		AnchorVector:   anchor,
		MutatedVector:  mutated,
		OperatorID:     "axis_worker_test",
		SourcePipeline: "async_test",
	}) {
		t.Fatal("expected enqueue")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if coordinator.Stats().Quarantined == 1 {
			cancel()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("worker did not process queue before deadline")
}
