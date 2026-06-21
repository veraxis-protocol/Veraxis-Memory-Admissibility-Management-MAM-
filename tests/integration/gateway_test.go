package integration

import (
	"context"
	"testing"

	"veraxis-memory-admissibility/pkg/bitmask"
	"veraxis-memory-admissibility/pkg/evaluate"
	"veraxis-memory-admissibility/pkg/gateway"
	"veraxis-memory-admissibility/pkg/tenant"
)

type profileCache map[[16]byte]gateway.MemoryProfile

func (p profileCache) GetProfile(memoryID [16]byte) (gateway.MemoryProfile, bool) {
	v, ok := p[memoryID]
	return v, ok
}

func TestGatewayValidAndHardRefusedMemory(t *testing.T) {
	var memA, memB [16]byte
	memA[0] = 1
	memB[0] = 2

	runtimeTenant := tenant.IDHash{1}
	runtimeDomain := tenant.IDHash{2}
	otherTenant := tenant.IDHash{9}

	cache := profileCache{
		memA: {MemoryID: memA, TenantHash: runtimeTenant, DomainHash: runtimeDomain, Flags: bitmask.FlagLifecycleActive | bitmask.ClassUseToneAdjustment},
		memB: {MemoryID: memB, TenantHash: otherTenant, DomainHash: runtimeDomain, Flags: bitmask.FlagLifecycleActive | bitmask.ClassUseToneAdjustment},
	}

	w := gateway.ClientWrapper{Profiles: cache}
	messages := []gateway.LLMMessage{
		{Role: "system", Content: "valid memory"},
		{Role: "system", Content: "cross tenant memory"},
	}

	_, leaves, err := w.SanitizeContextWindow(context.Background(), runtimeTenant, runtimeDomain, bitmask.EvaluationMask{
		AllowedUseClasses: bitmask.RuntimeFlags(bitmask.ClassUseToneAdjustment),
	}, messages, []gateway.MemoryContextBinding{
		{MemoryID: memA, MessageIdx: 0},
		{MemoryID: memB, MessageIdx: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !leaves[0].Injected || leaves[1].Injected {
		t.Fatalf("expected first injected and second stripped")
	}
	if leaves[1].DecisionCode != uint8(evaluate.DecisionHardRefuse) {
		t.Fatalf("expected hard refuse")
	}
}
