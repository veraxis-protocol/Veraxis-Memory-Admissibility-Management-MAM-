package integration

import (
	"context"
	"crypto/ed25519"
	"strings"
	"sync"
	"testing"
	"time"

	"veraxis-memory-admissibility/pkg/audit"
	"veraxis-memory-admissibility/pkg/bitmask"
	"veraxis-memory-admissibility/pkg/evaluate"
	"veraxis-memory-admissibility/pkg/gateway"
	"veraxis-memory-admissibility/pkg/orchestrator"
	"veraxis-memory-admissibility/pkg/quarantine"
	"veraxis-memory-admissibility/pkg/tenant"
)

type orchestratorProfileCache map[[16]byte]gateway.MemoryProfile

func (c orchestratorProfileCache) GetProfile(id [16]byte) (gateway.MemoryProfile, bool) {
	p, ok := c[id]
	return p, ok
}

type recordingProvider struct {
	mu       sync.Mutex
	calls    int
	messages [][]gateway.LLMMessage
	block    chan struct{}
}

func (p *recordingProvider) Invoke(ctx context.Context, messages []gateway.LLMMessage) (gateway.ProviderResponse, error) {
	if p.block != nil {
		select {
		case <-p.block:
		case <-ctx.Done():
			return gateway.ProviderResponse{}, ctx.Err()
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	cp := make([]gateway.LLMMessage, len(messages))
	copy(cp, messages)
	p.messages = append(p.messages, cp)
	return gateway.ProviderResponse{
		Text: "sub-agent processed sanitized supervisor constraints",
		Tokens: gateway.TokenMetrics{
			PromptTokens:     5,
			CompletionTokens: 7,
			TotalTokens:      12,
		},
	}, nil
}

func (p *recordingProvider) Calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func (p *recordingProvider) LastMessages() []gateway.LLMMessage {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.messages) == 0 {
		return nil
	}
	return p.messages[len(p.messages)-1]
}

func newOrchestratorFixture(t *testing.T, max int) (*orchestrator.HandoffCoordinator, *recordingProvider, tenant.IDHash, tenant.IDHash, [16]byte) {
	t.Helper()

	memID := [16]byte{0x20}
	validTenant := tenant.IDHash{0x01}
	validDomain := tenant.IDHash{0x02}

	cache := orchestratorProfileCache{
		memID: {
			MemoryID:   memID,
			TenantHash: validTenant,
			DomainHash: validDomain,
			Flags:      bitmask.FlagLifecycleActive | bitmask.ClassUseContextOnly,
		},
	}

	wrapper := &gateway.ClientWrapper{
		Profiles:       cache,
		PolicyHash:     [32]byte{0x55},
		RuntimeMonitor: quarantine.NewRuntimeMonitor(),
	}

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	provider := &recordingProvider{}
	coord := orchestrator.NewHandoffCoordinator(wrapper, provider, "key_test", priv, max)
	return coord, provider, validTenant, validDomain, memID
}

func TestOrchestratorHandoffPreservesOrderAndSealsLineage(t *testing.T) {
	coord, provider, validTenant, validDomain, memID := newOrchestratorFixture(t, 2)

	raw := []gateway.LLMMessage{
		{Role: "system", Content: "system constraints"},
		{Role: "user", Content: "memory context"},
		{Role: "assistant", Content: "prior summary"},
	}
	bindings := []gateway.MemoryContextBinding{
		{MemoryID: memID, MemoryHash: [32]byte{0xAA}, MessageIdx: 1},
	}

	res, err := coord.ExecuteAgentHandoff(
		context.Background(),
		[16]byte{0x01},
		[16]byte{0x02},
		"sess-1",
		"task-1",
		"actor-1",
		orchestrator.AgentIdentity{AgentID: "sub-agent-1", TenantHash: validTenant, DomainHash: validDomain},
		bitmask.EvaluationMask{AllowedUseClasses: bitmask.RuntimeFlags(bitmask.ClassUseContextOnly)},
		raw,
		bindings,
		"eep_001",
		"aep_001",
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(res.SanitizedPayload) != len(raw) {
		t.Fatalf("message count changed")
	}
	for i := range raw {
		if res.SanitizedPayload[i].Role != raw[i].Role {
			t.Fatalf("message order changed at %d", i)
		}
	}
	if provider.Calls() != 1 {
		t.Fatalf("expected provider invocation")
	}
	if res.InferenceBlock.SessionMAP.SessionID != "sess-1" {
		t.Fatalf("expected session map to bind session")
	}
	if !audit.VerifyLineageRecord(res.ConsequenceToken, res.InferenceBlock.SessionMAP) {
		t.Fatal("expected valid MCR lineage verification")
	}
}

func TestOrchestratorBoundaryLeakagePrevention(t *testing.T) {
	coord, provider, validTenant, validDomain, memID := newOrchestratorFixture(t, 2)

	// Mutate cache profile to different tenant to force hard boundary tombstone.
	profiles := coord.GatewayWrapper.Profiles.(orchestratorProfileCache)
	p := profiles[memID]
	p.TenantHash = tenant.IDHash{0x99}
	profiles[memID] = p

	rawSecret := "RAW SECRET CROSS TENANT MEMORY"
	raw := []gateway.LLMMessage{{Role: "user", Content: rawSecret}}

	res, err := coord.ExecuteAgentHandoff(
		context.Background(),
		[16]byte{0x03},
		[16]byte{0x04},
		"sess-2",
		"task-2",
		"actor-2",
		orchestrator.AgentIdentity{AgentID: "sub-agent-2", TenantHash: validTenant, DomainHash: validDomain},
		bitmask.EvaluationMask{AllowedUseClasses: bitmask.RuntimeFlags(bitmask.ClassUseContextOnly)},
		raw,
		[]gateway.MemoryContextBinding{{MemoryID: memID, MemoryHash: [32]byte{0xBB}, MessageIdx: 0}},
		"eep_002",
		"aep_002",
	)
	if err != nil {
		t.Fatal(err)
	}

	if res.SanitizedPayload[0].Content != gateway.TombstoneHardRefuse {
		t.Fatalf("expected hard-refuse tombstone, got %q", res.SanitizedPayload[0].Content)
	}
	last := provider.LastMessages()
	if len(last) != 1 {
		t.Fatalf("expected provider to receive one sanitized message")
	}
	if strings.Contains(last[0].Content, rawSecret) {
		t.Fatal("raw cross-tenant scratchpad leaked to provider")
	}
	if res.InferenceBlock.SessionMAP.LeafRecords[0].DecisionCode != uint8(evaluate.DecisionHardRefuse) {
		t.Fatal("expected Session MAP leaf to record hard refuse")
	}
}

func TestOrchestratorBackpressureRejectsWithoutProviderInvocation(t *testing.T) {
	coord, provider, validTenant, validDomain, memID := newOrchestratorFixture(t, 1)
	block := make(chan struct{})
	provider.block = block

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()

	errCh := make(chan error, 1)
	go func() {
		_, err := coord.ExecuteAgentHandoff(
			ctx1,
			[16]byte{0x05},
			[16]byte{0x06},
			"sess-3",
			"task-3",
			"actor-3",
			orchestrator.AgentIdentity{AgentID: "sub-agent-3", TenantHash: validTenant, DomainHash: validDomain},
			bitmask.EvaluationMask{AllowedUseClasses: bitmask.RuntimeFlags(bitmask.ClassUseContextOnly)},
			[]gateway.LLMMessage{{Role: "user", Content: "first"}},
			[]gateway.MemoryContextBinding{{MemoryID: memID, MemoryHash: [32]byte{0xCC}, MessageIdx: 0}},
			"eep_003",
			"aep_003",
		)
		errCh <- err
	}()

	time.Sleep(25 * time.Millisecond)

	_, err := coord.ExecuteAgentHandoff(
		context.Background(),
		[16]byte{0x07},
		[16]byte{0x08},
		"sess-4",
		"task-4",
		"actor-4",
		orchestrator.AgentIdentity{AgentID: "sub-agent-4", TenantHash: validTenant, DomainHash: validDomain},
		bitmask.EvaluationMask{AllowedUseClasses: bitmask.RuntimeFlags(bitmask.ClassUseContextOnly)},
		[]gateway.LLMMessage{{Role: "user", Content: "second raw"}},
		[]gateway.MemoryContextBinding{{MemoryID: memID, MemoryHash: [32]byte{0xDD}, MessageIdx: 0}},
		"eep_004",
		"aep_004",
	)
	if err == nil || !strings.Contains(err.Error(), "ORCHESTRATOR_BACKPRESSURE") {
		t.Fatalf("expected backpressure rejection, got %v", err)
	}

	if provider.Calls() != 0 {
		t.Fatal("provider must not be invoked for rejected second handoff while first blocked before invocation completion")
	}

	close(block)
	if err := <-errCh; err != nil {
		t.Fatalf("first handoff should complete after unblock, got %v", err)
	}
	if provider.Calls() != 1 {
		t.Fatalf("expected exactly one provider invocation, got %d", provider.Calls())
	}
}

func TestOrchestratorConcurrencySequence(t *testing.T) {
	coord, _, validTenant, validDomain, memID := newOrchestratorFixture(t, 8)

	var wg sync.WaitGroup
	errs := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := coord.ExecuteAgentHandoff(
				context.Background(),
				[16]byte{byte(i), 1},
				[16]byte{byte(i), 2},
				"sess-c",
				"task-c",
				"actor-c",
				orchestrator.AgentIdentity{AgentID: "sub-agent-c", TenantHash: validTenant, DomainHash: validDomain},
				bitmask.EvaluationMask{AllowedUseClasses: bitmask.RuntimeFlags(bitmask.ClassUseContextOnly)},
				[]gateway.LLMMessage{{Role: "user", Content: "msg"}},
				[]gateway.MemoryContextBinding{{MemoryID: memID, MemoryHash: [32]byte{0xEE}, MessageIdx: 0}},
				"eep_c",
				"aep_c",
			)
			if err != nil && !strings.Contains(err.Error(), "ORCHESTRATOR_BACKPRESSURE") {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("unexpected concurrency error: %v", err)
	}
}
