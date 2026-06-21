package integration

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"veraxis-memory-admissibility/pkg/audit"
	"veraxis-memory-admissibility/pkg/bitmask"
	"veraxis-memory-admissibility/pkg/evaluate"
	"veraxis-memory-admissibility/pkg/gateway"
	"veraxis-memory-admissibility/pkg/merkle"
	"veraxis-memory-admissibility/pkg/quarantine"
	"veraxis-memory-admissibility/pkg/sessionmap"
	"veraxis-memory-admissibility/pkg/tenant"
)

type quarantineProfileCache map[[16]byte]gateway.MemoryProfile

func (q quarantineProfileCache) GetProfile(id [16]byte) (gateway.MemoryProfile, bool) {
	p, ok := q[id]
	return p, ok
}

type runtimeVerifier struct {
	hash    [32]byte
	version uint64
}

func (r runtimeVerifier) KnownRuntimeSnapshot(hash [32]byte, version uint64) bool {
	return hash == r.hash && version == r.version
}

type policyVerifier2 map[[32]byte]bool

func (p policyVerifier2) KnownImmutableSnapshot(hash [32]byte) bool {
	return p[hash]
}

func TestDynamicQuarantineOverridesAllowedUse(t *testing.T) {
	memID := [16]byte{7}
	validTenant := tenant.IDHash{1}
	validDomain := tenant.IDHash{2}

	monitor := quarantine.NewRuntimeMonitor()
	event := quarantine.RevocationEvent{
		EventID:   [16]byte{9},
		MemoryID:  memID,
		EventType: quarantine.EventQuarantineMemory,
		Reason:    quarantine.ReasonPoisoningSuspected,
		CreatedAt: time.Unix(100, 0),
	}
	monitor.AppendEvent(event)
	snap := monitor.CompileAndSwap(time.Unix(101, 0))

	cache := quarantineProfileCache{
		memID: {MemoryID: memID, TenantHash: validTenant, DomainHash: validDomain, Flags: bitmask.FlagLifecycleActive | bitmask.ClassUseContextOnly},
	}
	wrapper := gateway.ClientWrapper{Profiles: cache, RuntimeMonitor: monitor}

	messages := []gateway.LLMMessage{{Role: "user", Content: "poisoned but statically allowed memory"}}
	sanitized, leaves, err := wrapper.SanitizeContextWindow(
		context.Background(),
		validTenant,
		validDomain,
		bitmask.EvaluationMask{AllowedUseClasses: bitmask.RuntimeFlags(bitmask.ClassUseContextOnly)},
		messages,
		[]gateway.MemoryContextBinding{{MemoryID: memID, MessageIdx: 0}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if sanitized[0].Content != gateway.TombstoneQuarantine {
		t.Fatalf("expected quarantine tombstone, got %q", sanitized[0].Content)
	}
	if leaves[0].Injected {
		t.Fatal("quarantined memory must not be injected")
	}
	if leaves[0].DecisionCode != uint8(evaluate.DecisionQuarantine) {
		t.Fatal("expected DecisionQuarantine")
	}
	if snap.Version == 0 || snap.SnapshotHash == ([32]byte{}) {
		t.Fatal("expected active snapshot info")
	}
}

func TestTombstoneAndRevokedDecisions(t *testing.T) {
	memDeleted := [16]byte{1}
	memRevoked := [16]byte{2}

	monitor := quarantine.NewRuntimeMonitor()
	monitor.AppendEvent(quarantine.RevocationEvent{EventID: [16]byte{3}, MemoryID: memDeleted, EventType: quarantine.EventDeleteRequested})
	monitor.AppendEvent(quarantine.RevocationEvent{EventID: [16]byte{4}, MemoryID: memRevoked, EventType: quarantine.EventRevokeMemory})
	monitor.CompileAndSwap(time.Unix(100, 0))

	if d := monitor.Lookup(memDeleted); d.Decision != evaluate.DecisionDeleteRequested {
		t.Fatalf("expected delete requested, got %v", d.Decision)
	}
	if d := monitor.Lookup(memRevoked); d.Decision != evaluate.DecisionRefuse {
		t.Fatalf("expected refuse for revoked, got %v", d.Decision)
	}
}

func TestSnapshotSwapChangesNextGatewayTurn(t *testing.T) {
	memID := [16]byte{1}
	validTenant := tenant.IDHash{1}
	validDomain := tenant.IDHash{2}
	monitor := quarantine.NewRuntimeMonitor()

	cache := quarantineProfileCache{
		memID: {MemoryID: memID, TenantHash: validTenant, DomainHash: validDomain, Flags: bitmask.FlagLifecycleActive | bitmask.ClassUseContextOnly},
	}
	wrapper := gateway.ClientWrapper{Profiles: cache, RuntimeMonitor: monitor}

	run := func() (string, bool) {
		sanitized, leaves, err := wrapper.SanitizeContextWindow(
			context.Background(),
			validTenant,
			validDomain,
			bitmask.EvaluationMask{AllowedUseClasses: bitmask.RuntimeFlags(bitmask.ClassUseContextOnly)},
			[]gateway.LLMMessage{{Role: "user", Content: "memory"}},
			[]gateway.MemoryContextBinding{{MemoryID: memID, MessageIdx: 0}},
		)
		if err != nil {
			t.Fatal(err)
		}
		return sanitized[0].Content, leaves[0].Injected
	}

	content, injected := run()
	if content != "memory" || !injected {
		t.Fatal("expected clean memory before snapshot update")
	}

	monitor.AppendEvent(quarantine.RevocationEvent{EventID: [16]byte{8}, MemoryID: memID, EventType: quarantine.EventQuarantineMemory})
	monitor.CompileAndSwap(time.Unix(100, 0))

	content, injected = run()
	if content != gateway.TombstoneQuarantine || injected {
		t.Fatal("expected quarantine after snapshot swap")
	}
}

func TestSessionMAPRuntimeSnapshotMutationFails(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	leaf := merkle.LeafRecord{MemoryID: [16]byte{1}, MemoryHash: [32]byte{2}, DecisionCode: uint8(evaluate.DecisionUse), Injected: true, PolicyHash: [32]byte{4}, ReasonCodeHash: [32]byte{5}}
	policyHash := [32]byte{4}
	runtimeHash := [32]byte{5}

	smap, err := sessionmap.GenerateSessionMAPWithRuntimeSnapshot(
		[16]byte{1}, "sess", "agent", "actor", "task",
		[32]byte{2}, [32]byte{3}, policyHash, runtimeHash, 7,
		[]merkle.LeafRecord{leaf},
		priv, "key", time.Hour, time.Unix(100, 0),
	)
	if err != nil {
		t.Fatal(err)
	}

	res, err := audit.VerifySessionMAPWithPolicyAndRuntime(
		pub,
		smap,
		policyVerifier2{policyHash: true},
		runtimeVerifier{hash: runtimeHash, version: 7},
	)
	if err != nil || !res.ReplayMatch {
		t.Fatalf("expected runtime-bound replay match: %v", err)
	}

	smap.RuntimeSnapshotVersion = 8
	res, err = audit.VerifySessionMAPWithPolicyAndRuntime(
		pub,
		smap,
		policyVerifier2{policyHash: true},
		runtimeVerifier{hash: runtimeHash, version: 7},
	)
	if err != nil {
		t.Fatal(err)
	}
	if res.ReplayMatch {
		t.Fatal("expected replay failure after runtime snapshot version mutation")
	}
}
