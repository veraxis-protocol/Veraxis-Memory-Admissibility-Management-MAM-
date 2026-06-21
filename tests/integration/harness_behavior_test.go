package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"veraxis-memory-admissibility/pkg/audit"
	"veraxis-memory-admissibility/pkg/bitmask"
	"veraxis-memory-admissibility/pkg/gateway"
	"veraxis-memory-admissibility/pkg/sessionmap"
	"veraxis-memory-admissibility/pkg/tenant"
)

type harnessProfileCache map[[16]byte]gateway.MemoryProfile

func (h harnessProfileCache) GetProfile(id [16]byte) (gateway.MemoryProfile, bool) {
	p, ok := h[id]
	return p, ok
}

type harnessVerifier struct{ activeHash [32]byte }

func (h harnessVerifier) KnownImmutableSnapshot(hash [32]byte) bool {
	return hash == h.activeHash
}

func hHash(input string) [32]byte {
	return sha256.Sum256([]byte(input))
}

func TestLocalHarnessBehavioralInvariant(t *testing.T) {
	validTenant := tenant.IDHash(hHash("tenant_enterprise_alpha"))
	rogueTenant := tenant.IDHash(hHash("tenant_attacker_omega"))
	defaultDomain := tenant.IDHash(hHash("domain_customer_support"))

	idGood := [16]byte{1}
	idQual := [16]byte{2}
	idRogue := [16]byte{3}

	cache := harnessProfileCache{
		idGood:  {MemoryID: idGood, TenantHash: validTenant, DomainHash: defaultDomain, Flags: bitmask.FlagLifecycleActive | bitmask.ClassUseContextOnly},
		idQual:  {MemoryID: idQual, TenantHash: validTenant, DomainHash: defaultDomain, Flags: bitmask.FlagLifecycleActive | bitmask.ClassUseToneAdjustment, UsageConstraints: "tone/context only"},
		idRogue: {MemoryID: idRogue, TenantHash: rogueTenant, DomainHash: defaultDomain, Flags: bitmask.FlagLifecycleActive | bitmask.ClassUseContextOnly},
	}

	policyHash := hHash("policy_snapshot_v1_2026")
	wrapper := gateway.ClientWrapper{Profiles: cache, PolicyHash: policyHash}

	messages := []gateway.LLMMessage{
		{Role: "system", Content: "system"},
		{Role: "user", Content: "good memory"},
		{Role: "user", Content: "qualified memory"},
		{Role: "user", Content: "rogue cross-tenant memory prompt payload"},
	}

	bindings := []gateway.MemoryContextBinding{
		{MemoryID: idGood, MemoryHash: hHash("good"), MessageIdx: 1},
		{MemoryID: idQual, MemoryHash: hHash("qual"), MessageIdx: 2},
		{MemoryID: idRogue, MemoryHash: hHash("rogue"), MessageIdx: 3},
	}

	mask := bitmask.EvaluationMask{
		AllowedUseClasses: bitmask.RuntimeFlags(bitmask.ClassUseContextOnly | bitmask.ClassUseToneAdjustment),
		ProhibitedSafety:  bitmask.RuntimeFlags(bitmask.FlagSafetyQuarantined),
	}

	sanitized, leaves, err := wrapper.SanitizeContextWindow(context.Background(), validTenant, defaultDomain, mask, messages, bindings)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(sanitized[3].Content, "rogue cross-tenant memory") {
		t.Fatal("rogue memory leaked into sanitized context")
	}
	if !strings.Contains(sanitized[2].Content, "[VERAXIS QUALIFIED MEMORY:") {
		t.Fatal("qualified memory was not annotated")
	}
	if len(leaves) != 3 || !leaves[0].Injected || !leaves[1].Injected || leaves[2].Injected {
		t.Fatal("unexpected injected leaf states")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	smap, err := sessionmap.GenerateSessionMAP(
		[16]byte{9}, "sess", "agent", "actor", "task",
		[32]byte(validTenant), hHash("runtime"), policyHash, leaves,
		priv, "key", time.Hour, time.Unix(100, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	res, err := audit.VerifySessionMAPWithPolicy(pub, smap, harnessVerifier{activeHash: policyHash})
	if err != nil {
		t.Fatal(err)
	}
	if !res.ReplayMatch {
		t.Fatal("expected audit replay match")
	}
}
