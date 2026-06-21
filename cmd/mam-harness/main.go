package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"veraxis-memory-admissibility/pkg/audit"
	"veraxis-memory-admissibility/pkg/bitmask"
	"veraxis-memory-admissibility/pkg/gateway"
	"veraxis-memory-admissibility/pkg/sessionmap"
	"veraxis-memory-admissibility/pkg/tenant"
)

type LLMProviderAdapter interface {
	Invoke(ctx context.Context, messages []gateway.LLMMessage) error
}

type MockProvider struct{}

func (m MockProvider) Invoke(ctx context.Context, messages []gateway.LLMMessage) error {
	for _, msg := range messages {
		if strings.Contains(msg.Content, "rogue cross-tenant memory") {
			return errors.New("SECURITY_BREACH: inadmissible raw memory reached provider payload")
		}
	}
	return nil
}

func hashBytes(input []byte) [32]byte {
	return sha256.Sum256(input)
}

type LocalCache struct {
	profiles map[[16]byte]gateway.MemoryProfile
}

func (c *LocalCache) GetProfile(id [16]byte) (gateway.MemoryProfile, bool) {
	p, ok := c.profiles[id]
	return p, ok
}

type StaticSnapshotVerifier struct {
	activeHash [32]byte
}

func (v StaticSnapshotVerifier) KnownImmutableSnapshot(hash [32]byte) bool {
	return hash == v.activeHash
}

func assert(condition bool, message string) {
	if !condition {
		fmt.Printf("ASSERTION_FAILED: %s\n", message)
		os.Exit(1)
	}
}

func main() {
	fmt.Println("Initializing Veraxis Admissible Memory Control Harness...")

	validTenant := tenant.IDHash(hashBytes([]byte("tenant_enterprise_alpha")))
	rogueTenant := tenant.IDHash(hashBytes([]byte("tenant_attacker_omega")))
	defaultDomain := tenant.IDHash(hashBytes([]byte("domain_customer_support")))

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Identity generation failed: %v\n", err)
		os.Exit(1)
	}

	idGood := [16]byte{1}
	idQual := [16]byte{2}
	idRogue := [16]byte{3}

	cache := &LocalCache{
		profiles: map[[16]byte]gateway.MemoryProfile{
			idGood: {
				MemoryID:   idGood,
				TenantHash: validTenant,
				DomainHash: defaultDomain,
				Flags:      bitmask.MemoryFlags(bitmask.FlagLifecycleActive | bitmask.ClassUseContextOnly),
			},
			idQual: {
				MemoryID:         idQual,
				TenantHash:       validTenant,
				DomainHash:       defaultDomain,
				Flags:            bitmask.MemoryFlags(bitmask.FlagLifecycleActive | bitmask.ClassUseToneAdjustment),
				UsageConstraints: "may be used for tone/context only; prohibited for automated denial",
			},
			idRogue: {
				MemoryID:   idRogue,
				TenantHash: rogueTenant,
				DomainHash: defaultDomain,
				Flags:      bitmask.MemoryFlags(bitmask.FlagLifecycleActive | bitmask.ClassUseContextOnly),
			},
		},
	}

	activeMask := bitmask.EvaluationMask{
		RequiredLifecycle:   bitmask.RuntimeFlags(bitmask.FlagLifecycleActive),
		ProhibitedSafety:    bitmask.RuntimeFlags(bitmask.FlagSafetyQuarantined),
		AllowedUseClasses:   bitmask.RuntimeFlags(bitmask.ClassUseContextOnly | bitmask.ClassUseToneAdjustment),
		ProhibitedUseBlocks: bitmask.RuntimeFlags(bitmask.BlockUseAutomatedDenial),
	}

	incomingMessages := []gateway.LLMMessage{
		{Role: "system", Content: "You are a customer service representative agent loop."},
		{Role: "user", Content: "Prior interaction history payload: verified secure context fragment."},
		{Role: "user", Content: "Prior interaction history payload: user emotional state context flag."},
		{Role: "user", Content: "Prior interaction history payload: rogue cross-tenant memory prompt payload."},
	}

	bindings := []gateway.MemoryContextBinding{
		{MemoryID: idGood, MemoryHash: hashBytes([]byte("good")), MessageIdx: 1},
		{MemoryID: idQual, MemoryHash: hashBytes([]byte("qual")), MessageIdx: 2},
		{MemoryID: idRogue, MemoryHash: hashBytes([]byte("rogue")), MessageIdx: 3},
	}

	policyHash := hashBytes([]byte("policy_snapshot_v1_2026"))
	wrapper := &gateway.ClientWrapper{
		Profiles:   cache,
		PolicyHash: policyHash,
	}

	ctx := context.Background()
	sanitizedMessages, leaves, err := wrapper.SanitizeContextWindow(
		ctx,
		validTenant,
		defaultDomain,
		activeMask,
		incomingMessages,
		bindings,
	)
	if err != nil {
		fmt.Printf("Gateway Interception Fault: %v\n", err)
		os.Exit(1)
	}

	assert(len(leaves) == 3, "expected three Merkle leaves")
	assert(sanitizedMessages[1].Content == incomingMessages[1].Content, "authorized memory should remain unchanged")
	assert(strings.Contains(sanitizedMessages[2].Content, "[VERAXIS QUALIFIED MEMORY:"), "qualified memory must contain constraint annotation")
	assert(sanitizedMessages[3].Content == gateway.TombstoneHardRefuse, "rogue memory must be replaced by hard-refuse tombstone")
	assert(leaves[0].Injected, "good memory leaf must be injected")
	assert(leaves[1].Injected, "qualified memory leaf must be injected")
	assert(!leaves[2].Injected, "rogue memory leaf must not be injected")

	provider := MockProvider{}
	if err := provider.Invoke(ctx, sanitizedMessages); err != nil {
		fmt.Printf("CRITICAL CONTROL FAILURE: %v\n", err)
		os.Exit(1)
	}

	if err := provider.Invoke(ctx, incomingMessages); err == nil {
		fmt.Println("CRITICAL CONTROL FAILURE: raw unsanitized payload unexpectedly passed MockProvider")
		os.Exit(1)
	}

	fmt.Println("✔ Step 1 & 2: Gateway interception verified. Rogue content successfully stripped.")

	mapID := [16]byte{100}
	contextHash := hashBytes([]byte("runtime_context_fingerprint"))
	now := time.Now()

	smap, err := sessionmap.GenerateSessionMAP(
		mapID,
		"session_test_01",
		"agent_support_alpha",
		"actor_user_99",
		"task_refund_check",
		[32]byte(validTenant),
		contextHash,
		policyHash,
		leaves,
		privKey,
		"key_id_harness_01",
		time.Hour,
		now,
	)
	if err != nil {
		fmt.Printf("Session MAP generation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✔ Step 3: Single-turn Session MAP generated and signed.")

	verifier := StaticSnapshotVerifier{activeHash: policyHash}

	res, err := audit.VerifySessionMAPWithPolicy(pubKey, smap, verifier)
	if err != nil || !res.ReplayMatch {
		fmt.Printf("CRITICAL AUDIT FAILURE: Replay mismatch or verification bug. Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✔ Step 4: Audit verification replay matched completely.")
	fmt.Println()
	fmt.Println("=======================================================")
	fmt.Println("VERAXIS STATUS: SUCCESS. Evidence control chain closed.")
	fmt.Println("=======================================================")
}
