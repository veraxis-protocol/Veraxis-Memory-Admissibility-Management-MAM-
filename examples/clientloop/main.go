package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"time"

	"veraxis-memory-admissibility/pkg/audit"
	"veraxis-memory-admissibility/pkg/bitmask"
	"veraxis-memory-admissibility/pkg/gateway"
	"veraxis-memory-admissibility/pkg/tenant"
)

type localCache map[[16]byte]gateway.MemoryProfile

func (l localCache) GetProfile(id [16]byte) (gateway.MemoryProfile, bool) {
	p, ok := l[id]
	return p, ok
}

type snapshotVerifier map[[32]byte]bool

func (s snapshotVerifier) KnownImmutableSnapshot(hash [32]byte) bool {
	return s[hash]
}

func hash(input string) [32]byte {
	return sha256.Sum256([]byte(input))
}

func main() {
	validTenant := tenant.IDHash(hash("tenant_enterprise_alpha"))
	rogueTenant := tenant.IDHash(hash("tenant_attacker_omega"))
	defaultDomain := tenant.IDHash(hash("domain_customer_support"))
	policyHash := hash("policy_snapshot_v1_2026")

	idGood := [16]byte{1}
	idQual := [16]byte{2}
	idRogue := [16]byte{3}

	cache := localCache{
		idGood:  {MemoryID: idGood, TenantHash: validTenant, DomainHash: defaultDomain, Flags: bitmask.FlagLifecycleActive | bitmask.ClassUseContextOnly},
		idQual:  {MemoryID: idQual, TenantHash: validTenant, DomainHash: defaultDomain, Flags: bitmask.FlagLifecycleActive | bitmask.ClassUseToneAdjustment, UsageConstraints: "may be used for tone/context only; prohibited for automated denial"},
		idRogue: {MemoryID: idRogue, TenantHash: rogueTenant, DomainHash: defaultDomain, Flags: bitmask.FlagLifecycleActive | bitmask.ClassUseContextOnly},
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	runner := gateway.LifecycleRunner{
		Wrapper: &gateway.ClientWrapper{Profiles: cache, PolicyHash: policyHash},
		Adapter: &gateway.OpenAIAdapter{ModelName: "gpt-4o"},
		Provider: gateway.MockInferenceProvider{Response: gateway.ProviderResponse{
			Text:   "Processed application query cleanly based on authorized memory states.",
			Tokens: gateway.TokenMetrics{PromptTokens: 256, CompletionTokens: 32, TotalTokens: 288},
		}},
	}

	messages := []gateway.LLMMessage{
		{Role: "system", Content: "You are a customer service representative agent loop."},
		{Role: "user", Content: "verified secure context fragment"},
		{Role: "user", Content: "user emotional state context flag"},
		{Role: "user", Content: "rogue cross-tenant memory prompt payload"},
	}

	bindings := []gateway.MemoryContextBinding{
		{MemoryID: idGood, MemoryHash: hash("good"), MessageIdx: 1},
		{MemoryID: idQual, MemoryHash: hash("qual"), MessageIdx: 2},
		{MemoryID: idRogue, MemoryHash: hash("rogue"), MessageIdx: 3},
	}

	block, payload, err := runner.ExecuteAdmissibleTurn(messages, bindings, gateway.MockRuntimeContext{
		Ctx:                context.Background(),
		Tenant:             validTenant,
		Domain:             defaultDomain,
		Mask:               bitmask.EvaluationMask{AllowedUseClasses: bitmask.RuntimeFlags(bitmask.ClassUseContextOnly | bitmask.ClassUseToneAdjustment)},
		MapID:              [16]byte{100},
		SessionID:          "session_example_01",
		AgentID:            "agent_support_alpha",
		ActorID:            "actor_user_99",
		TaskID:             "task_refund_check",
		ContextHash:        hash("runtime_context_fingerprint"),
		PrivateKey:         priv,
		KeyID:              "key_id_example_01",
		PolicySnapshotHash: policyHash,
		Now:                time.Now(),
		TTL:                time.Hour,
	})
	if err != nil {
		fmt.Printf("client loop failed: %v\n", err)
		os.Exit(1)
	}

	for _, msg := range payload.Messages {
		if strings.Contains(msg.Content, "rogue cross-tenant memory") {
			fmt.Println("rogue memory leaked into provider payload")
			os.Exit(1)
		}
	}

	res, err := audit.VerifySessionMAPWithPolicy(pub, block.SessionMAP, snapshotVerifier{policyHash: true})
	if err != nil || !res.ReplayMatch {
		fmt.Printf("audit replay failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("VERAXIS CLIENT LOOP: SUCCESS")
	fmt.Printf("InferenceID: %s\n", block.InferenceID)
	fmt.Printf("Model: %s\n", block.ModelName)
	fmt.Printf("TotalTokens: %d\n", block.UsageTokens.TotalTokens)
}
