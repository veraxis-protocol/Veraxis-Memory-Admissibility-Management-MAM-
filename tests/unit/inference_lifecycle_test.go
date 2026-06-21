package unit

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
	"veraxis-memory-admissibility/pkg/tenant"
)

type inferenceProfileCache map[[16]byte]gateway.MemoryProfile

func (p inferenceProfileCache) GetProfile(id [16]byte) (gateway.MemoryProfile, bool) {
	v, ok := p[id]
	return v, ok
}

type inferencePolicyVerifier map[[32]byte]bool

func (p inferencePolicyVerifier) KnownImmutableSnapshot(hash [32]byte) bool {
	return p[hash]
}

func inferenceHash(input string) [32]byte {
	return sha256.Sum256([]byte(input))
}

func buildInferenceRuntime(t *testing.T) (
	*gateway.LifecycleRunner,
	gateway.MockRuntimeContext,
	[]gateway.LLMMessage,
	[]gateway.MemoryContextBinding,
	ed25519.PublicKey,
	[32]byte,
) {
	t.Helper()

	validTenant := tenant.IDHash(inferenceHash("tenant_enterprise_alpha"))
	rogueTenant := tenant.IDHash(inferenceHash("tenant_attacker_omega"))
	defaultDomain := tenant.IDHash(inferenceHash("domain_customer_support"))

	idGood := [16]byte{1}
	idQual := [16]byte{2}
	idRogue := [16]byte{3}

	policyHash := inferenceHash("policy_snapshot_v1_2026")

	cache := inferenceProfileCache{
		idGood: {
			MemoryID:   idGood,
			TenantHash: validTenant,
			DomainHash: defaultDomain,
			Flags:      bitmask.FlagLifecycleActive | bitmask.ClassUseContextOnly,
		},
		idQual: {
			MemoryID:         idQual,
			TenantHash:       validTenant,
			DomainHash:       defaultDomain,
			Flags:            bitmask.FlagLifecycleActive | bitmask.ClassUseToneAdjustment,
			UsageConstraints: "may be used for tone/context only; prohibited for automated denial",
		},
		idRogue: {
			MemoryID:   idRogue,
			TenantHash: rogueTenant,
			DomainHash: defaultDomain,
			Flags:      bitmask.FlagLifecycleActive | bitmask.ClassUseContextOnly,
		},
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	runner := &gateway.LifecycleRunner{
		Wrapper: &gateway.ClientWrapper{
			Profiles:   cache,
			PolicyHash: policyHash,
		},
		Adapter: &gateway.OpenAIAdapter{ModelName: "gpt-4o"},
		Provider: gateway.MockInferenceProvider{
			Response: gateway.ProviderResponse{
				Text: "Processed application query cleanly based on authorized memory states.",
				Tokens: gateway.TokenMetrics{
					PromptTokens:     256,
					CompletionTokens: 32,
					TotalTokens:      288,
				},
			},
		},
	}

	messages := []gateway.LLMMessage{
		{Role: "system", Content: "You are a customer service representative agent loop."},
		{Role: "user", Content: "Prior interaction history payload: verified secure context fragment."},
		{Role: "user", Content: "Prior interaction history payload: user emotional state context flag."},
		{Role: "user", Content: "Prior interaction history payload: rogue cross-tenant memory prompt payload."},
	}

	bindings := []gateway.MemoryContextBinding{
		{MemoryID: idGood, MemoryHash: inferenceHash("good"), MessageIdx: 1},
		{MemoryID: idQual, MemoryHash: inferenceHash("qual"), MessageIdx: 2},
		{MemoryID: idRogue, MemoryHash: inferenceHash("rogue"), MessageIdx: 3},
	}

	params := gateway.MockRuntimeContext{
		Ctx:                context.Background(),
		Tenant:             validTenant,
		Domain:             defaultDomain,
		Mask:               bitmask.EvaluationMask{AllowedUseClasses: bitmask.RuntimeFlags(bitmask.ClassUseContextOnly | bitmask.ClassUseToneAdjustment)},
		MapID:              [16]byte{100},
		SessionID:          "session_test_01",
		AgentID:            "agent_support_alpha",
		ActorID:            "actor_user_99",
		TaskID:             "task_refund_check",
		ContextHash:        inferenceHash("runtime_context_fingerprint"),
		PrivateKey:         priv,
		KeyID:              "key_id_test_01",
		PolicySnapshotHash: policyHash,
		Now:                time.Unix(1000, 0),
		TTL:                time.Hour,
	}

	return runner, params, messages, bindings, pub, policyHash
}

func TestAdmissibleInferenceBlockVerifies(t *testing.T) {
	runner, params, messages, bindings, pub, policyHash := buildInferenceRuntime(t)

	block, providerPayload, err := runner.ExecuteAdmissibleTurn(messages, bindings, params)
	if err != nil {
		t.Fatal(err)
	}

	if block.ResponseText == "" {
		t.Fatal("expected response text")
	}
	if block.UsageTokens.TotalTokens != 288 {
		t.Fatalf("token metrics not bound: got %d", block.UsageTokens.TotalTokens)
	}
	if block.SessionMAP.MerkleRoot == ([32]byte{}) {
		t.Fatal("expected bound Session MAP")
	}
	if block.ModelName != "gpt-4o" || providerPayload.Model != "gpt-4o" {
		t.Fatal("model binding mismatch")
	}

	res, err := audit.VerifySessionMAPWithPolicy(pub, block.SessionMAP, inferencePolicyVerifier{policyHash: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.ReplayMatch {
		t.Fatal("expected replay match")
	}
}

func TestInferenceBlockNoRogueMemoryInProviderPayload(t *testing.T) {
	runner, params, messages, bindings, _, _ := buildInferenceRuntime(t)

	_, providerPayload, err := runner.ExecuteAdmissibleTurn(messages, bindings, params)
	if err != nil {
		t.Fatal(err)
	}

	for _, msg := range providerPayload.Messages {
		if strings.Contains(msg.Content, "rogue cross-tenant memory") {
			t.Fatal("rogue memory leaked into provider payload")
		}
	}
	if providerPayload.Messages[3].Content != gateway.TombstoneHardRefuse {
		t.Fatal("expected hard-refuse tombstone in provider payload")
	}
	if !strings.Contains(providerPayload.Messages[2].Content, "[VERAXIS QUALIFIED MEMORY:") {
		t.Fatal("expected qualified memory annotation in provider payload")
	}
}

func TestInferenceBlockMutationFailsAuditReplay(t *testing.T) {
	runner, params, messages, bindings, pub, policyHash := buildInferenceRuntime(t)

	block, _, err := runner.ExecuteAdmissibleTurn(messages, bindings, params)
	if err != nil {
		t.Fatal(err)
	}

	block.SessionMAP.LeafRecords[0].Injected = !block.SessionMAP.LeafRecords[0].Injected

	res, err := audit.VerifySessionMAPWithPolicy(pub, block.SessionMAP, inferencePolicyVerifier{policyHash: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.ReplayMatch {
		t.Fatal("expected replay mismatch after inference-block leaf mutation")
	}
}

func TestInferenceBlockUnknownPolicyFails(t *testing.T) {
	runner, params, messages, bindings, pub, _ := buildInferenceRuntime(t)

	block, _, err := runner.ExecuteAdmissibleTurn(messages, bindings, params)
	if err != nil {
		t.Fatal(err)
	}

	res, err := audit.VerifySessionMAPWithPolicy(pub, block.SessionMAP, inferencePolicyVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	if res.ReplayMatch {
		t.Fatal("expected unknown policy snapshot to fail replay")
	}
}
