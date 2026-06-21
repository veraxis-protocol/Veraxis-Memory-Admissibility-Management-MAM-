package orchestrator

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"veraxis-memory-admissibility/pkg/audit"
	"veraxis-memory-admissibility/pkg/bitmask"
	"veraxis-memory-admissibility/pkg/gateway"
	"veraxis-memory-admissibility/pkg/tenant"
)

const BackpressureError = "ORCHESTRATOR_BACKPRESSURE: handoff queue saturated; sub-agent initialization refused"

type AgentIdentity struct {
	AgentID    string
	TenantHash tenant.IDHash
	DomainHash tenant.IDHash
}

type HandoffCoordinator struct {
	GatewayWrapper *gateway.ClientWrapper
	Provider       gateway.LLMProviderAdapter
	AuditKeyID     string
	SigningKey     ed25519.PrivateKey
	ModelName      string
	slots          chan struct{}
}

type HandoffResult struct {
	SanitizedPayload []gateway.LLMMessage
	InferenceBlock   gateway.AdmissibleInferenceBlock
	ConsequenceToken audit.MachineConsequenceRecord
}

func NewHandoffCoordinator(
	wrapper *gateway.ClientWrapper,
	provider gateway.LLMProviderAdapter,
	keyID string,
	signingKey ed25519.PrivateKey,
	maxConcurrentHandoffs int,
) *HandoffCoordinator {
	if maxConcurrentHandoffs <= 0 {
		maxConcurrentHandoffs = 1
	}
	return &HandoffCoordinator{
		GatewayWrapper: wrapper,
		Provider:       provider,
		AuditKeyID:     keyID,
		SigningKey:     signingKey,
		ModelName:      "gpt-4o-sub-agent-v1",
		slots:          make(chan struct{}, maxConcurrentHandoffs),
	}
}

func (c *HandoffCoordinator) ExecuteAgentHandoff(
	ctx context.Context,
	mcrID [16]byte,
	mapID [16]byte,
	sessionID string,
	taskID string,
	actorID string,
	targetSubAgent AgentIdentity,
	mask bitmask.EvaluationMask,
	rawScratchpad []gateway.LLMMessage,
	bindings []gateway.MemoryContextBinding,
	eepID string,
	aepID string,
) (HandoffResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return HandoffResult{}, errors.New("ORCHESTRATOR_BACKPRESSURE: context done before slot admission -> " + err.Error())
	}
	if c == nil || c.GatewayWrapper == nil || c.Provider == nil {
		return HandoffResult{}, errors.New("ORCHESTRATOR_HOOK_ERR: coordinator requires gateway wrapper and provider")
	}
	if len(c.SigningKey) != ed25519.PrivateKeySize {
		return HandoffResult{}, errors.New("ORCHESTRATOR_HOOK_ERR: Ed25519 private signing key required")
	}

	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		return HandoffResult{}, errors.New(BackpressureError)
	}

	if err := ctx.Err(); err != nil {
		return HandoffResult{}, errors.New("ORCHESTRATOR_BACKPRESSURE: context deadline exceeded before handoff execution -> " + err.Error())
	}

	sanitizedMessages, leaves, err := c.GatewayWrapper.SanitizeContextWindow(
		ctx,
		targetSubAgent.TenantHash,
		targetSubAgent.DomainHash,
		mask,
		rawScratchpad,
		bindings,
	)
	if err != nil {
		return HandoffResult{}, errors.New("ORCHESTRATOR_HOOK_ERR: gateway scrubbing fault -> " + err.Error())
	}

	providerResponse, err := c.Provider.Invoke(ctx, sanitizedMessages)
	if err != nil {
		return HandoffResult{}, errors.New("ORCHESTRATOR_HOOK_ERR: sub-agent invocation execution failure -> " + err.Error())
	}

	now := time.Now().UTC()
	policyHash := c.GatewayWrapper.PolicyHash
	runtimeSnapshotHash := [32]byte{}
	runtimeSnapshotVersion := uint64(0)
	if c.GatewayWrapper.RuntimeMonitor != nil {
		runtimeSnapshotHash, runtimeSnapshotVersion = c.GatewayWrapper.RuntimeMonitor.ActiveSnapshotInfo()
	}

	runner := gateway.LifecycleRunner{
		Wrapper: c.GatewayWrapper,
		Adapter: &gateway.OpenAIAdapter{ModelName: c.modelName()},
		Provider: gateway.MockInferenceProvider{Response: gateway.ProviderResponse{
			Text:   providerResponse.Text,
			Tokens: providerResponse.Tokens,
		}},
	}
	_ = runner // kept to make package relationship explicit without re-sanitizing.

	smap, err := generateHandoffSessionMAP(
		mapID,
		sessionID,
		targetSubAgent.AgentID,
		actorID,
		taskID,
		targetSubAgent.TenantHash,
		policyHash,
		runtimeSnapshotHash,
		runtimeSnapshotVersion,
		leaves,
		c.SigningKey,
		c.AuditKeyID,
		time.Hour,
		now,
	)
	if err != nil {
		return HandoffResult{}, errors.New("ORCHESTRATOR_HOOK_ERR: evidence block compilation error -> " + err.Error())
	}

	inferenceBlock := gateway.AdmissibleInferenceBlock{
		InferenceID:  "inf_sub_" + shortID(mapID),
		ModelName:    c.modelName(),
		ResponseText: providerResponse.Text,
		UsageTokens:  providerResponse.Tokens,
		SessionMAP:   smap,
		CompletedAt:  now,
	}

	mcr, err := audit.CompileLineageRecord(mcrID, smap, eepID, aepID, now.Unix())
	if err != nil {
		return HandoffResult{}, errors.New("ORCHESTRATOR_HOOK_ERR: lineage seal failure -> " + err.Error())
	}

	return HandoffResult{
		SanitizedPayload: sanitizedMessages,
		InferenceBlock:   inferenceBlock,
		ConsequenceToken: mcr,
	}, nil
}

func (c *HandoffCoordinator) modelName() string {
	if c.ModelName != "" {
		return c.ModelName
	}
	return "gpt-4o-sub-agent-v1"
}

func shortID(id [16]byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 8)
	for i := 0; i < 4; i++ {
		out[i*2] = hex[id[i]>>4]
		out[i*2+1] = hex[id[i]&0x0f]
	}
	return string(out)
}
