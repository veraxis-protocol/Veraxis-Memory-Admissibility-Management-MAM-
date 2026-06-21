package gateway

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"veraxis-memory-admissibility/pkg/bitmask"
	"veraxis-memory-admissibility/pkg/sessionmap"
	"veraxis-memory-admissibility/pkg/tenant"
)

type TokenMetrics struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type AdmissibleInferenceBlock struct {
	InferenceID  string                `json:"inference_id"`
	ModelName    string                `json:"model_name"`
	ResponseText string                `json:"response_text"`
	UsageTokens  TokenMetrics          `json:"usage_tokens"`
	SessionMAP   sessionmap.SessionMAP `json:"session_map"`
	CompletedAt  time.Time             `json:"completed_at"`
}

type MockRuntimeContext struct {
	Ctx                context.Context
	Tenant             tenant.IDHash
	Domain             tenant.IDHash
	Mask               bitmask.EvaluationMask
	MapID              [16]byte
	SessionID          string
	AgentID            string
	ActorID            string
	TaskID             string
	ContextHash        [32]byte
	PrivateKey         ed25519.PrivateKey
	KeyID              string
	PolicySnapshotHash [32]byte
	Now                time.Time
	TTL                time.Duration
}

type LifecycleRunner struct {
	Wrapper  *ClientWrapper
	Adapter  *OpenAIAdapter
	Provider LLMProviderAdapter
}

type LLMProviderAdapter interface {
	Invoke(ctx context.Context, messages []LLMMessage) (ProviderResponse, error)
}

type ProviderResponse struct {
	Text   string
	Tokens TokenMetrics
}

type MockInferenceProvider struct {
	Response ProviderResponse
}

func (m MockInferenceProvider) Invoke(ctx context.Context, messages []LLMMessage) (ProviderResponse, error) {
	if err := ctx.Err(); err != nil {
		return ProviderResponse{}, err
	}
	if m.Response.Text == "" {
		return ProviderResponse{}, errors.New("MOCK_PROVIDER_ERR: response text required")
	}
	return m.Response, nil
}

func (r *LifecycleRunner) ExecuteAdmissibleTurn(
	messages []LLMMessage,
	bindings []MemoryContextBinding,
	runtimeParams MockRuntimeContext,
) (AdmissibleInferenceBlock, OpenAIRequestPayload, error) {
	if r == nil || r.Wrapper == nil || r.Adapter == nil || r.Provider == nil {
		return AdmissibleInferenceBlock{}, OpenAIRequestPayload{}, errors.New("INVALID_LIFECYCLE_RUNNER: wrapper, adapter, and provider required")
	}
	if runtimeParams.Ctx == nil {
		runtimeParams.Ctx = context.Background()
	}
	if runtimeParams.Now.IsZero() {
		runtimeParams.Now = time.Now()
	}
	if runtimeParams.TTL <= 0 {
		runtimeParams.TTL = time.Hour
	}
	if len(runtimeParams.PrivateKey) != ed25519.PrivateKeySize {
		return AdmissibleInferenceBlock{}, OpenAIRequestPayload{}, errors.New("INVALID_RUNTIME_CONTEXT: Ed25519 private key required")
	}

	sanitized, leaves, err := r.Wrapper.SanitizeContextWindow(
		runtimeParams.Ctx,
		runtimeParams.Tenant,
		runtimeParams.Domain,
		runtimeParams.Mask,
		messages,
		bindings,
	)
	if err != nil {
		return AdmissibleInferenceBlock{}, OpenAIRequestPayload{}, err
	}

	providerPayload := r.Adapter.Convert(sanitized)

	providerResponse, err := r.Provider.Invoke(runtimeParams.Ctx, sanitized)
	if err != nil {
		return AdmissibleInferenceBlock{}, providerPayload, err
	}

	policyHash := r.Wrapper.PolicyHash
	if runtimeParams.PolicySnapshotHash != ([32]byte{}) {
		policyHash = runtimeParams.PolicySnapshotHash
	}

	runtimeSnapshotHash := [32]byte{}
	runtimeSnapshotVersion := uint64(0)
	if r.Wrapper.RuntimeMonitor != nil {
		runtimeSnapshotHash, runtimeSnapshotVersion = r.Wrapper.RuntimeMonitor.ActiveSnapshotInfo()
	}

	smap, err := sessionmap.GenerateSessionMAPWithRuntimeSnapshot(
		runtimeParams.MapID,
		runtimeParams.SessionID,
		runtimeParams.AgentID,
		runtimeParams.ActorID,
		runtimeParams.TaskID,
		[32]byte(runtimeParams.Tenant),
		runtimeParams.ContextHash,
		policyHash,
		runtimeSnapshotHash,
		runtimeSnapshotVersion,
		leaves,
		runtimeParams.PrivateKey,
		runtimeParams.KeyID,
		runtimeParams.TTL,
		runtimeParams.Now,
	)
	if err != nil {
		return AdmissibleInferenceBlock{}, providerPayload, err
	}

	completedAt := runtimeParams.Now
	if completedAt.IsZero() {
		completedAt = time.Now()
	}

	return AdmissibleInferenceBlock{
		InferenceID:  "inf_local_0001",
		ModelName:    r.Adapter.ModelName,
		ResponseText: providerResponse.Text,
		UsageTokens:  providerResponse.Tokens,
		SessionMAP:   smap,
		CompletedAt:  completedAt,
	}, providerPayload, nil
}
