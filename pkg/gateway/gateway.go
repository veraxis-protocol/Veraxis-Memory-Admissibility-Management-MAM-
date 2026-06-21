package gateway

import (
	"context"
	"crypto/sha256"
	"errors"

	"veraxis-memory-admissibility/pkg/bitmask"
	"veraxis-memory-admissibility/pkg/evaluate"
	"veraxis-memory-admissibility/pkg/merkle"
	"veraxis-memory-admissibility/pkg/quarantine"
	"veraxis-memory-admissibility/pkg/tenant"
)

const (
	TombstoneRefresh         = "[VERAXIS: MEMORY_REFRESH_REQUIRED - CONTENT_STRIPPED]"
	TombstoneEscalate        = "[VERAXIS: MEMORY_ESCALATION_REQUIRED - CONTENT_STRIPPED]"
	TombstoneRefuse          = "[VERAXIS: MEMORY_ADMISSIBILITY_DENIED - CONTENT_STRIPPED]"
	TombstoneIgnore          = "[VERAXIS: MEMORY_IGNORED - CONTENT_STRIPPED]"
	TombstoneQuarantine      = "[VERAXIS: MEMORY_QUARANTINED - CONTENT_STRIPPED]"
	TombstoneDeleteRequested = "[VERAXIS: MEMORY_DELETION_REQUESTED - CONTENT_STRIPPED]"
	TombstoneHardRefuse      = "[VERAXIS: HARD_REFUSE_BOUNDARY_VIOLATION - CONTENT_STRIPPED]"
)

type LLMMessage struct {
	Role    string
	Content string
}

type MemoryContextBinding struct {
	MemoryID   [16]byte
	MemoryHash [32]byte
	MessageIdx int
}

type MemoryProfile struct {
	MemoryID         [16]byte
	TenantHash       tenant.IDHash
	DomainHash       tenant.IDHash
	Flags            bitmask.MemoryFlags
	UsageConstraints string
}

type ProfileCache interface {
	GetProfile(memoryID [16]byte) (MemoryProfile, bool)
}

type ClientWrapper struct {
	Profiles       ProfileCache
	PolicyHash     [32]byte
	RuntimeMonitor *quarantine.RuntimeMonitor
}

func (w *ClientWrapper) SanitizeContextWindow(
	ctx context.Context,
	runtimeTenant tenant.IDHash,
	runtimeDomain tenant.IDHash,
	mask bitmask.EvaluationMask,
	messages []LLMMessage,
	bindings []MemoryContextBinding,
) ([]LLMMessage, []merkle.LeafRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if w == nil || w.Profiles == nil {
		return nil, nil, errors.New("INVALID_GATEWAY: profile cache required")
	}

	sanitized := make([]LLMMessage, len(messages))
	copy(sanitized, messages)

	leaves := make([]merkle.LeafRecord, 0, len(bindings))

	for _, binding := range bindings {
		if binding.MessageIdx < 0 || binding.MessageIdx >= len(sanitized) {
			leaf := w.leaf(binding, evaluate.DecisionHardRefuse, false, evaluate.ReasonMemoryProfileMissing)
			leaves = append(leaves, leaf)
			continue
		}

		profile, ok := w.Profiles.GetProfile(binding.MemoryID)
		if !ok {
			sanitized[binding.MessageIdx].Content = TombstoneHardRefuse
			leaf := w.leaf(binding, evaluate.DecisionHardRefuse, false, evaluate.ReasonMemoryProfileMissing)
			leaves = append(leaves, leaf)
			continue
		}

		var decision evaluate.Decision
		var reason string

		if !tenant.ValidateTenant(profile.TenantHash, runtimeTenant) {
			decision = evaluate.DecisionHardRefuse
			reason = evaluate.ReasonTenantMismatch
		} else if !tenant.ValidateDomain(profile.DomainHash, runtimeDomain) {
			decision = evaluate.DecisionRefuse
			reason = evaluate.ReasonDomainMismatch
		} else if w.RuntimeMonitor != nil {
			runtimeDecision := w.RuntimeMonitor.Lookup(binding.MemoryID)
			if runtimeDecision.Decision != evaluate.DecisionUse {
				decision = runtimeDecision.Decision
				reason = runtimeDecision.Reason
			} else {
				decision, reason = evaluate.EvaluateMemoryHotPath(
					runtimeTenant,
					profile.TenantHash,
					runtimeDomain,
					profile.DomainHash,
					profile.Flags,
					mask,
				)
			}
		} else {
			decision, reason = evaluate.EvaluateMemoryHotPath(
				runtimeTenant,
				profile.TenantHash,
				runtimeDomain,
				profile.DomainHash,
				profile.Flags,
				mask,
			)
		}

		if decision == evaluate.DecisionUse && profile.UsageConstraints != "" {
			decision = evaluate.DecisionQualify
			reason = "QUALIFIED_USE_ONLY"
		}

		injected := false
		switch decision {
		case evaluate.DecisionUse:
			injected = true
		case evaluate.DecisionQualify:
			injected = true
			sanitized[binding.MessageIdx].Content = annotateConstraints(sanitized[binding.MessageIdx].Content, profile.UsageConstraints)
		case evaluate.DecisionRefresh:
			sanitized[binding.MessageIdx].Content = TombstoneRefresh
		case evaluate.DecisionEscalate:
			sanitized[binding.MessageIdx].Content = TombstoneEscalate
		case evaluate.DecisionRefuse:
			sanitized[binding.MessageIdx].Content = TombstoneRefuse
		case evaluate.DecisionIgnore:
			sanitized[binding.MessageIdx].Content = TombstoneIgnore
		case evaluate.DecisionQuarantine:
			sanitized[binding.MessageIdx].Content = TombstoneQuarantine
		case evaluate.DecisionDeleteRequested:
			sanitized[binding.MessageIdx].Content = TombstoneDeleteRequested
		case evaluate.DecisionHardRefuse:
			sanitized[binding.MessageIdx].Content = TombstoneHardRefuse
		default:
			sanitized[binding.MessageIdx].Content = TombstoneHardRefuse
			decision = evaluate.DecisionHardRefuse
			reason = "UNKNOWN_DECISION_FAIL_CLOSED"
		}

		leaves = append(leaves, w.leaf(binding, decision, injected, reason))
	}

	return sanitized, leaves, nil
}

func annotateConstraints(content, constraints string) string {
	if constraints == "" {
		constraints = "qualified memory; restricted downstream use"
	}
	return "[VERAXIS QUALIFIED MEMORY: " + constraints + "]\n" + content
}

func (w *ClientWrapper) leaf(binding MemoryContextBinding, decision evaluate.Decision, injected bool, reason string) merkle.LeafRecord {
	return merkle.LeafRecord{
		MemoryID:       binding.MemoryID,
		MemoryHash:     binding.MemoryHash,
		DecisionCode:   uint8(decision),
		Injected:       injected,
		PolicyHash:     w.PolicyHash,
		ReasonCodeHash: hashReason(reason),
	}
}

func hashReason(reason string) [32]byte {
	return sha256.Sum256([]byte(reason))
}
