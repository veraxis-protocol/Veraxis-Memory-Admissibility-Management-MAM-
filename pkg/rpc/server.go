package rpc

import (
	"context"
	"crypto/rand"
	"time"

	"veraxis-memory-admissibility/pkg/bitmask"
	"veraxis-memory-admissibility/pkg/evaluate"
	"veraxis-memory-admissibility/pkg/merkle"
	"veraxis-memory-admissibility/pkg/quarantine"
	"veraxis-memory-admissibility/pkg/tenant"
)

type AdmissibilityServer struct {
	Monitor *quarantine.RuntimeMonitor
	Ledger  *quarantine.FileLedger
}

func (s *AdmissibilityServer) EvaluateMemoryUse(
	ctx context.Context,
	req *EvaluateRequest,
) (*EvaluateResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || s.Monitor == nil {
		return nil, Internal("SERVER_NOT_READY: runtime monitor is required")
	}
	if req == nil || req.Context == nil || len(req.Candidates) == 0 {
		return nil, InvalidArgument("MISSING_ARGUMENT: context and candidates are required")
	}
	if len(req.Context.TenantHash) != 32 || len(req.Context.DomainHash) != 32 {
		return nil, InvalidArgument("MALFORMED_CONTEXT: tenant and domain hashes must be exactly 32 bytes")
	}

	var rTenant, rDomain tenant.IDHash
	copy(rTenant[:], req.Context.TenantHash)
	copy(rDomain[:], req.Context.DomainHash)

	mask := bitmask.EvaluationMask{
		RequiredLifecycle:   bitmask.RuntimeFlags(req.Context.RequiredLifecycle),
		ProhibitedSafety:    bitmask.RuntimeFlags(req.Context.ProhibitedSafety),
		AllowedUseClasses:   bitmask.RuntimeFlags(req.Context.AllowedUseClasses),
		ProhibitedUseBlocks: bitmask.RuntimeFlags(req.Context.ProhibitedUseBlocks),
	}

	decisions := make([]*MemoryDecisionLeaf, len(req.Candidates))
	merkleLeaves := make([]merkle.LeafRecord, len(req.Candidates))

	activeSnapshot := s.Monitor.GetActiveSnapshot()

	for i, candidate := range req.Candidates {
		if candidate == nil {
			return nil, InvalidArgument("MALFORMED_CANDIDATE: nil candidate")
		}
		if len(candidate.MemoryId) != 16 || len(candidate.MemoryHash) != 32 {
			return nil, InvalidArgument("MALFORMED_CANDIDATE: memory_id must be 16 bytes and memory_hash must be 32 bytes")
		}

		var mID [16]byte
		var mHash [32]byte
		copy(mID[:], candidate.MemoryId)
		copy(mHash[:], candidate.MemoryHash)

		dynamicDecision := s.Monitor.LookupWithSnapshot(activeSnapshot, mID)

		var finalDecision evaluate.Decision
		var reasonCode string

		if dynamicDecision.Decision != evaluate.DecisionUse {
			finalDecision = dynamicDecision.Decision
			reasonCode = dynamicDecision.Reason
		} else {
			memFlags := bitmask.MemoryFlags(candidate.MemoryFlags)
			finalDecision, reasonCode = evaluate.EvaluateMemoryHotPath(
				rTenant,
				rTenant,
				rDomain,
				rDomain,
				memFlags,
				mask,
			)
		}

		injected := finalDecision == evaluate.DecisionUse || finalDecision == evaluate.DecisionQualify

		memIDCopy := make([]byte, 16)
		copy(memIDCopy, candidate.MemoryId)

		decisions[i] = &MemoryDecisionLeaf{
			MemoryId:     memIDCopy,
			DecisionCode: uint32(finalDecision),
			ReasonCode:   reasonCode,
			Injected:     injected,
		}

		merkleLeaves[i] = merkle.LeafRecord{
			MemoryID:     mID,
			MemoryHash:   mHash,
			DecisionCode: uint8(finalDecision),
			Injected:     injected,
		}
	}

	root := merkle.BuildTurnTree(merkleLeaves)

	rootCopy := make([]byte, 32)
	copy(rootCopy, root[:])

	return &EvaluateResponse{
		SessionId:              req.SessionId,
		MerkleRoot:             rootCopy,
		Decisions:              decisions,
		RuntimeSnapshotVersion: activeSnapshot.Version,
	}, nil
}

func (s *AdmissibilityServer) RegisterRevocationEvent(
	ctx context.Context,
	req *RevocationRequest,
) (*RevocationResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || s.Monitor == nil {
		return nil, Internal("SERVER_NOT_READY: runtime monitor is required")
	}
	if req == nil || len(req.MemoryId) != 16 {
		return nil, InvalidArgument("MALFORMED_REVOCATION: memory_id must be exactly 16 bytes")
	}

	var memoryID [16]byte
	copy(memoryID[:], req.MemoryId)

	eventID, err := newEventID()
	if err != nil {
		return nil, err
	}

	event := quarantine.RevocationEvent{
		EventID:    eventID,
		MemoryID:   memoryID,
		EventType:  quarantine.EventType(req.EventType),
		Reason:     quarantine.QuarantineReason(req.ReasonCode),
		OperatorID: req.OperatorId,
		Source:     req.Source,
		CreatedAt:  time.Now().UTC(),
		NewState:   "active",
	}

	if s.Ledger != nil {
		if err := s.Ledger.AppendEvent(event); err != nil {
			return nil, err
		}
	}

	s.Monitor.AppendEvent(event)
	snap := s.Monitor.CompileAndSwap(time.Now().UTC())

	eventIDCopy := make([]byte, 16)
	copy(eventIDCopy, eventID[:])
	hashCopy := make([]byte, 32)
	copy(hashCopy, snap.SnapshotHash[:])

	return &RevocationResponse{
		EventId:                eventIDCopy,
		UpdatedSnapshotVersion: snap.Version,
		UpdatedSnapshotHash:    hashCopy,
	}, nil
}

func newEventID() ([16]byte, error) {
	var id [16]byte
	_, err := rand.Read(id[:])
	return id, err
}
