package vectorstore

import (
	"context"
	"errors"
	"sync/atomic"

	"veraxis-memory-admissibility/pkg/axis"
)

var (
	ErrNilCoordinator = errors.New("INTERCEPTOR_ERROR: DriftMonitorCoordinator required")
	ErrLengthMismatch = errors.New("INTERCEPTOR_ERROR: record length mismatch between baseline anchors and retrieved vectors")
)

type VectorRecord struct {
	MemoryID    [16]byte
	Embedding   axis.StructuralVector
	PayloadText string
}

type InterceptorStats struct {
	Submitted uint64
	Dropped   uint64
	Skipped   uint64
}

type InterceptorWrapper struct {
	Coordinator *axis.DriftMonitorCoordinator
	OperatorID  string
	PipelineID  string
	PolicyHash  [32]byte

	submitted atomic.Uint64
	dropped   atomic.Uint64
	skipped   atomic.Uint64
}

func NewInterceptorWrapper(
	coord *axis.DriftMonitorCoordinator,
	operatorID string,
	pipelineID string,
	policyHash [32]byte,
) *InterceptorWrapper {
	return &InterceptorWrapper{
		Coordinator: coord,
		OperatorID:  operatorID,
		PipelineID:  pipelineID,
		PolicyHash:  policyHash,
	}
}

// InterceptQueryResults mirrors a database post-query hook.
//
// The function must return retrieved records without waiting for Axis drift math.
// Vector analysis is submitted through the bounded queue and may be dropped under
// saturation to protect live retrieval latency. This is intentional for the
// ingestion edge: stale detection is safer than database query blocking.
func (w *InterceptorWrapper) InterceptQueryResults(
	ctx context.Context,
	anchorRecords []VectorRecord,
	retrievedRecords []VectorRecord,
) ([]VectorRecord, error) {
	if w == nil || w.Coordinator == nil {
		return retrievedRecords, ErrNilCoordinator
	}
	if len(anchorRecords) != len(retrievedRecords) {
		return retrievedRecords, ErrLengthMismatch
	}
	if err := ctx.Err(); err != nil {
		return retrievedRecords, err
	}

	for i := range retrievedRecords {
		anchor := anchorRecords[i]
		retrieved := retrievedRecords[i]

		if anchor.MemoryID != retrieved.MemoryID {
			w.skipped.Add(1)
			continue
		}

		job := axis.MemoryTransformationJob{
			MemoryID:       retrieved.MemoryID,
			AnchorVector:   cloneVector(anchor.Embedding),
			MutatedVector:  cloneVector(retrieved.Embedding),
			OperatorID:     w.OperatorID,
			SourcePipeline: w.PipelineID,
			PolicySnapshot: w.PolicyHash,
		}

		if w.Coordinator.SubmitNonBlocking(job) {
			w.submitted.Add(1)
		} else {
			w.dropped.Add(1)
		}
	}

	return retrievedRecords, nil
}

func (w *InterceptorWrapper) Stats() InterceptorStats {
	if w == nil {
		return InterceptorStats{}
	}
	return InterceptorStats{
		Submitted: w.submitted.Load(),
		Dropped:   w.dropped.Load(),
		Skipped:   w.skipped.Load(),
	}
}

func cloneVector(in axis.StructuralVector) axis.StructuralVector {
	out := make(axis.StructuralVector, len(in))
	copy(out, in)
	return out
}
