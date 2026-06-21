package policy

import "veraxis-memory-admissibility/pkg/bitmask"

type Snapshot struct {
	ID        string
	Hash      [32]byte
	Mask      bitmask.EvaluationMask
	Immutable bool
}

func ValidateSnapshot(s Snapshot) bool {
	return s.Immutable && s.ID != ""
}
