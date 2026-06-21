package unit

import (
	"testing"

	"veraxis-memory-admissibility/pkg/merkle"
)

func TestMerkleDeterministic(t *testing.T) {
	a := merkle.LeafRecord{DecisionCode: 1, Injected: true}
	b := merkle.LeafRecord{DecisionCode: 2, Injected: false}
	a.MemoryID[0] = 2
	b.MemoryID[0] = 1

	first := merkle.BuildTurnTree([]merkle.LeafRecord{a, b})
	second := merkle.BuildTurnTree([]merkle.LeafRecord{b, a})

	if first != second {
		t.Fatal("expected deterministic root regardless of input order")
	}
}
