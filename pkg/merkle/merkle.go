package merkle

import (
	"bytes"
	"crypto/sha256"
	"sort"
)

type LeafRecord struct {
	MemoryID       [16]byte
	MemoryHash     [32]byte
	DecisionCode   uint8
	Injected       bool
	PolicyHash     [32]byte
	ReasonCodeHash [32]byte
}

func (l LeafRecord) Hash() [32]byte {
	h := sha256.New()
	h.Write(l.MemoryID[:])
	h.Write(l.MemoryHash[:])
	h.Write([]byte{l.DecisionCode})
	if l.Injected {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	h.Write(l.PolicyHash[:])
	h.Write(l.ReasonCodeHash[:])

	var res [32]byte
	copy(res[:], h.Sum(nil))
	return res
}

// BuildTurnTree aggregates records deterministically into a single signature point.
// It copies the leaf slice before canonical sorting so callers' leaf order is never mutated.
// Odd leaves are promoted unchanged.
func BuildTurnTree(leaves []LeafRecord) [32]byte {
	if len(leaves) == 0 {
		return [32]byte{}
	}

	ordered := make([]LeafRecord, len(leaves))
	copy(ordered, leaves)

	sort.Slice(ordered, func(i, j int) bool {
		return bytes.Compare(ordered[i].MemoryID[:], ordered[j].MemoryID[:]) < 0
	})

	hashes := make([][32]byte, len(ordered))
	for i, leaf := range ordered {
		hashes[i] = leaf.Hash()
	}

	for len(hashes) > 1 {
		nextLevel := make([][32]byte, 0, (len(hashes)+1)/2)
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				h := sha256.New()
				h.Write(hashes[i][:])
				h.Write(hashes[i+1][:])
				var parent [32]byte
				copy(parent[:], h.Sum(nil))
				nextLevel = append(nextLevel, parent)
			} else {
				nextLevel = append(nextLevel, hashes[i])
			}
		}
		hashes = nextLevel
	}

	return hashes[0]
}
