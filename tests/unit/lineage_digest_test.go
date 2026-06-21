package unit

import (
	"testing"

	"veraxis-memory-admissibility/pkg/audit"
	"veraxis-memory-admissibility/pkg/sessionmap"
)

func TestLineageDigestUsesBigEndianStableFields(t *testing.T) {
	smap := sessionmap.SessionMAP{
		SessionMAPID:           [16]byte{1},
		MerkleRoot:             [32]byte{2},
		PolicySnapshotHash:     [32]byte{3},
		RuntimeSnapshotHash:    [32]byte{4},
		RuntimeSnapshotVersion: 0x0102030405060708,
	}

	mcr, err := audit.CompileLineageRecord([16]byte{5}, smap, "eep", "aep", 123)
	if err != nil {
		t.Fatal(err)
	}

	recomputed := audit.ComputeLineageDigest(
		[16]byte{5},
		smap.SessionMAPID,
		smap.MerkleRoot,
		smap.PolicySnapshotHash,
		smap.RuntimeSnapshotHash,
		smap.RuntimeSnapshotVersion,
		"eep",
		"aep",
		123,
	)

	if mcr.LineageDigest != recomputed {
		t.Fatal("digest did not match deterministic big-endian recomputation")
	}
}

func TestVerifyLineageRejectsDifferentSessionMap(t *testing.T) {
	smap := sessionmap.SessionMAP{
		SessionMAPID:           [16]byte{1},
		MerkleRoot:             [32]byte{2},
		PolicySnapshotHash:     [32]byte{3},
		RuntimeSnapshotHash:    [32]byte{4},
		RuntimeSnapshotVersion: 9,
	}

	mcr, err := audit.CompileLineageRecord([16]byte{5}, smap, "eep", "aep", 123)
	if err != nil {
		t.Fatal(err)
	}

	other := smap
	other.MerkleRoot = [32]byte{9}

	if audit.VerifyLineageRecord(mcr, other) {
		t.Fatal("expected verification failure against different Session MAP")
	}
}
