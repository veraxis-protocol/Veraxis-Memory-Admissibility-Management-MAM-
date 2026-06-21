package integration

import (
	"testing"
	"time"

	"veraxis-memory-admissibility/pkg/audit"
	"veraxis-memory-admissibility/pkg/sessionmap"
)

func baselineLineageSMAP() (sessionmap.SessionMAP, [16]byte, int64) {
	mockMCRID := [16]byte{0xAA}
	mockMAPID := [16]byte{0xBB}
	mockRoot := [32]byte{0x11}
	mockPolicy := [32]byte{0x22}
	mockRuntime := [32]byte{0x33}
	mockVersion := uint64(42)
	nowUnix := time.Unix(1700000000, 0).Unix()

	validSMAP := sessionmap.SessionMAP{
		SessionMAPID:           mockMAPID,
		MerkleRoot:             mockRoot,
		PolicySnapshotHash:     mockPolicy,
		RuntimeSnapshotHash:    mockRuntime,
		RuntimeSnapshotVersion: mockVersion,
	}

	return validSMAP, mockMCRID, nowUnix
}

func TestLineageControlFidelity(t *testing.T) {
	validSMAP, mockMCRID, nowUnix := baselineLineageSMAP()

	mcr, err := audit.CompileLineageRecord(mockMCRID, validSMAP, "eep_valid_01", "aep_valid_02", nowUnix)
	if err != nil {
		t.Fatalf("Lineage construction failed unexpectedly: %v", err)
	}

	if !audit.VerifyLineageRecord(mcr, validSMAP) {
		t.Fatal("LINEAGE_REPLAY_ERROR: legitimate track record failed verification check")
	}

	recalculated := audit.ComputeLineageDigest(
		mcr.MCRID,
		mcr.SessionMAPID,
		mcr.MerkleRoot,
		mcr.PolicySnapshotHash,
		mcr.RuntimeSnapshotHash,
		mcr.RuntimeSnapshotVersion,
		mcr.EEPID,
		mcr.AEPID,
		mcr.LinkedAtUnix,
	)
	if recalculated != mcr.LineageDigest {
		t.Fatal("lineage digest failed deterministic recomputation")
	}
}

func TestLineageRejectsMissingTrackers(t *testing.T) {
	validSMAP, mockMCRID, nowUnix := baselineLineageSMAP()

	if _, err := audit.CompileLineageRecord(mockMCRID, validSMAP, "", "aep_valid_02", nowUnix); err == nil {
		t.Fatal("expected rejection for empty EEP tracking reference")
	}
	if _, err := audit.CompileLineageRecord(mockMCRID, validSMAP, "eep_valid_01", "", nowUnix); err == nil {
		t.Fatal("expected rejection for empty AEP tracking reference")
	}
}

func TestLineageTamperInterception(t *testing.T) {
	validSMAP, mockMCRID, nowUnix := baselineLineageSMAP()

	mcr, err := audit.CompileLineageRecord(mockMCRID, validSMAP, "eep_valid_01", "aep_valid_02", nowUnix)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		edit func(*audit.MachineConsequenceRecord)
	}{
		{name: "policy", edit: func(m *audit.MachineConsequenceRecord) { m.PolicySnapshotHash = [32]byte{0x99} }},
		{name: "runtime_hash", edit: func(m *audit.MachineConsequenceRecord) { m.RuntimeSnapshotHash = [32]byte{0x98} }},
		{name: "runtime_version", edit: func(m *audit.MachineConsequenceRecord) { m.RuntimeSnapshotVersion++ }},
		{name: "map_id", edit: func(m *audit.MachineConsequenceRecord) { m.SessionMAPID = [16]byte{0x97} }},
		{name: "merkle_root", edit: func(m *audit.MachineConsequenceRecord) { m.MerkleRoot = [32]byte{0x96} }},
		{name: "eep", edit: func(m *audit.MachineConsequenceRecord) { m.EEPID = "eep_tampered" }},
		{name: "aep", edit: func(m *audit.MachineConsequenceRecord) { m.AEPID = "aep_tampered" }},
		{name: "time", edit: func(m *audit.MachineConsequenceRecord) { m.LinkedAtUnix++ }},
		{name: "digest", edit: func(m *audit.MachineConsequenceRecord) { m.LineageDigest = [32]byte{0x95} }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := mcr
			tc.edit(&tampered)
			if audit.VerifyLineageRecord(tampered, validSMAP) {
				t.Fatalf("expected tamper detection for %s", tc.name)
			}
		})
	}
}
