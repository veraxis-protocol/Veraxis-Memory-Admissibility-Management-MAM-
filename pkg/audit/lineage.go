package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"veraxis-memory-admissibility/pkg/sessionmap"
)

type MachineConsequenceRecord struct {
	MCRID                  [16]byte `json:"mcr_id"`
	SessionMAPID           [16]byte `json:"session_map_id"`
	MerkleRoot             [32]byte `json:"merkle_root"`
	PolicySnapshotHash     [32]byte `json:"policy_snapshot_hash"`
	RuntimeSnapshotHash    [32]byte `json:"runtime_snapshot_hash"`
	RuntimeSnapshotVersion uint64   `json:"runtime_snapshot_version"`
	EEPID                  string   `json:"eep_id"`
	AEPID                  string   `json:"aep_id"`
	LineageDigest          [32]byte `json:"lineage_digest"`
	LinkedAtUnix           int64    `json:"linked_at_unix"`
}

func CompileLineageRecord(
	mcrID [16]byte,
	smap sessionmap.SessionMAP,
	eepID string,
	aepID string,
	linkedAtUnix int64,
) (MachineConsequenceRecord, error) {
	if eepID == "" || aepID == "" {
		return MachineConsequenceRecord{}, errors.New("LINEAGE_MALFORMED: EEP and AEP trackers are required to close the consequence loop")
	}

	lineageDigest := ComputeLineageDigest(
		mcrID,
		smap.SessionMAPID,
		smap.MerkleRoot,
		smap.PolicySnapshotHash,
		smap.RuntimeSnapshotHash,
		smap.RuntimeSnapshotVersion,
		eepID,
		aepID,
		linkedAtUnix,
	)

	return MachineConsequenceRecord{
		MCRID:                  mcrID,
		SessionMAPID:           smap.SessionMAPID,
		MerkleRoot:             smap.MerkleRoot,
		PolicySnapshotHash:     smap.PolicySnapshotHash,
		RuntimeSnapshotHash:    smap.RuntimeSnapshotHash,
		RuntimeSnapshotVersion: smap.RuntimeSnapshotVersion,
		EEPID:                  eepID,
		AEPID:                  aepID,
		LineageDigest:          lineageDigest,
		LinkedAtUnix:           linkedAtUnix,
	}, nil
}

func ComputeLineageDigest(
	mcrID [16]byte,
	sessionMapID [16]byte,
	merkleRoot [32]byte,
	policySnapshotHash [32]byte,
	runtimeSnapshotHash [32]byte,
	runtimeSnapshotVersion uint64,
	eepID string,
	aepID string,
	linkedAtUnix int64,
) [32]byte {
	h := sha256.New()

	h.Write(mcrID[:])
	h.Write(sessionMapID[:])
	h.Write(merkleRoot[:])
	h.Write(policySnapshotHash[:])
	h.Write(runtimeSnapshotHash[:])

	var uBuf [8]byte
	binary.BigEndian.PutUint64(uBuf[:], runtimeSnapshotVersion)
	h.Write(uBuf[:])

	h.Write([]byte(eepID))
	h.Write([]byte{0})
	h.Write([]byte(aepID))
	h.Write([]byte{0})

	binary.BigEndian.PutUint64(uBuf[:], uint64(linkedAtUnix))
	h.Write(uBuf[:])

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func VerifyLineageRecord(mcr MachineConsequenceRecord, smap sessionmap.SessionMAP) bool {
	if mcr.SessionMAPID != smap.SessionMAPID ||
		mcr.MerkleRoot != smap.MerkleRoot ||
		mcr.PolicySnapshotHash != smap.PolicySnapshotHash ||
		mcr.RuntimeSnapshotHash != smap.RuntimeSnapshotHash ||
		mcr.RuntimeSnapshotVersion != smap.RuntimeSnapshotVersion {
		return false
	}

	recalculated, err := CompileLineageRecord(
		mcr.MCRID,
		smap,
		mcr.EEPID,
		mcr.AEPID,
		mcr.LinkedAtUnix,
	)
	if err != nil {
		return false
	}

	return mcr.LineageDigest == recalculated.LineageDigest
}
