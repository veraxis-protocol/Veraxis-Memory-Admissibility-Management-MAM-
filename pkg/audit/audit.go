package audit

import (
	"crypto/ed25519"
	"errors"

	"veraxis-memory-admissibility/pkg/merkle"
	"veraxis-memory-admissibility/pkg/sessionmap"
)

type PolicySnapshotVerifier interface {
	KnownImmutableSnapshot(hash [32]byte) bool
}

type RuntimeSnapshotVerifier interface {
	KnownRuntimeSnapshot(hash [32]byte, version uint64) bool
}

type VerificationResult struct {
	SignatureValid  bool
	MerkleRootValid bool
	ReplayMatch     bool
}

func VerifySessionMAP(pubKey ed25519.PublicKey, smap sessionmap.SessionMAP) (VerificationResult, error) {
	var res VerificationResult

	if len(smap.LeafRecords) == 0 {
		return res, errors.New("INVALID_AUDIT_FRAME: zero leaf records submitted")
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return res, errors.New("INVALID_PUBLIC_KEY: Ed25519 public key required")
	}

	reconstructedRoot := merkle.BuildTurnTree(smap.LeafRecords)
	if reconstructedRoot != smap.MerkleRoot {
		return res, nil
	}

	res.MerkleRootValid = true
	res.SignatureValid = ed25519.Verify(pubKey, smap.AttestationBytes(), smap.Signature[:])
	res.ReplayMatch = res.MerkleRootValid && res.SignatureValid

	return res, nil
}

func VerifySessionMAPWithPolicy(
	pubKey ed25519.PublicKey,
	smap sessionmap.SessionMAP,
	verifier PolicySnapshotVerifier,
) (VerificationResult, error) {
	if verifier == nil {
		return VerificationResult{}, errors.New("INVALID_VERIFIER: snapshot verifier required")
	}
	if !verifier.KnownImmutableSnapshot(smap.PolicySnapshotHash) {
		return VerificationResult{ReplayMatch: false}, nil
	}
	return VerifySessionMAP(pubKey, smap)
}

func VerifySessionMAPWithPolicyAndRuntime(
	pubKey ed25519.PublicKey,
	smap sessionmap.SessionMAP,
	policyVerifier PolicySnapshotVerifier,
	runtimeVerifier RuntimeSnapshotVerifier,
) (VerificationResult, error) {
	if policyVerifier == nil {
		return VerificationResult{}, errors.New("INVALID_POLICY_VERIFIER: snapshot verifier required")
	}
	if runtimeVerifier == nil {
		return VerificationResult{}, errors.New("INVALID_RUNTIME_VERIFIER: runtime snapshot verifier required")
	}
	if !policyVerifier.KnownImmutableSnapshot(smap.PolicySnapshotHash) {
		return VerificationResult{ReplayMatch: false}, nil
	}
	if !runtimeVerifier.KnownRuntimeSnapshot(smap.RuntimeSnapshotHash, smap.RuntimeSnapshotVersion) {
		return VerificationResult{ReplayMatch: false}, nil
	}
	return VerifySessionMAP(pubKey, smap)
}
