package integration

import (
	"crypto/ed25519"
	"testing"
	"time"

	"veraxis-memory-admissibility/pkg/audit"
	"veraxis-memory-admissibility/pkg/evaluate"
	"veraxis-memory-admissibility/pkg/merkle"
	"veraxis-memory-admissibility/pkg/sessionmap"
)

type snapshotVerifier map[[32]byte]bool

func (s snapshotVerifier) KnownImmutableSnapshot(hash [32]byte) bool {
	return s[hash]
}

func makeLeaf(id byte, injected bool, decision evaluate.Decision) merkle.LeafRecord {
	var l merkle.LeafRecord
	l.MemoryID[0] = id
	l.MemoryHash[0] = id + 10
	l.DecisionCode = uint8(decision)
	l.Injected = injected
	l.PolicyHash[0] = 5
	l.ReasonCodeHash[0] = id + 20
	return l
}

func makeSignedMap(t *testing.T) (ed25519.PublicKey, sessionmap.SessionMAP) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var smid [16]byte
	smid[0] = 1
	var tenantHash [32]byte
	tenantHash[0] = 2
	var runtimeHash [32]byte
	runtimeHash[0] = 3
	var policyHash [32]byte
	policyHash[0] = 4

	leaves := []merkle.LeafRecord{
		makeLeaf(2, true, evaluate.DecisionUse),
		makeLeaf(1, false, evaluate.DecisionRefuse),
	}

	smap, err := sessionmap.GenerateSessionMAP(
		smid,
		"sess",
		"agent",
		"actor",
		"task",
		tenantHash,
		runtimeHash,
		policyHash,
		leaves,
		priv,
		"key-1",
		time.Hour,
		time.Unix(100, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	return pub, smap
}

func TestValidSessionMAPVerifies(t *testing.T) {
	pub, smap := makeSignedMap(t)

	res, err := audit.VerifySessionMAP(pub, smap)
	if err != nil {
		t.Fatal(err)
	}
	if !res.ReplayMatch || !res.MerkleRootValid || !res.SignatureValid {
		t.Fatalf("expected valid replay")
	}
}

func TestCanonicalByteSortingResilience(t *testing.T) {
	pub, smap := makeSignedMap(t)

	smap.LeafRecords[0], smap.LeafRecords[1] = smap.LeafRecords[1], smap.LeafRecords[0]

	res, err := audit.VerifySessionMAP(pub, smap)
	if err != nil {
		t.Fatal(err)
	}
	if !res.ReplayMatch {
		t.Fatalf("expected canonical sorting to preserve replay")
	}
}

func TestMutationInjectedTrueToFalseFails(t *testing.T) {
	pub, smap := makeSignedMap(t)
	smap.LeafRecords[0].Injected = false
	assertReplayFails(t, pub, smap)
}

func TestMutationInjectedFalseToTrueFails(t *testing.T) {
	pub, smap := makeSignedMap(t)
	smap.LeafRecords[1].Injected = true
	assertReplayFails(t, pub, smap)
}

func TestMutationDecisionUseToRefuseFails(t *testing.T) {
	pub, smap := makeSignedMap(t)
	smap.LeafRecords[0].DecisionCode = uint8(evaluate.DecisionRefuse)
	assertReplayFails(t, pub, smap)
}

func TestMutationDecisionRefuseToUseFails(t *testing.T) {
	pub, smap := makeSignedMap(t)
	smap.LeafRecords[1].DecisionCode = uint8(evaluate.DecisionUse)
	assertReplayFails(t, pub, smap)
}

func TestMutationMemoryHashFails(t *testing.T) {
	pub, smap := makeSignedMap(t)
	smap.LeafRecords[0].MemoryHash[0] ^= 0xff
	assertReplayFails(t, pub, smap)
}

func TestMutationMemoryIDFails(t *testing.T) {
	pub, smap := makeSignedMap(t)
	smap.LeafRecords[0].MemoryID[0] ^= 0xff
	assertReplayFails(t, pub, smap)
}

func TestMutationPolicyHashFails(t *testing.T) {
	pub, smap := makeSignedMap(t)
	smap.LeafRecords[0].PolicyHash[0] ^= 0xff
	assertReplayFails(t, pub, smap)
}

func TestMutationReasonCodeHashFails(t *testing.T) {
	pub, smap := makeSignedMap(t)
	smap.LeafRecords[0].ReasonCodeHash[0] ^= 0xff
	assertReplayFails(t, pub, smap)
}

func TestMutationMerkleRootFails(t *testing.T) {
	pub, smap := makeSignedMap(t)
	smap.MerkleRoot[0] ^= 0xff
	assertReplayFails(t, pub, smap)
}

func TestMutationSignatureFails(t *testing.T) {
	pub, smap := makeSignedMap(t)
	smap.Signature[0] ^= 0xff
	assertReplayFails(t, pub, smap)
}

func TestEmptyLeafRecordsRejected(t *testing.T) {
	pub, smap := makeSignedMap(t)
	smap.LeafRecords = nil
	_, err := audit.VerifySessionMAP(pub, smap)
	if err == nil {
		t.Fatal("expected empty leaf error")
	}
}

func TestPublicKeyMismatchFails(t *testing.T) {
	_, smap := makeSignedMap(t)
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := audit.VerifySessionMAP(otherPub, smap)
	if err != nil {
		t.Fatal(err)
	}
	if res.ReplayMatch {
		t.Fatal("expected public key mismatch failure")
	}
}

func TestUnknownPolicySnapshotFails(t *testing.T) {
	pub, smap := makeSignedMap(t)
	res, err := audit.VerifySessionMAPWithPolicy(pub, smap, snapshotVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	if res.ReplayMatch {
		t.Fatal("expected unknown policy snapshot to fail replay")
	}
}

func TestKnownPolicySnapshotPasses(t *testing.T) {
	pub, smap := makeSignedMap(t)
	verifier := snapshotVerifier{smap.PolicySnapshotHash: true}
	res, err := audit.VerifySessionMAPWithPolicy(pub, smap, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if !res.ReplayMatch {
		t.Fatal("expected known policy snapshot to pass replay")
	}
}

func assertReplayFails(t *testing.T, pub ed25519.PublicKey, smap sessionmap.SessionMAP) {
	t.Helper()
	res, err := audit.VerifySessionMAP(pub, smap)
	if err != nil {
		t.Fatal(err)
	}
	if res.ReplayMatch {
		t.Fatal("expected replay mismatch")
	}
}
