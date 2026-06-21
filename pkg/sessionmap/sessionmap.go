package sessionmap

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"time"

	"veraxis-memory-admissibility/pkg/merkle"
)

type SessionMAP struct {
	Version                string
	SessionMAPID           [16]byte
	SessionID              string
	AgentID                string
	ActorID                string
	TenantHash             [32]byte
	TaskID                 string
	RuntimeContextHash     [32]byte
	PolicySnapshotHash     [32]byte
	RuntimeSnapshotHash    [32]byte
	RuntimeSnapshotVersion uint64
	MerkleRoot             [32]byte
	Signature              [64]byte
	SigningKeyID           string
	CreatedAt              time.Time
	ExpiresAt              time.Time
	LeafRecords            []merkle.LeafRecord
}

func GenerateSessionMAP(
	sessionMapID [16]byte,
	sessionID string,
	agentID string,
	actorID string,
	taskID string,
	tenantHash [32]byte,
	runtimeContextHash [32]byte,
	policySnapshotHash [32]byte,
	leaves []merkle.LeafRecord,
	privKey ed25519.PrivateKey,
	keyID string,
	ttl time.Duration,
	now time.Time,
) (SessionMAP, error) {
	return GenerateSessionMAPWithRuntimeSnapshot(
		sessionMapID,
		sessionID,
		agentID,
		actorID,
		taskID,
		tenantHash,
		runtimeContextHash,
		policySnapshotHash,
		[32]byte{},
		0,
		leaves,
		privKey,
		keyID,
		ttl,
		now,
	)
}

func GenerateSessionMAPWithRuntimeSnapshot(
	sessionMapID [16]byte,
	sessionID string,
	agentID string,
	actorID string,
	taskID string,
	tenantHash [32]byte,
	runtimeContextHash [32]byte,
	policySnapshotHash [32]byte,
	runtimeSnapshotHash [32]byte,
	runtimeSnapshotVersion uint64,
	leaves []merkle.LeafRecord,
	privKey ed25519.PrivateKey,
	keyID string,
	ttl time.Duration,
	now time.Time,
) (SessionMAP, error) {
	if len(leaves) == 0 {
		return SessionMAP{}, errors.New("INVALID_SESSION_MAP: zero leaf records")
	}
	if len(privKey) != ed25519.PrivateKeySize {
		return SessionMAP{}, errors.New("INVALID_SIGNING_KEY: Ed25519 private key required")
	}
	if ttl <= 0 {
		return SessionMAP{}, errors.New("INVALID_TTL: ttl must be positive")
	}

	root := merkle.BuildTurnTree(leaves)
	smap := SessionMAP{
		Version:                "0.1",
		SessionMAPID:           sessionMapID,
		SessionID:              sessionID,
		AgentID:                agentID,
		ActorID:                actorID,
		TenantHash:             tenantHash,
		TaskID:                 taskID,
		RuntimeContextHash:     runtimeContextHash,
		PolicySnapshotHash:     policySnapshotHash,
		RuntimeSnapshotHash:    runtimeSnapshotHash,
		RuntimeSnapshotVersion: runtimeSnapshotVersion,
		MerkleRoot:             root,
		SigningKeyID:           keyID,
		CreatedAt:              now,
		ExpiresAt:              now.Add(ttl),
		LeafRecords:            leaves,
	}

	sig := ed25519.Sign(privKey, smap.AttestationBytes())
	copy(smap.Signature[:], sig)
	return smap, nil
}

func (s SessionMAP) AttestationBytes() []byte {
	var buf bytes.Buffer
	buf.Write([]byte(s.Version))
	buf.Write(s.SessionMAPID[:])
	buf.Write([]byte(s.SessionID))
	buf.Write([]byte(s.AgentID))
	buf.Write([]byte(s.ActorID))
	buf.Write(s.TenantHash[:])
	buf.Write([]byte(s.TaskID))
	buf.Write(s.RuntimeContextHash[:])
	buf.Write(s.PolicySnapshotHash[:])
	buf.Write(s.RuntimeSnapshotHash[:])
	var num [8]byte
	binary.BigEndian.PutUint64(num[:], s.RuntimeSnapshotVersion)
	buf.Write(num[:])
	buf.Write(s.MerkleRoot[:])
	buf.Write([]byte(s.SigningKeyID))
	binary.BigEndian.PutUint64(num[:], uint64(s.CreatedAt.UnixNano()))
	buf.Write(num[:])
	binary.BigEndian.PutUint64(num[:], uint64(s.ExpiresAt.UnixNano()))
	buf.Write(num[:])
	return buf.Bytes()
}
