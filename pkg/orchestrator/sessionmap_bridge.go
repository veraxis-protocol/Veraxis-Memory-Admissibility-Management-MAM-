package orchestrator

import (
	"crypto/ed25519"
	"time"

	"veraxis-memory-admissibility/pkg/merkle"
	"veraxis-memory-admissibility/pkg/sessionmap"
	"veraxis-memory-admissibility/pkg/tenant"
)

func generateHandoffSessionMAP(
	mapID [16]byte,
	sessionID string,
	agentID string,
	actorID string,
	taskID string,
	tenantHash tenant.IDHash,
	policyHash [32]byte,
	runtimeSnapshotHash [32]byte,
	runtimeSnapshotVersion uint64,
	leaves []merkle.LeafRecord,
	signingKey ed25519.PrivateKey,
	keyID string,
	ttl time.Duration,
	now time.Time,
) (sessionmap.SessionMAP, error) {
	return sessionmap.GenerateSessionMAPWithRuntimeSnapshot(
		mapID,
		sessionID,
		agentID,
		actorID,
		taskID,
		[32]byte(tenantHash),
		[32]byte{},
		policyHash,
		runtimeSnapshotHash,
		runtimeSnapshotVersion,
		leaves,
		signingKey,
		keyID,
		ttl,
		now,
	)
}
