package unit

import (
	"testing"
	"time"

	"veraxis-memory-admissibility/pkg/ops"
)

func baselineTelemetry() ops.SnapshotTelemetry {
	return ops.SnapshotTelemetry{
		NodeID:          "node-a",
		SnapshotVersion: 10,
		SnapshotHash:    [32]byte{1},
		LastAppliedAt:   time.Unix(100, 0),
		WALReadable:     true,
		PubSubReachable: true,
	}
}

func TestEvaluateReadinessReady(t *testing.T) {
	res := ops.EvaluateReadiness(baselineTelemetry(), ops.HealthConfig{
		ClusterBaselineVersion: 10,
		MaxVersionLag:          2,
		MaxSnapshotLag:         time.Second,
		Now:                    time.Unix(100, 0),
	})
	if !res.Ready || res.Reason != "MAM_READY" {
		t.Fatalf("expected ready, got %#v", res)
	}
}

func TestEvaluateReadinessOutOfSync(t *testing.T) {
	tel := baselineTelemetry()
	tel.SnapshotVersion = 7
	res := ops.EvaluateReadiness(tel, ops.HealthConfig{
		ClusterBaselineVersion: 10,
		MaxVersionLag:          2,
		Now:                    time.Unix(100, 0),
	})
	if res.Ready || res.Reason != "MAM_SNAPSHOT_OUT_OF_SYNC" {
		t.Fatalf("expected out-of-sync, got %#v", res)
	}
}

func TestEvaluateReadinessFailClosedAfterCooling(t *testing.T) {
	tel := baselineTelemetry()
	tel.PubSubReachable = false
	tel.CoolingSince = time.Unix(0, 0)
	res := ops.EvaluateReadiness(tel, ops.HealthConfig{
		ClusterBaselineVersion: 10,
		MaxVersionLag:          2,
		MaxCoolingLock:         30 * time.Second,
		Now:                    time.Unix(31, 0),
	})
	if res.Ready || res.Reason != "MAM_PUBSUB_UNREACHABLE" {
		t.Fatalf("expected pubsub fail-closed, got %#v", res)
	}
}

func TestEvaluateReadinessCoolingLockAllowed(t *testing.T) {
	tel := baselineTelemetry()
	tel.PubSubReachable = false
	tel.CoolingSince = time.Unix(10, 0)
	res := ops.EvaluateReadiness(tel, ops.HealthConfig{
		ClusterBaselineVersion: 10,
		MaxVersionLag:          2,
		MaxCoolingLock:         30 * time.Second,
		Now:                    time.Unix(20, 0),
	})
	if !res.Ready || res.Reason != "MAM_PUBSUB_COOLING_LOCK" {
		t.Fatalf("expected cooling lock ready, got %#v", res)
	}
}

func TestValidateBootReplayRequiresSnapshot(t *testing.T) {
	if err := ops.ValidateBootReplay(0, [32]byte{}, nil); err == nil {
		t.Fatal("expected invalid snapshot error")
	}
	if err := ops.ValidateBootReplay(1, [32]byte{1}, nil); err != nil {
		t.Fatalf("expected valid replay, got %v", err)
	}
}
