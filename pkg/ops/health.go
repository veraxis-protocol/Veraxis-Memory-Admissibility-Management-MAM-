package ops

import (
	"errors"
	"time"
)

type SnapshotTelemetry struct {
	NodeID          string
	SnapshotVersion uint64
	SnapshotHash    [32]byte
	LastAppliedAt   time.Time
	WALReadable     bool
	PubSubReachable bool
	CoolingSince    time.Time
}

type HealthConfig struct {
	ClusterBaselineVersion uint64
	MaxVersionLag          uint64
	MaxSnapshotLag         time.Duration
	MaxCoolingLock         time.Duration
	Now                    time.Time
}

type ReadinessResult struct {
	Ready  bool
	Reason string
}

func EvaluateReadiness(t SnapshotTelemetry, cfg HealthConfig) ReadinessResult {
	now := cfg.Now
	if now.IsZero() {
		now = time.Now()
	}

	if t.SnapshotVersion == 0 || t.SnapshotHash == ([32]byte{}) {
		return ReadinessResult{Ready: false, Reason: "MAM_RUNTIME_SNAPSHOT_ZERO"}
	}
	if !t.WALReadable {
		return ReadinessResult{Ready: false, Reason: "MAM_WAL_UNREADABLE"}
	}

	if cfg.ClusterBaselineVersion > t.SnapshotVersion {
		lag := cfg.ClusterBaselineVersion - t.SnapshotVersion
		if cfg.MaxVersionLag > 0 && lag > cfg.MaxVersionLag {
			return ReadinessResult{Ready: false, Reason: "MAM_SNAPSHOT_OUT_OF_SYNC"}
		}
	}

	if !t.LastAppliedAt.IsZero() && cfg.MaxSnapshotLag > 0 && now.Sub(t.LastAppliedAt) > cfg.MaxSnapshotLag {
		return ReadinessResult{Ready: false, Reason: "MAM_SNAPSHOT_LAG_EXCEEDED"}
	}

	if !t.PubSubReachable {
		if t.CoolingSince.IsZero() {
			return ReadinessResult{Ready: true, Reason: "MAM_PUBSUB_COOLING_LOCK"}
		}
		if cfg.MaxCoolingLock > 0 && now.Sub(t.CoolingSince) > cfg.MaxCoolingLock {
			return ReadinessResult{Ready: false, Reason: "MAM_PUBSUB_UNREACHABLE"}
		}
		return ReadinessResult{Ready: true, Reason: "MAM_PUBSUB_COOLING_LOCK"}
	}

	return ReadinessResult{Ready: true, Reason: "MAM_READY"}
}

func ValidateBootReplay(snapshotVersion uint64, snapshotHash [32]byte, replayErr error) error {
	if replayErr != nil {
		return replayErr
	}
	if snapshotVersion == 0 || snapshotHash == ([32]byte{}) {
		return errors.New("MAM_BOOT_REPLAY_INVALID_SNAPSHOT")
	}
	return nil
}
