package quarantine

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"veraxis-memory-admissibility/pkg/evaluate"
)

type State uint8

const (
	StateClear State = iota
	StateQuarantined
	StateDeletionRequested
	StateRevoked
	StatePoisoningSuspected
)

func BlocksInjection(s State) bool {
	return s == StateQuarantined ||
		s == StateDeletionRequested ||
		s == StateRevoked ||
		s == StatePoisoningSuspected
}

type EventType uint8
type QuarantineReason uint8

const (
	EventQuarantineMemory EventType = iota
	EventDeleteRequested
	EventRevokeMemory
	EventClearQuarantine
	EventPoisoningSuspected
	EventPromptInjectionDetected
	EventCrossSessionLeak
	EventCrossAgentLeak
)

const (
	ReasonPoisoningSuspected QuarantineReason = iota
	ReasonPromptInjectionDetected
	ReasonCrossSessionLeak
	ReasonRetroactiveRevocation
)

type RevocationEvent struct {
	EventID       [16]byte
	MemoryID      [16]byte
	EventType     EventType
	Reason        QuarantineReason
	OperatorID    string
	Source        string
	CreatedAt     time.Time
	PolicyHash    [32]byte
	PreviousState string
	NewState      string
	Signature     [64]byte
	SigningKeyID  string
}

type QuarantineState struct {
	EventID    [16]byte
	ReasonCode string
}

type TombstoneState struct {
	EventID [16]byte
}

type RevocationState struct {
	EventID [16]byte
}

type RuntimeSnapshot struct {
	Version        uint64
	SnapshotHash   [32]byte
	CreatedAtUnix  int64
	HighestEventID [16]byte
	EventCount     uint64
	Quarantined    map[[16]byte]QuarantineState
	Tombstoned     map[[16]byte]TombstoneState
	Revoked        map[[16]byte]RevocationState
}

type RuntimeDecision struct {
	Decision evaluate.Decision
	Reason   string
	StateRef [16]byte
}

type RuntimeMonitor struct {
	snapshot atomic.Value // stores *RuntimeSnapshot

	ledgerMu sync.Mutex
	ledger   []RevocationEvent
}

func NewRuntimeMonitor() *RuntimeMonitor {
	m := &RuntimeMonitor{}
	m.SwapActiveSnapshot(NewEmptySnapshot(0, time.Now()))
	return m
}

func NewEmptySnapshot(version uint64, createdAt time.Time) *RuntimeSnapshot {
	snap := &RuntimeSnapshot{
		Version:       version,
		CreatedAtUnix: createdAt.Unix(),
		Quarantined:   make(map[[16]byte]QuarantineState),
		Tombstoned:    make(map[[16]byte]TombstoneState),
		Revoked:       make(map[[16]byte]RevocationState),
	}
	snap.SnapshotHash = ComputeSnapshotHash(snap)
	return snap
}

func (m *RuntimeMonitor) Lookup(id [16]byte) RuntimeDecision {
	val := m.snapshot.Load()
	if val == nil {
		return RuntimeDecision{Decision: evaluate.DecisionUse, Reason: "RUNTIME_STATE_UNINITIALIZED"}
	}

	snap := val.(*RuntimeSnapshot)

	if state, ok := snap.Tombstoned[id]; ok {
		return RuntimeDecision{
			Decision: evaluate.DecisionDeleteRequested,
			Reason:   "DELETION_REQUESTED",
			StateRef: state.EventID,
		}
	}
	if state, ok := snap.Quarantined[id]; ok {
		return RuntimeDecision{
			Decision: evaluate.DecisionQuarantine,
			Reason:   state.ReasonCode,
			StateRef: state.EventID,
		}
	}
	if state, ok := snap.Revoked[id]; ok {
		return RuntimeDecision{
			Decision: evaluate.DecisionRefuse,
			Reason:   "MEMORY_REVOKED",
			StateRef: state.EventID,
		}
	}

	return RuntimeDecision{Decision: evaluate.DecisionUse, Reason: "RUNTIME_STATE_CLEAR"}
}

func (m *RuntimeMonitor) GetActiveSnapshot() *RuntimeSnapshot {
	val := m.snapshot.Load()
	if val == nil {
		return NewEmptySnapshot(0, time.Now())
	}
	return val.(*RuntimeSnapshot)
}

func (m *RuntimeMonitor) LookupWithSnapshot(snap *RuntimeSnapshot, id [16]byte) RuntimeDecision {
	if snap == nil {
		return RuntimeDecision{Decision: evaluate.DecisionUse, Reason: "RUNTIME_STATE_UNINITIALIZED"}
	}
	if state, ok := snap.Tombstoned[id]; ok {
		return RuntimeDecision{
			Decision: evaluate.DecisionDeleteRequested,
			Reason:   "DELETION_REQUESTED",
			StateRef: state.EventID,
		}
	}
	if state, ok := snap.Quarantined[id]; ok {
		return RuntimeDecision{
			Decision: evaluate.DecisionQuarantine,
			Reason:   state.ReasonCode,
			StateRef: state.EventID,
		}
	}
	if state, ok := snap.Revoked[id]; ok {
		return RuntimeDecision{
			Decision: evaluate.DecisionRefuse,
			Reason:   "MEMORY_REVOKED",
			StateRef: state.EventID,
		}
	}
	return RuntimeDecision{Decision: evaluate.DecisionUse, Reason: "RUNTIME_STATE_CLEAR"}
}

func (m *RuntimeMonitor) ActiveSnapshotInfo() ([32]byte, uint64) {
	val := m.snapshot.Load()
	if val == nil {
		return [32]byte{}, 0
	}
	snap := val.(*RuntimeSnapshot)
	return snap.SnapshotHash, snap.Version
}

func (m *RuntimeMonitor) SwapActiveSnapshot(newSnap *RuntimeSnapshot) {
	if newSnap == nil {
		return
	}
	m.snapshot.Store(newSnap)
}

func (m *RuntimeMonitor) AppendEvent(event RevocationEvent) {
	m.ledgerMu.Lock()
	m.ledger = append(m.ledger, event)
	m.ledgerMu.Unlock()
}

func (m *RuntimeMonitor) Ledger() []RevocationEvent {
	m.ledgerMu.Lock()
	defer m.ledgerMu.Unlock()

	out := make([]RevocationEvent, len(m.ledger))
	copy(out, m.ledger)
	return out
}

func (m *RuntimeMonitor) CompileAndSwap(createdAt time.Time) *RuntimeSnapshot {
	events := m.Ledger()
	val := m.snapshot.Load()
	version := uint64(1)
	if val != nil {
		version = val.(*RuntimeSnapshot).Version + 1
	}
	snap := CompileSnapshot(events, version, createdAt)
	m.SwapActiveSnapshot(snap)
	return snap
}

func CompileSnapshot(events []RevocationEvent, version uint64, createdAt time.Time) *RuntimeSnapshot {
	snap := &RuntimeSnapshot{
		Version:       version,
		CreatedAtUnix: createdAt.Unix(),
		EventCount:    uint64(len(events)),
		Quarantined:   make(map[[16]byte]QuarantineState),
		Tombstoned:    make(map[[16]byte]TombstoneState),
		Revoked:       make(map[[16]byte]RevocationState),
	}

	for _, event := range events {
		snap.HighestEventID = event.EventID
		switch event.EventType {
		case EventDeleteRequested:
			delete(snap.Quarantined, event.MemoryID)
			delete(snap.Revoked, event.MemoryID)
			snap.Tombstoned[event.MemoryID] = TombstoneState{EventID: event.EventID}
		case EventQuarantineMemory, EventPoisoningSuspected, EventPromptInjectionDetected, EventCrossSessionLeak, EventCrossAgentLeak:
			delete(snap.Revoked, event.MemoryID)
			snap.Quarantined[event.MemoryID] = QuarantineState{
				EventID:    event.EventID,
				ReasonCode: reasonCode(event),
			}
		case EventRevokeMemory:
			delete(snap.Quarantined, event.MemoryID)
			snap.Revoked[event.MemoryID] = RevocationState{EventID: event.EventID}
		case EventClearQuarantine:
			delete(snap.Quarantined, event.MemoryID)
		}
	}

	snap.SnapshotHash = ComputeSnapshotHash(snap)
	return snap
}

func ComputeSnapshotHash(snap *RuntimeSnapshot) [32]byte {
	h := sha256.New()

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], snap.Version)
	h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], snap.EventCount)
	h.Write(buf[:])
	h.Write(snap.HighestEventID[:])

	writeQuarantineSet(h, snap.Quarantined)
	writeTombstoneSet(h, snap.Tombstoned)
	writeRevocationSet(h, snap.Revoked)

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

type quarantinePair struct {
	id    [16]byte
	state QuarantineState
}

type tombstonePair struct {
	id    [16]byte
	state TombstoneState
}

type revocationPair struct {
	id    [16]byte
	state RevocationState
}

func writeQuarantineSet(h interface{ Write([]byte) (int, error) }, set map[[16]byte]QuarantineState) {
	pairs := make([]quarantinePair, 0, len(set))
	for id, state := range set {
		pairs = append(pairs, quarantinePair{id: id, state: state})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return string(pairs[i].id[:]) < string(pairs[j].id[:])
	})
	for _, pair := range pairs {
		h.Write([]byte("Q"))
		h.Write(pair.id[:])
		h.Write(pair.state.EventID[:])
		h.Write([]byte(pair.state.ReasonCode))
	}
}

func writeTombstoneSet(h interface{ Write([]byte) (int, error) }, set map[[16]byte]TombstoneState) {
	pairs := make([]tombstonePair, 0, len(set))
	for id, state := range set {
		pairs = append(pairs, tombstonePair{id: id, state: state})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return string(pairs[i].id[:]) < string(pairs[j].id[:])
	})
	for _, pair := range pairs {
		h.Write([]byte("T"))
		h.Write(pair.id[:])
		h.Write(pair.state.EventID[:])
	}
}

func writeRevocationSet(h interface{ Write([]byte) (int, error) }, set map[[16]byte]RevocationState) {
	pairs := make([]revocationPair, 0, len(set))
	for id, state := range set {
		pairs = append(pairs, revocationPair{id: id, state: state})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return string(pairs[i].id[:]) < string(pairs[j].id[:])
	})
	for _, pair := range pairs {
		h.Write([]byte("R"))
		h.Write(pair.id[:])
		h.Write(pair.state.EventID[:])
	}
}

func reasonCode(event RevocationEvent) string {
	switch event.EventType {
	case EventPoisoningSuspected:
		return "MEMORY_POISONING_SUSPECTED"
	case EventPromptInjectionDetected:
		return "PROMPT_INJECTION_DETECTED"
	case EventCrossSessionLeak:
		return "CROSS_SESSION_LEAK"
	case EventCrossAgentLeak:
		return "CROSS_AGENT_LEAK"
	case EventQuarantineMemory:
		switch event.Reason {
		case ReasonPromptInjectionDetected:
			return "PROMPT_INJECTION_DETECTED"
		case ReasonCrossSessionLeak:
			return "CROSS_SESSION_LEAK"
		case ReasonRetroactiveRevocation:
			return "RETROACTIVE_REVOCATION"
		default:
			return "MEMORY_POISONING_SUSPECTED"
		}
	default:
		return "MEMORY_QUARANTINED"
	}
}

// NowUTC returns current UTC time. It is a small seam for persistence recovery.
func NowUTC() time.Time {
	return time.Now().UTC()
}
