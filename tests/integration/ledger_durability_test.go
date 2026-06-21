package integration

import (
	"os"
	"strings"
	"testing"
	"time"

	"veraxis-memory-admissibility/pkg/evaluate"
	"veraxis-memory-admissibility/pkg/quarantine"
)

func ledgerEvent(eventID, memID byte, eventType quarantine.EventType) quarantine.RevocationEvent {
	return quarantine.RevocationEvent{
		EventID:    [16]byte{eventID},
		MemoryID:   [16]byte{memID},
		EventType:  eventType,
		Reason:     quarantine.ReasonPoisoningSuspected,
		OperatorID: "operator_test",
		Source:     "test",
		CreatedAt:  time.Unix(int64(eventID), 0),
		NewState:   "active",
	}
}

func TestDurableLedgerReplayReconstructsSnapshotHash(t *testing.T) {
	path := t.TempDir() + "/revocation.vm"

	ledger, err := quarantine.NewFileLedger(path)
	if err != nil {
		t.Fatal(err)
	}

	events := []quarantine.RevocationEvent{
		ledgerEvent(1, 11, quarantine.EventQuarantineMemory),
		ledgerEvent(2, 12, quarantine.EventDeleteRequested),
		ledgerEvent(3, 13, quarantine.EventRevokeMemory),
		ledgerEvent(4, 14, quarantine.EventPromptInjectionDetected),
		ledgerEvent(5, 15, quarantine.EventCrossSessionLeak),
	}

	for _, event := range events {
		if err := ledger.AppendEvent(event); err != nil {
			t.Fatal(err)
		}
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	replayed, err := quarantine.ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	preCrash := quarantine.CompileSnapshot(replayed, 1, time.Unix(100, 0))

	monitor, recovered, err := quarantine.RecoverMonitorFromFile(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	if preCrash.SnapshotHash != recovered.SnapshotHash {
		t.Fatalf("snapshot hash mismatch across recovery")
	}

	if d := monitor.Lookup([16]byte{11}); d.Decision != evaluate.DecisionQuarantine {
		t.Fatalf("expected recovered quarantine, got %v", d.Decision)
	}
	if d := monitor.Lookup([16]byte{12}); d.Decision != evaluate.DecisionDeleteRequested {
		t.Fatalf("expected recovered tombstone, got %v", d.Decision)
	}
	if d := monitor.Lookup([16]byte{13}); d.Decision != evaluate.DecisionRefuse {
		t.Fatalf("expected recovered revocation, got %v", d.Decision)
	}
}

func TestDurableLedgerPartialWriteDetected(t *testing.T) {
	path := t.TempDir() + "/revocation.vm"

	ledger, err := quarantine.NewFileLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.AppendEvent(ledgerEvent(1, 11, quarantine.EventQuarantineMemory)); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0x00, 0x00, 0x01}); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	_, err = quarantine.ReplayFile(path)
	if err == nil {
		t.Fatal("expected partial write replay error")
	}
	if !strings.Contains(err.Error(), quarantine.ErrPersistenceCorruptionPrefix) {
		t.Fatalf("expected persistence corruption error, got %v", err)
	}
}

func TestDurableLedgerTamperDetected(t *testing.T) {
	path := t.TempDir() + "/revocation.vm"

	ledger, err := quarantine.NewFileLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.AppendEvent(ledgerEvent(1, 11, quarantine.EventQuarantineMemory)); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Record starts with 4 length bytes + 2 magic bytes. Flip the first payload byte.
	if len(b) < 8 {
		t.Fatal("ledger unexpectedly short")
	}
	b[6] ^= 0xff
	if err := os.WriteFile(path, b, 0644); err != nil {
		t.Fatal(err)
	}

	_, err = quarantine.ReplayFile(path)
	if err == nil {
		t.Fatal("expected tamper replay error")
	}
	if !strings.Contains(err.Error(), quarantine.ErrSecurityAlertPrefix) {
		t.Fatalf("expected security alert error, got %v", err)
	}
}

func TestDurableLedgerClearQuarantineRequiresEvent(t *testing.T) {
	path := t.TempDir() + "/revocation.vm"

	ledger, err := quarantine.NewFileLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	memID := byte(21)
	if err := ledger.AppendEvent(ledgerEvent(1, memID, quarantine.EventQuarantineMemory)); err != nil {
		t.Fatal(err)
	}
	if err := ledger.AppendEvent(ledgerEvent(2, memID, quarantine.EventClearQuarantine)); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	monitor, _, err := quarantine.RecoverMonitorFromFile(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	if d := monitor.Lookup([16]byte{memID}); d.Decision != evaluate.DecisionUse {
		t.Fatalf("expected clear state after clear event, got %v", d.Decision)
	}
}
