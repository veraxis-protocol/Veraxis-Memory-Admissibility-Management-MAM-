package integration

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"veraxis-memory-admissibility/pkg/bitmask"
	"veraxis-memory-admissibility/pkg/evaluate"
	"veraxis-memory-admissibility/pkg/merkle"
	"veraxis-memory-admissibility/pkg/quarantine"
	"veraxis-memory-admissibility/pkg/rpc"
)

func rpcHash32(seed byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = seed
	}
	return out
}

func rpcID16(seed byte) []byte {
	out := make([]byte, 16)
	for i := range out {
		out[i] = seed
	}
	return out
}

func testRPCServer(t *testing.T) *rpc.AdmissibilityServer {
	t.Helper()
	return &rpc.AdmissibilityServer{
		Monitor: quarantine.NewRuntimeMonitor(),
	}
}

func TestRPCEvaluateMemoryUseMerkleMatches(t *testing.T) {
	s := testRPCServer(t)

	req := &rpc.EvaluateRequest{
		SessionId: "sess",
		AgentId:   "agent",
		Context: &rpc.RuntimeContext{
			TenantHash:        rpcHash32(1),
			DomainHash:        rpcHash32(2),
			AllowedUseClasses: uint64(bitmask.ClassUseContextOnly),
		},
		Candidates: []*rpc.MemoryCandidate{
			{MemoryId: rpcID16(1), MemoryHash: rpcHash32(11), MemoryFlags: uint64(bitmask.FlagLifecycleActive | bitmask.ClassUseContextOnly)},
			{MemoryId: rpcID16(2), MemoryHash: rpcHash32(22), MemoryFlags: uint64(bitmask.FlagLifecycleActive)},
		},
	}

	resp, err := s.EvaluateMemoryUse(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Decisions) != 2 {
		t.Fatalf("expected two decisions")
	}
	if resp.Decisions[0].DecisionCode != uint32(evaluate.DecisionUse) || !resp.Decisions[0].Injected {
		t.Fatalf("expected first memory use, got %#v", resp.Decisions[0])
	}

	var id1, id2 [16]byte
	var h1, h2 [32]byte
	copy(id1[:], req.Candidates[0].MemoryId)
	copy(id2[:], req.Candidates[1].MemoryId)
	copy(h1[:], req.Candidates[0].MemoryHash)
	copy(h2[:], req.Candidates[1].MemoryHash)

	expected := merkle.BuildTurnTree([]merkle.LeafRecord{
		{MemoryID: id1, MemoryHash: h1, DecisionCode: uint8(resp.Decisions[0].DecisionCode), Injected: resp.Decisions[0].Injected},
		{MemoryID: id2, MemoryHash: h2, DecisionCode: uint8(resp.Decisions[1].DecisionCode), Injected: resp.Decisions[1].Injected},
	})
	if !bytes.Equal(resp.MerkleRoot, expected[:]) {
		t.Fatal("merkle root mismatch")
	}
}

func TestRPCMalformedInputsFailClosed(t *testing.T) {
	s := testRPCServer(t)

	_, err := s.EvaluateMemoryUse(context.Background(), &rpc.EvaluateRequest{
		Context: &rpc.RuntimeContext{
			TenantHash: rpcHash32(1)[:30],
			DomainHash: rpcHash32(2),
		},
		Candidates: []*rpc.MemoryCandidate{{MemoryId: rpcID16(1), MemoryHash: rpcHash32(1)}},
	})
	if rpc.ErrorCode(err) != rpc.CodeInvalidArgument {
		t.Fatalf("expected invalid argument for malformed context, got %v", err)
	}

	_, err = s.EvaluateMemoryUse(context.Background(), &rpc.EvaluateRequest{
		Context: &rpc.RuntimeContext{
			TenantHash: rpcHash32(1),
			DomainHash: rpcHash32(2),
		},
		Candidates: []*rpc.MemoryCandidate{{MemoryId: rpcID16(1)[:12], MemoryHash: rpcHash32(1)}},
	})
	if rpc.ErrorCode(err) != rpc.CodeInvalidArgument {
		t.Fatalf("expected invalid argument for malformed candidate, got %v", err)
	}

	_, err = s.RegisterRevocationEvent(context.Background(), &rpc.RevocationRequest{MemoryId: rpcID16(1)[:15]})
	if rpc.ErrorCode(err) != rpc.CodeInvalidArgument {
		t.Fatalf("expected invalid argument for malformed revocation, got %v", err)
	}
}

func TestRPCRevocationUpdatesSnapshot(t *testing.T) {
	s := testRPCServer(t)
	memID := rpcID16(44)

	rev, err := s.RegisterRevocationEvent(context.Background(), &rpc.RevocationRequest{
		MemoryId:   memID,
		EventType:  uint32(quarantine.EventQuarantineMemory),
		ReasonCode: uint32(quarantine.ReasonPoisoningSuspected),
		OperatorId: "operator",
		Source:     "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rev.EventId) != 16 || len(rev.UpdatedSnapshotHash) != 32 || rev.UpdatedSnapshotVersion == 0 {
		t.Fatalf("invalid revocation response: %#v", rev)
	}

	resp, err := s.EvaluateMemoryUse(context.Background(), &rpc.EvaluateRequest{
		SessionId: "sess",
		Context: &rpc.RuntimeContext{
			TenantHash:        rpcHash32(1),
			DomainHash:        rpcHash32(2),
			AllowedUseClasses: uint64(bitmask.ClassUseContextOnly),
		},
		Candidates: []*rpc.MemoryCandidate{
			{MemoryId: memID, MemoryHash: rpcHash32(1), MemoryFlags: uint64(bitmask.FlagLifecycleActive | bitmask.ClassUseContextOnly)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decisions[0].DecisionCode != uint32(evaluate.DecisionQuarantine) || resp.Decisions[0].Injected {
		t.Fatalf("expected quarantined response, got %#v", resp.Decisions[0])
	}
}

func TestRPCConcurrentReadWhileWriting(t *testing.T) {
	s := testRPCServer(t)

	req := &rpc.EvaluateRequest{
		SessionId: "sess",
		Context: &rpc.RuntimeContext{
			TenantHash:        rpcHash32(1),
			DomainHash:        rpcHash32(2),
			AllowedUseClasses: uint64(bitmask.ClassUseContextOnly),
		},
		Candidates: []*rpc.MemoryCandidate{
			{MemoryId: rpcID16(1), MemoryHash: rpcHash32(1), MemoryFlags: uint64(bitmask.FlagLifecycleActive | bitmask.ClassUseContextOnly)},
		},
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2000)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, err := s.EvaluateMemoryUse(context.Background(), req)
				if err != nil {
					errs <- err
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 500; j++ {
			_, err := s.RegisterRevocationEvent(context.Background(), &rpc.RevocationRequest{
				MemoryId:   rpcID16(byte(j % 255)),
				EventType:  uint32(quarantine.EventQuarantineMemory),
				ReasonCode: uint32(quarantine.ReasonPoisoningSuspected),
				OperatorId: "operator",
				Source:     "concurrency-test",
			})
			if err != nil {
				errs <- err
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrency test timed out")
	}
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("unexpected rpc concurrency error: %v", err)
		}
	}
}
