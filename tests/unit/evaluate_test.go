package unit

import (
	"testing"

	"veraxis-memory-admissibility/pkg/bitmask"
	"veraxis-memory-admissibility/pkg/evaluate"
	"veraxis-memory-admissibility/pkg/tenant"
)

func TestTenantIsolationAssert(t *testing.T) {
	runtimeTenant := tenant.IDHash{0x1A}
	maliciousMemoryTenant := tenant.IDHash{0x2B}
	domain := tenant.IDHash{0x03}

	decision, code := evaluate.EvaluateMemoryHotPath(
		runtimeTenant,
		maliciousMemoryTenant,
		domain,
		domain,
		bitmask.FlagLifecycleActive|bitmask.ClassUseToneAdjustment,
		bitmask.EvaluationMask{AllowedUseClasses: bitmask.RuntimeFlags(bitmask.ClassUseToneAdjustment)},
	)

	if decision != evaluate.DecisionHardRefuse || code != evaluate.ReasonTenantMismatch {
		t.Fatalf("expected hard refuse tenant mismatch, got %v %s", decision, code)
	}
}

func TestBitmaskConstraintEnforced(t *testing.T) {
	tenantID := tenant.IDHash{0x01}
	domainID := tenant.IDHash{0x02}

	badMemoryFlags := bitmask.FlagLifecycleActive | bitmask.BlockUseAutomatedDenial | bitmask.ClassUseToneAdjustment

	activeMask := bitmask.EvaluationMask{
		AllowedUseClasses:   bitmask.RuntimeFlags(bitmask.ClassUseToneAdjustment),
		ProhibitedUseBlocks: bitmask.RuntimeFlags(bitmask.BlockUseAutomatedDenial),
	}

	decision, code := evaluate.EvaluateMemoryHotPath(
		tenantID,
		tenantID,
		domainID,
		domainID,
		badMemoryFlags,
		activeMask,
	)

	if decision != evaluate.DecisionRefuse || code != evaluate.ReasonProhibitedUseEnforced {
		t.Fatalf("expected prohibited use refusal, got %v %s", decision, code)
	}
}

func TestDeletionRequestedBeforePolicy(t *testing.T) {
	tenantID := tenant.IDHash{0x01}
	domainID := tenant.IDHash{0x02}

	flags := bitmask.FlagLifecycleActive | bitmask.FlagLifecycleDeletionReq | bitmask.ClassUseToneAdjustment

	decision, code := evaluate.EvaluateMemoryHotPath(
		tenantID,
		tenantID,
		domainID,
		domainID,
		flags,
		bitmask.EvaluationMask{AllowedUseClasses: bitmask.RuntimeFlags(bitmask.ClassUseToneAdjustment)},
	)

	if decision != evaluate.DecisionDeleteRequested || code != evaluate.ReasonDeletionRequested {
		t.Fatalf("expected deletion requested, got %v %s", decision, code)
	}
}
