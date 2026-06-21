package evaluate

import (
	"veraxis-memory-admissibility/pkg/bitmask"
	"veraxis-memory-admissibility/pkg/tenant"
)

type Decision uint8

const (
	DecisionUse Decision = iota
	DecisionQualify
	DecisionRefresh
	DecisionEscalate
	DecisionRefuse
	DecisionIgnore
	DecisionQuarantine
	DecisionDeleteRequested
	DecisionHardRefuse
)

const (
	ReasonUse                      = "USE"
	ReasonTenantMismatch           = "TENANT_MISMATCH"
	ReasonDomainMismatch           = "DOMAIN_MISMATCH"
	ReasonDeletionRequested        = "DELETION_REQUESTED"
	ReasonLifecycleInvalid         = "LIFECYCLE_INVALID"
	ReasonMemoryExpired            = "MEMORY_EXPIRED"
	ReasonMemoryRevoked            = "MEMORY_REVOKED"
	ReasonSafetyIsolationTriggered = "SAFETY_ISOLATION_TRIGGERED"
	ReasonProhibitedUseEnforced    = "PROHIBITED_USE_ENFORCED"
	ReasonNoExplicitUsePermitted   = "NO_EXPLICIT_USE_PERMITTED"
	ReasonMemoryProfileMissing     = "MEMORY_PROFILE_MISSING"
)

const InvalidLifecycleFlags = bitmask.FlagLifecycleExpired |
	bitmask.FlagLifecycleDeletionReq |
	bitmask.FlagLifecycleRevoked

func EvaluateMemoryHotPath(
	runtimeTenant, memTenant tenant.IDHash,
	runtimeDomain, memDomain tenant.IDHash,
	memFlags bitmask.MemoryFlags,
	mask bitmask.EvaluationMask,
) (Decision, string) {
	if !tenant.ValidateTenant(memTenant, runtimeTenant) {
		return DecisionHardRefuse, ReasonTenantMismatch
	}
	if !tenant.ValidateDomain(memDomain, runtimeDomain) {
		return DecisionRefuse, ReasonDomainMismatch
	}

	mBytes := bitmask.RuntimeFlags(memFlags)

	if (mBytes & bitmask.RuntimeFlags(InvalidLifecycleFlags)) != 0 {
		if (mBytes & bitmask.RuntimeFlags(bitmask.FlagLifecycleDeletionReq)) != 0 {
			return DecisionDeleteRequested, ReasonDeletionRequested
		}
		if (mBytes & bitmask.RuntimeFlags(bitmask.FlagLifecycleExpired)) != 0 {
			return DecisionRefresh, ReasonMemoryExpired
		}
		if (mBytes & bitmask.RuntimeFlags(bitmask.FlagLifecycleRevoked)) != 0 {
			return DecisionRefuse, ReasonMemoryRevoked
		}
		return DecisionRefuse, ReasonLifecycleInvalid
	}

	if (mBytes & mask.ProhibitedSafety) != 0 {
		return DecisionQuarantine, ReasonSafetyIsolationTriggered
	}
	if (mBytes & mask.ProhibitedUseBlocks) != 0 {
		return DecisionRefuse, ReasonProhibitedUseEnforced
	}
	if (mBytes & mask.AllowedUseClasses) == 0 {
		return DecisionIgnore, ReasonNoExplicitUsePermitted
	}

	return DecisionUse, ReasonUse
}
