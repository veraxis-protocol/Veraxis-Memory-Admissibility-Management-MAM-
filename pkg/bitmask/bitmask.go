package bitmask

type MemoryFlags uint64
type RuntimeFlags uint64

const (
	FlagLifecycleActive      MemoryFlags = 1 << 0
	FlagLifecycleExpired     MemoryFlags = 1 << 1
	FlagLifecycleDeletionReq MemoryFlags = 1 << 2
	FlagLifecycleRevoked     MemoryFlags = 1 << 3

	FlagSafetyQuarantined        MemoryFlags = 1 << 4
	FlagSafetyPoisoningSuspected MemoryFlags = 1 << 5

	ClassUseToneAdjustment  MemoryFlags = 1 << 8
	ClassUseContextOnly     MemoryFlags = 1 << 9
	ClassUseDecisionSupport MemoryFlags = 1 << 10
	ClassUseAutomatedAction MemoryFlags = 1 << 11

	BlockUseAutomatedDenial  MemoryFlags = 1 << 16
	BlockUseCreditEvaluation MemoryFlags = 1 << 17
	BlockUseClinicalTriage   MemoryFlags = 1 << 18

	Tier0Transient       MemoryFlags = 1 << 24
	Tier1Preference      MemoryFlags = 1 << 25
	Tier2Operational     MemoryFlags = 1 << 26
	Tier3HighConsequence MemoryFlags = 1 << 27
)

type EvaluationMask struct {
	RequiredLifecycle   RuntimeFlags
	ProhibitedSafety    RuntimeFlags
	AllowedUseClasses   RuntimeFlags
	ProhibitedUseBlocks RuntimeFlags
	SensitivityLimit    RuntimeFlags
}
