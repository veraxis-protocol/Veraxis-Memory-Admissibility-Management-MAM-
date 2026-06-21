package axis

// Phase 3 package. Must not be imported by Phase 1 or Phase 2 hot-path packages.
// This package is offline-only until explicitly integrated into background monitors.

type AxialIntegrityEngine interface {
	EvaluateDrift(anchor, transformed StructuralVector) AxisCheckResult
}
