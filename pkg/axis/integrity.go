package axis

import (
	"errors"
	"math"
)

const (
	DriftTypeTemporality = "TEMPORARY_STATE_PROMOTED_TO_STABLE_TRAIT"
	DriftTypeEpistemic   = "INFERENCE_PROMOTED_TO_FACT"
	DriftTypeScope       = "CONTEXT_BOUND_MEMORY_REUSED_GLOBALLY"
	DriftTypeTrust       = "LOW_TRUST_SOURCE_PROMOTED"
	DriftTypeMandate     = "PREFERENCE_PROMOTED_TO_MANDATE"

	ReasonTemporality = "TEMPORARITY_DRIFT_DETECTED"
	ReasonEpistemic   = "EPISTEMIC_MODAL_SHIFT"
	ReasonScope       = "SCOPE_EXPANSION_VIOLATION"
	ReasonTrust       = "SOURCE_TRUST_COLLAPSE"
	ReasonMandate     = "PREFERENCE_PROMOTED_TO_AUTHORITY"
)

type StructuralVector []float32

type AxisCheckResult struct {
	AxisPreserved bool     `json:"axis_preserved"`
	DriftScore    float64  `json:"drift_score"`
	DriftType     string   `json:"drift_type"`
	ReasonCodes   []string `json:"reason_codes"`
}

type InvariantDimensions struct {
	TemporalityStart int
	TemporalityEnd   int
	EpistemicStart   int
	EpistemicEnd     int
	ScopeStart       int
	ScopeEnd         int
	TrustStart       int
	TrustEnd         int
	MandateStart     int
	MandateEnd       int
}

var DefaultDimensions = InvariantDimensions{
	TemporalityStart: 0, TemporalityEnd: 23,
	EpistemicStart: 24, EpistemicEnd: 47,
	ScopeStart: 48, ScopeEnd: 71,
	TrustStart: 72, TrustEnd: 95,
	MandateStart: 96, MandateEnd: 127,
}

func CosineSimilarity(v1, v2 StructuralVector, start, end int) (float64, error) {
	if len(v1) != 128 || len(v2) != 128 {
		return 0, errors.New("INVALID_VECTOR_SIZE: structural vectors must be exactly 128 dimensions")
	}
	if start < 0 || end >= len(v1) || start > end {
		return 0, errors.New("INVALID_VECTOR_BOUNDS: dimension partition slice is out of range")
	}

	var dotProduct, normV1, normV2 float64
	for i := start; i <= end; i++ {
		dotProduct += float64(v1[i] * v2[i])
		normV1 += float64(v1[i] * v1[i])
		normV2 += float64(v2[i] * v2[i])
	}

	if normV1 == 0 || normV2 == 0 {
		return 0, nil
	}

	return dotProduct / (math.Sqrt(normV1) * math.Sqrt(normV2)), nil
}

func EvaluateDrift(anchor, mutated StructuralVector, dims InvariantDimensions, threshold float64) AxisCheckResult {
	res := AxisCheckResult{AxisPreserved: true, ReasonCodes: []string{}}

	check := func(start, end int, driftType, reason string) {
		sim, err := CosineSimilarity(anchor, mutated, start, end)
		if err != nil {
			res.AxisPreserved = false
			res.DriftType = "INVALID_AXIS_INPUT"
			res.ReasonCodes = append(res.ReasonCodes, err.Error())
			res.DriftScore = 1.0
			return
		}

		drift := 1.0 - sim
		if drift > threshold {
			res.AxisPreserved = false
			res.ReasonCodes = append(res.ReasonCodes, reason)
			if drift > res.DriftScore {
				res.DriftScore = drift
				res.DriftType = driftType
			}
		}
	}

	check(dims.TemporalityStart, dims.TemporalityEnd, DriftTypeTemporality, ReasonTemporality)
	check(dims.EpistemicStart, dims.EpistemicEnd, DriftTypeEpistemic, ReasonEpistemic)
	check(dims.ScopeStart, dims.ScopeEnd, DriftTypeScope, ReasonScope)
	check(dims.TrustStart, dims.TrustEnd, DriftTypeTrust, ReasonTrust)
	check(dims.MandateStart, dims.MandateEnd, DriftTypeMandate, ReasonMandate)

	return res
}
