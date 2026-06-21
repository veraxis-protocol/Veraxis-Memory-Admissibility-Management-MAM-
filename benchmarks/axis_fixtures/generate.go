package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
)

type AxisFixture struct {
	FixtureID                   string    `json:"fixture_id"`
	Category                    string    `json:"category"`
	AnchorDescription           string    `json:"anchor_description"`
	MutatedDescription          string    `json:"mutated_description"`
	ExpectedDriftType           string    `json:"expected_drift_type"`
	ExpectedReasonCode          string    `json:"expected_reason_code"`
	GlobalSimilarityExpectedMin float64   `json:"global_similarity_expected_min"`
	AxisDriftExpectedMin        float64   `json:"axis_drift_expected_min"`
	AnchorVector                []float32 `json:"anchor_vector"`
	MutatedVector               []float32 `json:"mutated_vector"`
}

// GenerateBaseVector builds a normalized vector where the target axis has low
// global mass but remains structurally meaningful inside the isolated subspace.
// This preserves high global similarity while making axis-local drift visible.
func GenerateBaseVector(targetStart, targetEnd int) []float32 {
	v := make([]float32, 128)
	for i := 0; i < 128; i++ {
		if i >= targetStart && i <= targetEnd {
			v[i] = 0.03 * float32(i%5+1)
		} else {
			v[i] = 0.30 * float32(i%5+1)
		}
	}
	normalize(v)
	return v
}

func NormalizeBaseVector() []float32 {
	v := make([]float32, 128)
	for i := 0; i < 128; i++ {
		v[i] = 0.1 * float32(i%5+1)
	}
	normalize(v)
	return v
}

func MutateSubspace(base []float32, start, end int, factor float32) []float32 {
	mutated := make([]float32, 128)
	copy(mutated, base)
	for i := start; i <= end; i++ {
		mutated[i] = mutated[i] * factor
	}
	normalize(mutated)
	return mutated
}

func normalize(v []float32) {
	var mag float64
	for i := 0; i < len(v); i++ {
		mag += float64(v[i] * v[i])
	}
	mag = math.Sqrt(mag)
	if mag == 0 {
		return
	}
	for i := 0; i < len(v); i++ {
		v[i] = float32(float64(v[i]) / mag)
	}
}

func fixture(id, category, anchor, mutated, driftType, reason string, start, end int) AxisFixture {
	base := GenerateBaseVector(start, end)
	return AxisFixture{
		FixtureID:                   id,
		Category:                    category,
		AnchorDescription:           anchor,
		MutatedDescription:          mutated,
		ExpectedDriftType:           driftType,
		ExpectedReasonCode:          reason,
		GlobalSimilarityExpectedMin: 0.95,
		AxisDriftExpectedMin:        1.50,
		AnchorVector:                base,
		MutatedVector:               MutateSubspace(base, start, end, -3.5),
	}
}

func main() {
	cleanBase := NormalizeBaseVector()

	fixtures := []AxisFixture{
		fixture("temporality_shift_001", "TEMPORALITY_SHIFT", "User is currently frustrated with logging in.", "User is an abusive client with ongoing security risks.", "TEMPORARY_STATE_PROMOTED_TO_STABLE_TRAIT", "TEMPORARITY_DRIFT_DETECTED", 0, 23),
		fixture("epistemic_shift_001", "EPISTEMIC_MODAL_SHIFT", "The support note says the user suspects a double billing error.", "The system confirmed a double billing error occurred.", "INFERENCE_PROMOTED_TO_FACT", "EPISTEMIC_MODAL_SHIFT", 24, 47),
		fixture("scope_expansion_001", "SCOPE_EXPANSION", "Apply a 10% discount for this specific delayed order code.", "Always apply a 10% discount globally to this user profile.", "CONTEXT_BOUND_MEMORY_REUSED_GLOBALLY", "SCOPE_EXPANSION_VIOLATION", 48, 71),
		fixture("source_trust_001", "SOURCE_TRUST_COLLAPSE", "Unverified customer statement claims prior approval.", "Customer has prior approval.", "LOW_TRUST_SOURCE_PROMOTED", "SOURCE_TRUST_COLLAPSE", 72, 95),
		fixture("mandate_confusion_001", "MANDATE_CONFUSION", "User prefers faster responses.", "Agent is authorized to skip review steps for this user.", "PREFERENCE_PROMOTED_TO_MANDATE", "PREFERENCE_PROMOTED_TO_AUTHORITY", 96, 127),
		{
			FixtureID:                   "clean_control_001",
			Category:                    "CLEAN_CONTROL",
			AnchorDescription:           "User prefers concise responses.",
			MutatedDescription:          "User prefers concise answers.",
			ExpectedDriftType:           "",
			ExpectedReasonCode:          "",
			GlobalSimilarityExpectedMin: 0.99,
			AxisDriftExpectedMin:        0.00,
			AnchorVector:                cleanBase,
			MutatedVector:               cleanBase,
		},
	}

	dir := "benchmarks/axis_fixtures"
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Printf("Fixture directory failure: %v\n", err)
		os.Exit(1)
	}
	filePath := filepath.Join(dir, "fixtures.json")
	file, err := os.Create(filePath)
	if err != nil {
		fmt.Printf("Fixture registration failure: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(fixtures); err != nil {
		fmt.Printf("JSON payload serialization failure: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✔ Step 14B Complete: Synthetic testing terrain committed to fixtures.json.")
}
