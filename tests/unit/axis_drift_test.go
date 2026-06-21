package unit

import (
	"go/parser"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"veraxis-memory-admissibility/pkg/axis"
)

func axisBaseVectorForTarget(start, end int) axis.StructuralVector {
	base := make(axis.StructuralVector, 128)
	var mag float64
	for i := 0; i < 128; i++ {
		if i >= start && i <= end {
			base[i] = 0.03 * float32(i%5+1)
		} else {
			base[i] = 0.30 * float32(i%5+1)
		}
		mag += float64(base[i] * base[i])
	}
	mag = math.Sqrt(mag)
	for i := 0; i < 128; i++ {
		base[i] = float32(float64(base[i]) / mag)
	}
	return base
}

func axisBaseVector() axis.StructuralVector {
	base := make(axis.StructuralVector, 128)
	var mag float64
	for i := 0; i < 128; i++ {
		base[i] = 0.1 * float32(i%5+1)
		mag += float64(base[i] * base[i])
	}
	mag = math.Sqrt(mag)
	for i := 0; i < 128; i++ {
		base[i] = float32(float64(base[i]) / mag)
	}
	return base
}

func axisMutateSubspace(base axis.StructuralVector, start, end int, factor float32) axis.StructuralVector {
	mutated := make(axis.StructuralVector, 128)
	copy(mutated, base)
	for i := start; i <= end; i++ {
		mutated[i] = mutated[i] * factor
	}
	var mag float64
	for i := 0; i < 128; i++ {
		mag += float64(mutated[i] * mutated[i])
	}
	mag = math.Sqrt(mag)
	for i := 0; i < 128; i++ {
		mutated[i] = float32(float64(mutated[i]) / mag)
	}
	return mutated
}

func calculateGlobalSimilarity(v1, v2 axis.StructuralVector) float64 {
	var dot, n1, n2 float64
	for i := 0; i < 128; i++ {
		dot += float64(v1[i] * v2[i])
		n1 += float64(v1[i] * v1[i])
		n2 += float64(v2[i] * v2[i])
	}
	if n1 == 0 || n2 == 0 {
		return 0
	}
	return dot / (math.Sqrt(n1) * math.Sqrt(n2))
}

func requireReason(t *testing.T, reasons []string, want string) {
	t.Helper()
	for _, reason := range reasons {
		if reason == want {
			return
		}
	}
	t.Fatalf("missing reason %q in %#v", want, reasons)
}

func TestAxisTemporalityBlindspot(t *testing.T) {
	base := axisBaseVectorForTarget(axis.DefaultDimensions.TemporalityStart, axis.DefaultDimensions.TemporalityEnd)
	mutated := axisMutateSubspace(base, axis.DefaultDimensions.TemporalityStart, axis.DefaultDimensions.TemporalityEnd, -3.5)

	globalSim := calculateGlobalSimilarity(base, mutated)
	if globalSim < 0.95 {
		t.Fatalf("fixture global similarity too low: %f", globalSim)
	}

	res := axis.EvaluateDrift(base, mutated, axis.DefaultDimensions, 0.35)
	if res.AxisPreserved {
		t.Fatal("expected temporality drift")
	}
	if res.DriftType != axis.DriftTypeTemporality {
		t.Fatalf("unexpected drift type: %s", res.DriftType)
	}
	requireReason(t, res.ReasonCodes, axis.ReasonTemporality)
}

func TestAxisEpistemicCorruption(t *testing.T) {
	base := axisBaseVectorForTarget(axis.DefaultDimensions.EpistemicStart, axis.DefaultDimensions.EpistemicEnd)
	mutated := axisMutateSubspace(base, axis.DefaultDimensions.EpistemicStart, axis.DefaultDimensions.EpistemicEnd, -3.5)

	res := axis.EvaluateDrift(base, mutated, axis.DefaultDimensions, 0.35)
	if res.AxisPreserved || res.DriftType != axis.DriftTypeEpistemic {
		t.Fatalf("expected epistemic drift, got %#v", res)
	}
	requireReason(t, res.ReasonCodes, axis.ReasonEpistemic)
}

func TestAxisScopeExpansion(t *testing.T) {
	base := axisBaseVectorForTarget(axis.DefaultDimensions.ScopeStart, axis.DefaultDimensions.ScopeEnd)
	mutated := axisMutateSubspace(base, axis.DefaultDimensions.ScopeStart, axis.DefaultDimensions.ScopeEnd, -3.5)

	res := axis.EvaluateDrift(base, mutated, axis.DefaultDimensions, 0.35)
	if res.AxisPreserved || res.DriftType != axis.DriftTypeScope {
		t.Fatalf("expected scope drift, got %#v", res)
	}
	requireReason(t, res.ReasonCodes, axis.ReasonScope)
}

func TestAxisSourceTrustCollapse(t *testing.T) {
	base := axisBaseVectorForTarget(axis.DefaultDimensions.TrustStart, axis.DefaultDimensions.TrustEnd)
	mutated := axisMutateSubspace(base, axis.DefaultDimensions.TrustStart, axis.DefaultDimensions.TrustEnd, -3.5)

	res := axis.EvaluateDrift(base, mutated, axis.DefaultDimensions, 0.35)
	if res.AxisPreserved || res.DriftType != axis.DriftTypeTrust {
		t.Fatalf("expected trust drift, got %#v", res)
	}
	requireReason(t, res.ReasonCodes, axis.ReasonTrust)
}

func TestAxisMandateConfusion(t *testing.T) {
	base := axisBaseVectorForTarget(axis.DefaultDimensions.MandateStart, axis.DefaultDimensions.MandateEnd)
	mutated := axisMutateSubspace(base, axis.DefaultDimensions.MandateStart, axis.DefaultDimensions.MandateEnd, -3.5)

	res := axis.EvaluateDrift(base, mutated, axis.DefaultDimensions, 0.35)
	if res.AxisPreserved || res.DriftType != axis.DriftTypeMandate {
		t.Fatalf("expected mandate drift, got %#v", res)
	}
	requireReason(t, res.ReasonCodes, axis.ReasonMandate)
}

func TestAxisCleanControl(t *testing.T) {
	base := axisBaseVector()

	res := axis.EvaluateDrift(base, base, axis.DefaultDimensions, 0.35)
	if !res.AxisPreserved {
		t.Fatalf("expected preserved axis, got %#v", res)
	}
	if res.DriftScore != 0 {
		t.Fatalf("expected zero drift, got %f", res.DriftScore)
	}
}

func TestAxisInvalidBoundsAndNullVectors(t *testing.T) {
	base := axisBaseVector()
	_, err := axis.CosineSimilarity(base, base, 30, 29)
	if err == nil {
		t.Fatal("expected invalid bounds error")
	}

	null1 := make(axis.StructuralVector, 128)
	null2 := make(axis.StructuralVector, 128)
	sim, err := axis.CosineSimilarity(null1, null2, 0, 31)
	if err != nil {
		t.Fatalf("unexpected null vector error: %v", err)
	}
	if sim != 0 {
		t.Fatalf("expected null vector similarity 0, got %f", sim)
	}
}

func TestAxisFixtureFileExists(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "benchmarks", "axis_fixtures", "fixtures.json")
	b, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("fixtures.json missing: %v", err)
	}
	if !strings.Contains(string(b), "temporality_shift_001") {
		t.Fatal("fixtures.json missing temporality fixture")
	}
}

func TestAxisNotImportedByHotPathPackages(t *testing.T) {
	paths := []string{
		filepath.Join("..", "..", "pkg", "evaluate"),
		filepath.Join("..", "..", "pkg", "bitmask"),
		filepath.Join("..", "..", "pkg", "tenant"),
	}

	for _, root := range paths {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
				continue
			}
			filePath := filepath.Join(root, entry.Name())
			file, err := parser.ParseFile(token.NewFileSet(), filePath, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range file.Imports {
				if strings.Contains(imp.Path.Value, "pkg/axis") {
					t.Fatalf("hot path package imports axis: %s", filePath)
				}
			}
		}
	}
}
