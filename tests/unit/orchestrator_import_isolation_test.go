package unit

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCorePackagesDoNotImportOrchestrator(t *testing.T) {
	paths := []string{
		filepath.Join("..", "..", "pkg", "evaluate"),
		filepath.Join("..", "..", "pkg", "bitmask"),
		filepath.Join("..", "..", "pkg", "tenant"),
		filepath.Join("..", "..", "pkg", "quarantine"),
		filepath.Join("..", "..", "pkg", "gateway"),
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
				if strings.Contains(imp.Path.Value, "pkg/orchestrator") {
					t.Fatalf("core package imports orchestrator: %s", filePath)
				}
			}
		}
	}
}
