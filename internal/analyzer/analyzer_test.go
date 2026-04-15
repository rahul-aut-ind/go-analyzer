package analyzer_test

import (
	"testing"

	"github.com/rahul-aut-ind/go-analyzer/internal/analyzer"
)

// freshAnalyzer is a minimal implementation used only in tests.
type freshAnalyzer struct{ name string }

func (a *freshAnalyzer) Name() string        { return a.name }
func (a *freshAnalyzer) Description() string { return "test analyzer" }
func (a *freshAnalyzer) Run(_ string) ([]analyzer.Finding, error) {
	return []analyzer.Finding{
		{RuleID: "TEST001", Severity: "info", Message: "test", File: "f.go", Line: 1},
	}, nil
}

func TestRegisterAndAll(t *testing.T) {
	before := len(analyzer.All())

	a := &freshAnalyzer{name: "register-test"}
	analyzer.Register(a)

	after := analyzer.All()
	if len(after) != before+1 {
		t.Errorf("All() length: want %d, got %d", before+1, len(after))
	}
}

func TestGet_Found(t *testing.T) {
	name := "get-test-found"
	analyzer.Register(&freshAnalyzer{name: name})

	got, ok := analyzer.Get(name)
	if !ok {
		t.Fatalf("Get(%q) returned false, want true", name)
	}
	if got.Name() != name {
		t.Errorf("Get(%q).Name() = %q, want %q", name, got.Name(), name)
	}
}

func TestGet_NotFound(t *testing.T) {
	_, ok := analyzer.Get("no-such-analyzer-xyz")
	if ok {
		t.Error("Get() for unknown name should return false")
	}
}

func TestFinding_Fields(t *testing.T) {
	f := analyzer.Finding{
		RuleID:     "R001",
		Severity:   "high",
		Message:    "msg",
		File:       "main.go",
		Line:       10,
		Column:     5,
		Suggestion: "fix it",
	}
	if f.RuleID != "R001" {
		t.Errorf("RuleID: want R001, got %s", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("Severity: want high, got %s", f.Severity)
	}
}

func TestAll_ReturnsCopy(t *testing.T) {
	a1 := analyzer.All()
	// Modifying a1 must not affect subsequent calls.
	if len(a1) > 0 {
		a1[0] = nil
	}
	a2 := analyzer.All()
	if len(a1) > 0 && a2[0] == nil {
		t.Error("All() returned a slice that shares backing array with internal state")
	}
}
