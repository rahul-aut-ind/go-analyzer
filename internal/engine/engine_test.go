package engine

import (
	"testing"

	"github.com/rahul-aut-ind/go-analyzer/internal/analyzer"
	"github.com/rahul-aut-ind/go-analyzer/internal/config"
)

// mockAnalyzer is a test double that returns pre-canned findings.
type mockAnalyzer struct {
	name     string
	findings []analyzer.Finding
	err      error
}

func (m *mockAnalyzer) Name() string        { return m.name }
func (m *mockAnalyzer) Description() string { return "mock analyzer for testing" }
func (m *mockAnalyzer) Run(_ string) ([]analyzer.Finding, error) {
	return m.findings, m.err
}

func defaultConfig() *config.Config {
	cfg, _ := config.Load("")
	return cfg
}

func TestRun_EmptyAnalyzers(t *testing.T) {
	result, err := Run(RunOptions{Dir: ".", Config: defaultConfig()})
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if result == nil {
		t.Fatal("Run() returned nil result")
	}
}

func TestRun_CollectsFindings(t *testing.T) {
	f1 := analyzer.Finding{RuleID: "TEST001", Severity: "high", Message: "test finding 1", File: "a.go", Line: 1}
	f2 := analyzer.Finding{RuleID: "TEST002", Severity: "low", Message: "test finding 2", File: "b.go", Line: 5}

	ma1 := &mockAnalyzer{name: "engine-mock1", findings: []analyzer.Finding{f1}}
	ma2 := &mockAnalyzer{name: "engine-mock2", findings: []analyzer.Finding{f2}}

	analyzer.Register(ma1)
	analyzer.Register(ma2)

	result, err := Run(RunOptions{
		Dir:    ".",
		Config: defaultConfig(),
		Only:   []string{"engine-mock1", "engine-mock2"},
	})
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	found1, found2 := false, false
	for _, f := range result.Findings {
		if f.RuleID == "TEST001" {
			found1 = true
		}
		if f.RuleID == "TEST002" {
			found2 = true
		}
	}
	if !found1 || !found2 {
		t.Errorf("missing expected findings in result: %+v", result.Findings)
	}

	if len(result.Findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(result.Findings))
	}
	// First finding should have higher or equal severity vs last.
	first := severityOrder[result.Findings[0].Severity]
	last := severityOrder[result.Findings[len(result.Findings)-1].Severity]
	if first < last {
		t.Error("findings not sorted by severity descending")
	}
}

func TestRun_AnalyzerError(t *testing.T) {
	bad := &mockAnalyzer{name: "engine-bad-mock", err: errAnalyzerFailed}
	analyzer.Register(bad)

	result, err := Run(RunOptions{
		Dir:    ".",
		Config: defaultConfig(),
		Only:   []string{"engine-bad-mock"},
	})
	if err != nil {
		t.Fatalf("Run() should not propagate analyzer-level errors: %v", err)
	}
	if result.Errors["engine-bad-mock"] == nil {
		t.Error("expected error recorded for engine-bad-mock analyzer")
	}
}

func TestRun_OnlyFilter(t *testing.T) {
	ma := &mockAnalyzer{name: "engine-filter-mock", findings: []analyzer.Finding{
		{RuleID: "EF001", Severity: "low", File: "x.go", Line: 1},
	}}
	analyzer.Register(ma)

	result, err := Run(RunOptions{Dir: ".", Config: defaultConfig(), Only: []string{"engine-filter-mock"}})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range result.Findings {
		if f.RuleID == "EF001" {
			found = true
		}
	}
	if !found {
		t.Error("expected EF001 finding when only=engine-filter-mock")
	}
}

func TestRun_SkipFilter(t *testing.T) {
	ma := &mockAnalyzer{name: "engine-skip-mock", findings: []analyzer.Finding{
		{RuleID: "ES001", Severity: "low", File: "x.go", Line: 1},
	}}
	analyzer.Register(ma)

	result, err := Run(RunOptions{Dir: ".", Config: defaultConfig(), Skip: []string{"engine-skip-mock"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.RuleID == "ES001" {
			t.Error("ES001 finding should have been skipped")
		}
	}
}

// errAnalyzerFailed is a sentinel error used by mockAnalyzer tests.
var errAnalyzerFailed = analyzerError("simulated analyzer failure")

type analyzerError string

func (e analyzerError) Error() string { return string(e) }
