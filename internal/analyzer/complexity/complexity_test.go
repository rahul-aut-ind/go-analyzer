// Package complexity_test provides unit tests for the complexity analyzer.
// White-box helpers (ExportedCyclomaticComplexity, ExportedMaxNestingDepth,
// ExportedCountParams) are published from export_test.go so this external
// test package can exercise internal logic directly.
package complexity_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahul-aut-ind/go-analyzer/internal/analyzer/complexity"
)

// parseFunc parses a Go source string and returns the first *ast.FuncDecl
// together with its token.FileSet.
func parseFunc(t *testing.T, src string) (*ast.FuncDecl, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", "package p\n"+src, 0)
	if err != nil {
		t.Fatalf("parseFunc: %v", err)
	}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			return fn, fset
		}
	}
	t.Fatal("parseFunc: no function declaration found in source")
	return nil, nil
}

// ----- cyclomatic complexity tests -----

// TestCyclomaticComplexity_BelowThreshold verifies that a simple function
// with no branches has complexity 1 and would not be flagged by CMPLX001.
func TestCyclomaticComplexity_BelowThreshold(t *testing.T) {
	src := `func simple(x int) int { return x + 1 }`
	fn, _ := parseFunc(t, src)
	got := complexity.ExportedCyclomaticComplexity(fn)
	if got != 1 {
		t.Errorf("expected complexity 1, got %d", got)
	}
}

// TestCyclomaticComplexity_ExactlyEleven verifies that a function with
// exactly 11 added decision points (total complexity = 12) is detected.
//
// Branch accounting:
//
//	start=1
//	if a > 0          +1 → 2
//	else if a < 0     +1 → 3
//	if b > 0          +1 → 4
//	else if b < 0     +1 → 5
//	if c > 0          +1 → 6
//	if d > 0 && e > 0 +1(if)+1(&&) → 8
//	else if d < 0     +1 → 9
//	case 1:           +1 → 10
//	case 2:           +1 → 11
//	case 3:           +1 → 12
func TestCyclomaticComplexity_ExactlyEleven(t *testing.T) {
	src := `
func withElevenBranches(a, b, c, d, e, f int) string {
	result := ""
	if a > 0 {
		result += "a"
	} else if a < 0 {
		result += "neg-a"
	}
	if b > 0 {
		result += "b"
	} else if b < 0 {
		result += "neg-b"
	}
	if c > 0 {
		result += "c"
	}
	if d > 0 && e > 0 {
		result += "de"
	} else if d < 0 {
		result += "neg-d"
	}
	switch f {
	case 1:
		result += "one"
	case 2:
		result += "two"
	case 3:
		result += "three"
	default:
		result += "other"
	}
	return result
}`
	fn, _ := parseFunc(t, src)
	got := complexity.ExportedCyclomaticComplexity(fn)
	if got <= 10 {
		t.Errorf("expected complexity > 10, got %d (should be flagged by CMPLX001)", got)
	}
}

// TestCyclomaticComplexity_ForAndRange verifies that for loops and range
// statements each contribute +1 to complexity.
func TestCyclomaticComplexity_ForAndRange(t *testing.T) {
	src := `
func withLoops(items []int) int {
	sum := 0
	for i := 0; i < 10; i++ {
		sum++
	}
	for _, v := range items {
		sum += v
	}
	return sum
}`
	fn, _ := parseFunc(t, src)
	// start=1, for=+1, range=+1 → 3
	got := complexity.ExportedCyclomaticComplexity(fn)
	if got != 3 {
		t.Errorf("expected complexity 3, got %d", got)
	}
}

// TestCyclomaticComplexity_SelectAndLogical verifies that select CommClauses
// and logical operators (&&, ||) are each counted.
func TestCyclomaticComplexity_SelectAndLogical(t *testing.T) {
	src := `
func withSelectAndLogical(ch1, ch2 <-chan int, x, y bool) {
	select {
	case <-ch1:
	case <-ch2:
	default:
	}
	if x && y {
	}
}`
	fn, _ := parseFunc(t, src)
	// start=1, case ch1=+1, case ch2=+1, if=+1, &&=+1 → 5
	got := complexity.ExportedCyclomaticComplexity(fn)
	if got != 5 {
		t.Errorf("expected complexity 5, got %d", got)
	}
}

// TestCyclomaticComplexity_LogicalOrCounted verifies || is counted.
func TestCyclomaticComplexity_LogicalOrCounted(t *testing.T) {
	src := `
func withOr(a, b bool) {
	if a || b {
	}
}`
	fn, _ := parseFunc(t, src)
	// start=1, if=+1, ||=+1 → 3
	got := complexity.ExportedCyclomaticComplexity(fn)
	if got != 3 {
		t.Errorf("expected complexity 3, got %d", got)
	}
}

// TestCyclomaticComplexity_DefaultCaseNotCounted verifies that the default
// clause in a switch does not add to cyclomatic complexity.
func TestCyclomaticComplexity_DefaultCaseNotCounted(t *testing.T) {
	src := `
func withDefault(x int) {
	switch x {
	case 1:
	default:
	}
}`
	fn, _ := parseFunc(t, src)
	// start=1, case 1=+1 → 2 (default not counted)
	got := complexity.ExportedCyclomaticComplexity(fn)
	if got != 2 {
		t.Errorf("expected complexity 2, got %d", got)
	}
}

// ----- nesting depth tests -----

// TestNestingDepth_BelowThreshold verifies that exactly 4 levels of nesting
// do not exceed the threshold (threshold is > 4, so 4 is acceptable).
func TestNestingDepth_BelowThreshold(t *testing.T) {
	src := `
func fourLevels(a, b, c, d bool) {
	if a {            // depth 1
		if b {        // depth 2
			if c {    // depth 3
				if d {// depth 4
				}
			}
		}
	}
}`
	fn, _ := parseFunc(t, src)
	got := complexity.ExportedMaxNestingDepth(fn.Body)
	if got > 4 {
		t.Errorf("expected depth <= 4, got %d", got)
	}
	if got != 4 {
		t.Errorf("expected depth to be exactly 4, got %d", got)
	}
}

// TestNestingDepth_FiveLevels verifies that 5 nested levels of control flow
// are detected and correctly counted, triggering CMPLX003.
func TestNestingDepth_FiveLevels(t *testing.T) {
	src := `
func fiveLevels(a, b, c, d, e bool) {
	if a {                 // depth 1
		if b {             // depth 2
			if c {         // depth 3
				if d {     // depth 4
					if e { // depth 5
					}
				}
			}
		}
	}
}`
	fn, _ := parseFunc(t, src)
	got := complexity.ExportedMaxNestingDepth(fn.Body)
	if got != 5 {
		t.Errorf("expected depth 5, got %d", got)
	}
}

// TestNestingDepth_ForInIf verifies that mixed nesting types (if inside for,
// etc.) are counted correctly.
func TestNestingDepth_ForInIf(t *testing.T) {
	src := `
func mixed(items []int, flag bool) {
	if flag {                    // depth 1
		for _, v := range items { // depth 2
			if v > 0 {           // depth 3
				_ = v
			}
		}
	}
}`
	fn, _ := parseFunc(t, src)
	got := complexity.ExportedMaxNestingDepth(fn.Body)
	if got != 3 {
		t.Errorf("expected depth 3, got %d", got)
	}
}

// TestNestingDepth_FlatFunction verifies a function with no nesting has depth 0.
func TestNestingDepth_FlatFunction(t *testing.T) {
	src := `func flat() { x := 1; _ = x }`
	fn, _ := parseFunc(t, src)
	got := complexity.ExportedMaxNestingDepth(fn.Body)
	if got != 0 {
		t.Errorf("expected depth 0, got %d", got)
	}
}

// TestNestingDepth_SwitchCounts verifies that switch adds a nesting level.
func TestNestingDepth_SwitchCounts(t *testing.T) {
	src := `
func withSwitch(x int) {
	switch x { // depth 1
	case 1:
		if x > 0 { // depth 2
		}
	}
}`
	fn, _ := parseFunc(t, src)
	got := complexity.ExportedMaxNestingDepth(fn.Body)
	if got != 2 {
		t.Errorf("expected depth 2, got %d", got)
	}
}

// ----- parameter count tests -----

// TestCountParams_BelowThreshold verifies that 5 parameters are counted
// correctly and would not trigger CMPLX004.
func TestCountParams_BelowThreshold(t *testing.T) {
	src := `func fiveParams(a, b, c, d, e int) {}`
	fn, _ := parseFunc(t, src)
	got := complexity.ExportedCountParams(fn)
	if got != 5 {
		t.Errorf("expected 5 params, got %d", got)
	}
}

// TestCountParams_SixParams verifies that 6 parameters exceed the threshold
// and would trigger CMPLX004.
func TestCountParams_SixParams(t *testing.T) {
	src := `func sixParams(a, b, c, d, e, f int) {}`
	fn, _ := parseFunc(t, src)
	got := complexity.ExportedCountParams(fn)
	if got != 6 {
		t.Errorf("expected 6 params, got %d", got)
	}
}

// TestCountParams_MultipleTypes verifies correct counting when parameters
// span multiple type groups (e.g. "a, b int, c string, d, e, f bool").
func TestCountParams_MultipleTypes(t *testing.T) {
	src := `func multiType(a, b int, c string, d, e, f bool) {}`
	fn, _ := parseFunc(t, src)
	// a,b=2 + c=1 + d,e,f=3 → 6
	got := complexity.ExportedCountParams(fn)
	if got != 6 {
		t.Errorf("expected 6 params, got %d", got)
	}
}

// TestCountParams_NoParams verifies that a function with no parameters
// returns 0.
func TestCountParams_NoParams(t *testing.T) {
	src := `func noParams() {}`
	fn, _ := parseFunc(t, src)
	got := complexity.ExportedCountParams(fn)
	if got != 0 {
		t.Errorf("expected 0 params, got %d", got)
	}
}

// TestCountParams_SingleParam verifies a single named parameter.
func TestCountParams_SingleParam(t *testing.T) {
	src := `func oneParam(x int) {}`
	fn, _ := parseFunc(t, src)
	got := complexity.ExportedCountParams(fn)
	if got != 1 {
		t.Errorf("expected 1 param, got %d", got)
	}
}

// ----- integration tests against testdata/sample -----

// TestRun_DetectsTestdataSampleViolations runs the full complexity analyzer
// against the testdata/sample module and verifies expected findings for
// HighComplexityFunction.
func TestRun_DetectsTestdataSampleViolations(t *testing.T) {
	sampleDir, err := findTestdata()
	if err != nil {
		t.Skipf("testdata/sample not found, skipping integration test: %v", err)
	}

	a := complexity.New()
	findings, err := a.Run(sampleDir)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	wantRules := map[string]bool{
		"CMPLX001": false,
		"CMPLX004": false,
	}

	for _, f := range findings {
		if _, ok := wantRules[f.RuleID]; ok {
			wantRules[f.RuleID] = true
		}
	}

	for ruleID, found := range wantRules {
		if !found {
			t.Errorf("expected finding %s to be reported, but it was not", ruleID)
		}
	}
}

// TestRun_CMPLX001_FunctionName verifies that the CMPLX001 finding message
// names the HighComplexityFunction function.
func TestRun_CMPLX001_FunctionName(t *testing.T) {
	sampleDir, err := findTestdata()
	if err != nil {
		t.Skipf("testdata/sample not found: %v", err)
	}

	a := complexity.New()
	findings, err := a.Run(sampleDir)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	for _, f := range findings {
		if f.RuleID == "CMPLX001" {
			if !strings.Contains(f.Message, "HighComplexityFunction") {
				t.Errorf("CMPLX001 finding does not mention HighComplexityFunction: %s", f.Message)
			}
			return
		}
	}
	t.Error("no CMPLX001 finding found")
}

// TestRun_CMPLX004_FunctionName verifies that the CMPLX004 finding message
// names the HighComplexityFunction function.
func TestRun_CMPLX004_FunctionName(t *testing.T) {
	sampleDir, err := findTestdata()
	if err != nil {
		t.Skipf("testdata/sample not found: %v", err)
	}

	a := complexity.New()
	findings, err := a.Run(sampleDir)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	for _, f := range findings {
		if f.RuleID == "CMPLX004" {
			if !strings.Contains(f.Message, "HighComplexityFunction") {
				t.Errorf("CMPLX004 finding does not mention HighComplexityFunction: %s", f.Message)
			}
			return
		}
	}
	t.Error("no CMPLX004 finding found")
}

// TestRun_FindingsHaveFileAndLine verifies that every finding produced by
// Run has a non-empty File path and a positive Line number.
func TestRun_FindingsHaveFileAndLine(t *testing.T) {
	sampleDir, err := findTestdata()
	if err != nil {
		t.Skipf("testdata/sample not found: %v", err)
	}

	a := complexity.New()
	findings, err := a.Run(sampleDir)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	for _, f := range findings {
		if f.File == "" {
			t.Errorf("finding %s has empty File", f.RuleID)
		}
		if f.Line <= 0 {
			t.Errorf("finding %s has non-positive Line: %d", f.RuleID, f.Line)
		}
	}
}

// TestRun_FindingsHaveSuggestions verifies that every finding includes a
// non-empty Suggestion string.
func TestRun_FindingsHaveSuggestions(t *testing.T) {
	sampleDir, err := findTestdata()
	if err != nil {
		t.Skipf("testdata/sample not found: %v", err)
	}

	a := complexity.New()
	findings, err := a.Run(sampleDir)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	for _, f := range findings {
		if f.Suggestion == "" {
			t.Errorf("finding %s (line %d) has empty Suggestion", f.RuleID, f.Line)
		}
	}
}

// TestAnalyzer_Metadata verifies the Name and Description are non-empty
// and that Name returns "complexity".
func TestAnalyzer_Metadata(t *testing.T) {
	a := complexity.New()
	if a.Name() == "" {
		t.Error("Name() returned empty string")
	}
	if a.Description() == "" {
		t.Error("Description() returned empty string")
	}
	if a.Name() != "complexity" {
		t.Errorf("expected Name() == %q, got %q", "complexity", a.Name())
	}
}

// TestRun_InvalidDir verifies that Run returns an error for a nonexistent
// directory rather than panicking or silently returning empty findings.
func TestRun_InvalidDir(t *testing.T) {
	a := complexity.New()
	_, err := a.Run("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Error("expected error for invalid directory, got nil")
	}
}

// findTestdata walks upward from the current working directory to locate the
// testdata/sample directory at the module root.
func findTestdata() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	current := cwd
	for {
		candidate := filepath.Join(current, "testdata", "sample")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return "", os.ErrNotExist
}
