package race

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahul-aut-ind/go-analyzer/internal/analyzer"
)

// ---- helpers ----------------------------------------------------------------

// writeFile creates a file at path with the given content, creating parent
// directories as needed. It calls t.Fatal on any error.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// runOnSrc writes src into a temp dir and runs the race analyzer, returning the
// findings.
func runOnSrc(t *testing.T, src string) []analyzer.Finding {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "main.go"), src)
	findings, err := runRaceAnalysis(dir)
	if err != nil {
		t.Fatalf("runRaceAnalysis: %v", err)
	}
	return findings
}

// findingsWithRule returns the subset of findings whose RuleID matches rule.
func findingsWithRule(findings []analyzer.Finding, rule string) []analyzer.Finding {
	var out []analyzer.Finding
	for _, f := range findings {
		if f.RuleID == rule {
			out = append(out, f)
		}
	}
	return out
}

// ---- RACE001 ----------------------------------------------------------------

func TestRACE001_LoopVariableCapture(t *testing.T) {
	src := `package main

import (
	"fmt"
	"sync"
)

func RaceLoopCapture() {
	values := []int{1, 2, 3}
	var wg sync.WaitGroup
	for _, v := range values {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println(v) // v captured from outer scope
		}()
	}
	wg.Wait()
}
`
	findings := runOnSrc(t, src)
	race001 := findingsWithRule(findings, "RACE001")
	if len(race001) == 0 {
		t.Fatal("expected at least one RACE001 finding, got none")
	}
	f := race001[0]
	if !strings.Contains(f.Message, "v") {
		t.Errorf("expected message to mention variable 'v', got: %s", f.Message)
	}
	if f.Severity != "high" {
		t.Errorf("expected severity 'high', got %q", f.Severity)
	}
	if f.File == "" {
		t.Error("finding should have a non-empty File field")
	}
}

func TestRACE001_MultipleLoopVars(t *testing.T) {
	src := `package main

import (
	"fmt"
	"sync"
)

func example() {
	m := map[string]int{"a": 1, "b": 2}
	var wg sync.WaitGroup
	for k, v := range m {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println(k, v)
		}()
	}
	wg.Wait()
}
`
	findings := runOnSrc(t, src)
	race001 := findingsWithRule(findings, "RACE001")
	if len(race001) == 0 {
		t.Fatal("expected RACE001 finding for both k and v capture, got none")
	}
}

func TestRACE001_NoCapture_VariableShadowed(t *testing.T) {
	// When the loop variable is passed as an argument it should NOT be flagged.
	src := `package main

import (
	"fmt"
	"sync"
)

func SafeCapture() {
	values := []int{1, 2, 3}
	var wg sync.WaitGroup
	for _, v := range values {
		wg.Add(1)
		go func(v int) {
			defer wg.Done()
			fmt.Println(v)
		}(v)
	}
	wg.Wait()
}
`
	findings := runOnSrc(t, src)
	race001 := findingsWithRule(findings, "RACE001")
	if len(race001) != 0 {
		t.Errorf("expected no RACE001 findings for safe capture, got %d: %+v", len(race001), race001)
	}
}

func TestRACE001_NoGoroutine(t *testing.T) {
	src := `package main

import "fmt"

func NoGoroutine() {
	values := []int{1, 2, 3}
	for _, v := range values {
		fmt.Println(v)
	}
}
`
	findings := runOnSrc(t, src)
	race001 := findingsWithRule(findings, "RACE001")
	if len(race001) != 0 {
		t.Errorf("expected no RACE001 findings, got %d", len(race001))
	}
}

// ---- RACE002 ----------------------------------------------------------------

func TestRACE002_MapWriteInGoroutine(t *testing.T) {
	src := `package main

import (
	"fmt"
	"sync"
)

func RaceMapWrite() {
	m := make(map[string]int)
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			m[fmt.Sprintf("key%d", n)] = n
		}(i)
	}
	wg.Wait()
}
`
	findings := runOnSrc(t, src)
	race002 := findingsWithRule(findings, "RACE002")
	if len(race002) == 0 {
		t.Fatal("expected at least one RACE002 finding, got none")
	}
	f := race002[0]
	if f.Severity != "high" {
		t.Errorf("expected severity 'high', got %q", f.Severity)
	}
	if !strings.Contains(strings.ToLower(f.Suggestion), "mutex") &&
		!strings.Contains(strings.ToLower(f.Suggestion), "sync.map") {
		t.Errorf("suggestion should mention mutex or sync.Map, got: %s", f.Suggestion)
	}
}

func TestRACE002_NoMapWrite(t *testing.T) {
	src := `package main

import (
	"fmt"
	"sync"
)

func SafeGoroutine() {
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			fmt.Println(n)
		}(i)
	}
	wg.Wait()
}
`
	findings := runOnSrc(t, src)
	race002 := findingsWithRule(findings, "RACE002")
	if len(race002) != 0 {
		t.Errorf("expected no RACE002 findings, got %d", len(race002))
	}
}

// ---- RACE003 ----------------------------------------------------------------

func TestRACE003_NonAtomicIncrement(t *testing.T) {
	src := `package main

import "sync"

func RaceCounter() {
	var counter int
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			counter++ // non-atomic increment
		}()
	}
	wg.Wait()
}
`
	findings := runOnSrc(t, src)
	race003 := findingsWithRule(findings, "RACE003")
	if len(race003) == 0 {
		t.Fatal("expected at least one RACE003 finding, got none")
	}
	f := race003[0]
	if f.Severity != "high" {
		t.Errorf("expected severity 'high', got %q", f.Severity)
	}
	if !strings.Contains(f.Message, "++") {
		t.Errorf("expected message to mention '++', got: %s", f.Message)
	}
}

func TestRACE003_NonAtomicDecrement(t *testing.T) {
	src := `package main

import "sync"

func RaceDecrement() {
	var counter int = 100
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			counter-- // non-atomic decrement
		}()
	}
	wg.Wait()
}
`
	findings := runOnSrc(t, src)
	race003 := findingsWithRule(findings, "RACE003")
	if len(race003) == 0 {
		t.Fatal("expected at least one RACE003 finding, got none")
	}
	f := race003[0]
	if !strings.Contains(f.Message, "--") {
		t.Errorf("expected message to mention '--', got: %s", f.Message)
	}
}

func TestRACE003_LocalVarIncrement_Flagged(t *testing.T) {
	// Even local increments inside goroutines are flagged (the analyzer cannot
	// distinguish shared from local via the heuristic).
	src := `package main

import "sync"

func LocalIncrement() {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		localVar := 0
		localVar++
		_ = localVar
	}()
	wg.Wait()
}
`
	findings := runOnSrc(t, src)
	race003 := findingsWithRule(findings, "RACE003")
	// We expect it to be flagged since we cannot distinguish local from shared.
	if len(race003) == 0 {
		t.Fatal("expected RACE003 finding for ++ inside goroutine, got none")
	}
}

// ---- RACE004 ----------------------------------------------------------------

func TestRACE004_WaitGroupAddInsideGoroutine(t *testing.T) {
	src := `package main

import "sync"

func BadWaitGroup() {
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		go func() {
			wg.Add(1) // should be called before the goroutine
			defer wg.Done()
		}()
	}
	wg.Wait()
}
`
	findings := runOnSrc(t, src)
	race004 := findingsWithRule(findings, "RACE004")
	if len(race004) == 0 {
		t.Fatal("expected at least one RACE004 finding, got none")
	}
	f := race004[0]
	if f.Severity != "medium" {
		t.Errorf("expected severity 'medium', got %q", f.Severity)
	}
	if !strings.Contains(strings.ToLower(f.Suggestion), "before") {
		t.Errorf("suggestion should mention calling Add before goroutine, got: %s", f.Suggestion)
	}
}

func TestRACE004_WaitGroupAddBeforeGoroutine(t *testing.T) {
	// Correct usage: wg.Add is called before launching the goroutine.
	src := `package main

import "sync"

func GoodWaitGroup() {
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
		}()
	}
	wg.Wait()
}
`
	findings := runOnSrc(t, src)
	race004 := findingsWithRule(findings, "RACE004")
	if len(race004) != 0 {
		t.Errorf("expected no RACE004 findings for correct wg.Add usage, got %d", len(race004))
	}
}

// ---- empty / no-Go-files edge cases -----------------------------------------

func TestRun_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	findings, err := runRaceAnalysis(dir)
	if err != nil {
		t.Fatalf("unexpected error on empty dir: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for empty dir, got %d", len(findings))
	}
}

func TestRun_NonExistentDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	// Should return an error or empty findings, not panic.
	findings, err := runRaceAnalysis(dir)
	// Either outcome is acceptable as long as there is no panic.
	_ = findings
	_ = err
}

func TestRun_InvalidGoFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "bad.go"), `package main; func broken( {`)
	// Should skip the file gracefully.
	findings, err := runRaceAnalysis(dir)
	if err != nil {
		t.Fatalf("unexpected error on invalid Go file: %v", err)
	}
	_ = findings
}

// ---- testdata/sample fixture -------------------------------------------------

func TestRunOnSampleFixture(t *testing.T) {
	// Find the testdata/sample directory relative to this test file.
	sampleDir := filepath.Join("..", "..", "..", "testdata", "sample")
	absDir, err := filepath.Abs(sampleDir)
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	if _, err := os.Stat(absDir); err != nil {
		t.Skipf("testdata/sample not found: %v", err)
	}

	findings, err := runRaceAnalysis(absDir)
	if err != nil {
		t.Fatalf("runRaceAnalysis: %v", err)
	}

	tests := []struct {
		rule    string
		wantMin int
	}{
		{"RACE001", 1},
		{"RACE002", 1},
	}

	for _, tc := range tests {
		t.Run(tc.rule, func(t *testing.T) {
			got := findingsWithRule(findings, tc.rule)
			if len(got) < tc.wantMin {
				t.Errorf("expected at least %d %s findings in testdata/sample, got %d", tc.wantMin, tc.rule, len(got))
			}
		})
	}
}

// ---- Analyzer interface / registration --------------------------------------

func TestNew_ImplementsInterface(t *testing.T) {
	a := New()
	if a.Name() != "race" {
		t.Errorf("expected name 'race', got %q", a.Name())
	}
	if a.Description() == "" {
		t.Error("Description() returned empty string")
	}
}

func TestNew_Run(t *testing.T) {
	a := New()
	dir := t.TempDir()
	findings, err := a.Run(dir)
	if err != nil {
		t.Fatalf("Run on empty dir: %v", err)
	}
	_ = findings
}

// ---- parseRaceOutput --------------------------------------------------------

func TestParseRaceOutput_BasicReport(t *testing.T) {
	output := `==================
WARNING: DATA RACE
Write at 0x00c0000ba018 by goroutine 7:
  main.RaceCounter.func1()
      /tmp/myapp/main.go:12 +0x28

Previous read at 0x00c0000ba018 by goroutine 6:
  main.RaceCounter.func1()
      /tmp/myapp/main.go:12 +0x28

==================
`
	findings := parseRaceOutput(output, "/tmp/myapp")
	if len(findings) == 0 {
		t.Fatal("expected findings from race output, got none")
	}
	f := findings[0]
	if f.RuleID != "RACE000" {
		t.Errorf("expected RuleID RACE000, got %q", f.RuleID)
	}
	if f.Line != 12 {
		t.Errorf("expected line 12, got %d", f.Line)
	}
}

func TestParseRaceOutput_Empty(t *testing.T) {
	findings := parseRaceOutput("", "/tmp")
	if len(findings) != 0 {
		t.Errorf("expected no findings from empty output, got %d", len(findings))
	}
}

func TestParseRaceOutput_NoRace(t *testing.T) {
	output := `ok  	example.com/myapp	0.123s
`
	findings := parseRaceOutput(output, "/tmp")
	if len(findings) != 0 {
		t.Errorf("expected no findings when no DATA RACE in output, got %d", len(findings))
	}
}

func TestParseRaceOutput_Deduplication(t *testing.T) {
	// The same file:line appears twice in the race report; should deduplicate.
	output := `==================
WARNING: DATA RACE
Write at 0x00c0000ba018 by goroutine 7:
  main.foo()
      /tmp/myapp/main.go:20 +0x28

Previous read at 0x00c0000ba018 by goroutine 6:
  main.foo()
      /tmp/myapp/main.go:20 +0x28

==================
`
	findings := parseRaceOutput(output, "/tmp/myapp")
	if len(findings) != 1 {
		t.Errorf("expected 1 deduplicated finding, got %d", len(findings))
	}
}

// ---- mergeFindings ----------------------------------------------------------

func TestMergeFindings_Deduplication(t *testing.T) {
	f := analyzer.Finding{RuleID: "RACE001", File: "main.go", Line: 10}
	merged := mergeFindings([]analyzer.Finding{f}, []analyzer.Finding{f})
	if len(merged) != 1 {
		t.Errorf("expected 1 deduplicated finding, got %d", len(merged))
	}
}

func TestMergeFindings_BothSetsPreserved(t *testing.T) {
	a := analyzer.Finding{RuleID: "RACE001", File: "main.go", Line: 10}
	b := analyzer.Finding{RuleID: "RACE002", File: "main.go", Line: 20}
	merged := mergeFindings([]analyzer.Finding{a}, []analyzer.Finding{b})
	if len(merged) != 2 {
		t.Errorf("expected 2 findings, got %d", len(merged))
	}
}

func TestMergeFindings_Empty(t *testing.T) {
	merged := mergeFindings(nil, nil)
	if len(merged) != 0 {
		t.Errorf("expected 0 findings, got %d", len(merged))
	}
}

// ---- collectGoFiles ---------------------------------------------------------

func TestCollectGoFiles_SkipsVendor(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "main.go"), "package main")
	writeFile(t, filepath.Join(dir, "vendor", "lib.go"), "package lib")

	files, err := collectGoFiles(dir)
	if err != nil {
		t.Fatalf("collectGoFiles: %v", err)
	}
	for _, f := range files {
		if strings.Contains(f, "vendor") {
			t.Errorf("vendor file should be excluded: %s", f)
		}
	}
}

func TestCollectGoFiles_SkipsHiddenDirs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "main.go"), "package main")
	writeFile(t, filepath.Join(dir, ".hidden", "file.go"), "package hidden")

	files, err := collectGoFiles(dir)
	if err != nil {
		t.Fatalf("collectGoFiles: %v", err)
	}
	for _, f := range files {
		if strings.Contains(f, ".hidden") {
			t.Errorf("hidden dir file should be excluded: %s", f)
		}
	}
}

// ---- table-driven combination test ------------------------------------------

func TestMultipleRulesInOneFile(t *testing.T) {
	src := `package main

import (
	"fmt"
	"sync"
)

func Combined() {
	m := make(map[string]int)
	var counter int
	values := []int{1, 2, 3}
	var wg sync.WaitGroup
	for _, v := range values {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println(v)     // RACE001: captures v
			m["k"] = 1         // RACE002: map write without mutex
			counter++          // RACE003: non-atomic increment
		}()
	}
	wg.Wait()
}
`
	tests := []struct {
		rule    string
		wantMin int
	}{
		{"RACE001", 1},
		{"RACE002", 1},
		{"RACE003", 1},
	}

	findings := runOnSrc(t, src)
	for _, tc := range tests {
		t.Run(tc.rule, func(t *testing.T) {
			got := findingsWithRule(findings, tc.rule)
			if len(got) < tc.wantMin {
				t.Errorf("expected at least %d %s findings, got %d; all findings: %+v",
					tc.wantMin, tc.rule, len(got), findings)
			}
		})
	}
}
