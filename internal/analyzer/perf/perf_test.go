// Package perf_test contains table-driven tests for the performance analyzer.
// Each rule has at least one positive (triggers the rule) and one negative
// (does not trigger the rule) test case. Inline source code is parsed with
// go/parser so no external files are required.
package perf

import (
	"go/parser"
	"go/token"
	"testing"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// parseSource parses src as a Go source file and returns the AST.
// It calls t.Fatal if parsing fails.
func parseSource(t *testing.T, src string) (*token.FileSet, interface{ Pos() token.Pos }) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, 0)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return fset, f
}

// countFindings runs analyzeFile on src and returns the count of findings
// with the given ruleID.
func countFindings(t *testing.T, src, ruleID string) int {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, 0)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	findings := analyzeFile(fset, f, "test.go")
	count := 0
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			count++
		}
	}
	return count
}

// ─── PERF001 ─────────────────────────────────────────────────────────────────

func TestPERF001_StringConcatInLoop(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantMin int // minimum number of PERF001 findings expected
	}{
		{
			name: "positive: += inside range loop",
			src: `package p
import "fmt"
func f(items []string) string {
	result := ""
	for _, item := range items {
		result += item
	}
	fmt.Println(result)
	return result
}`,
			wantMin: 1,
		},
		{
			name: "positive: = x + y inside for loop",
			src: `package p
func f(items []string) string {
	result := ""
	for i := 0; i < len(items); i++ {
		result = result + items[i]
	}
	return result
}`,
			wantMin: 1,
		},
		{
			name: "positive: += inside range loop (same as sample/main.go PERF001)",
			src: `package p
func StringConcatInLoop(items []string) string {
	result := ""
	for _, item := range items {
		result = result + item
	}
	return result
}`,
			wantMin: 1,
		},
		{
			name: "negative: string concat outside loop",
			src: `package p
func f(a, b string) string {
	return a + b
}`,
			wantMin: 0,
		},
		{
			name: "positive: int addition inside loop (conservative AST heuristic)",
			src: `package p
func f(n int) int {
	sum := 0
	for i := 0; i < n; i++ {
		sum = sum + i
	}
	return sum
}`,
			// The pure-AST check cannot distinguish int + int from string + string;
			// it conservatively flags all BinaryExpr ADD inside loops. This is a
			// known trade-off documented in the rule description.
			wantMin: 1,
		},
		{
			name: "negative: strings.Builder (no + concatenation)",
			src: `package p
import "strings"
func f(items []string) string {
	var sb strings.Builder
	for _, item := range items {
		sb.WriteString(item)
	}
	return sb.String()
}`,
			wantMin: 0,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			count := countFindings(t, tc.src, "PERF001")
			if tc.wantMin > 0 && count < tc.wantMin {
				t.Errorf("PERF001: expected at least %d finding(s), got %d", tc.wantMin, count)
			}
			if tc.wantMin == 0 && count > 0 {
				t.Errorf("PERF001: expected 0 findings, got %d", count)
			}
		})
	}
}

// ─── PERF002 ─────────────────────────────────────────────────────────────────

func TestPERF002_RegexpInsideFunction(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantMin int
	}{
		{
			name: "positive: regexp.MustCompile inside function (matches sample/main.go PERF002)",
			src: `package p
import "regexp"
func RegexpInsideFunction(s string) bool {
	re := regexp.MustCompile(` + "`^\\d+$`" + `)
	return re.MatchString(s)
}`,
			wantMin: 1,
		},
		{
			name: "positive: regexp.Compile inside function",
			src: `package p
import "regexp"
func f(s string) (bool, error) {
	re, err := regexp.Compile(` + "`^[a-z]+$`" + `)
	if err != nil {
		return false, err
	}
	return re.MatchString(s), nil
}`,
			wantMin: 1,
		},
		{
			name: "negative: regexp.MustCompile at package level",
			src: `package p
import "regexp"
var re = regexp.MustCompile(` + "`^\\d+$`" + `)
func f(s string) bool { return re.MatchString(s) }`,
			wantMin: 0,
		},
		{
			name: "negative: no regexp usage",
			src: `package p
import "strings"
func f(s string) bool { return strings.HasPrefix(s, "foo") }`,
			wantMin: 0,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			count := countFindings(t, tc.src, "PERF002")
			if tc.wantMin > 0 && count < tc.wantMin {
				t.Errorf("PERF002: expected at least %d finding(s), got %d", tc.wantMin, count)
			}
			if tc.wantMin == 0 && count > 0 {
				t.Errorf("PERF002: expected 0 findings, got %d", count)
			}
		})
	}
}

// ─── PERF003 ─────────────────────────────────────────────────────────────────

func TestPERF003_DeferInLoop(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantMin int
	}{
		{
			name: "positive: defer inside range loop",
			src: `package p
import "os"
func f(files []string) {
	for _, name := range files {
		f, _ := os.Open(name)
		defer f.Close()
	}
}`,
			wantMin: 1,
		},
		{
			name: "positive: defer inside for loop",
			src: `package p
import "os"
func f(n int) {
	for i := 0; i < n; i++ {
		f, _ := os.CreateTemp("", "tmp")
		defer f.Close()
	}
}`,
			wantMin: 1,
		},
		{
			name: "negative: defer outside loop",
			src: `package p
import "os"
func f() {
	file, _ := os.Open("test")
	defer file.Close()
}`,
			wantMin: 0,
		},
		{
			name: "negative: no defer at all",
			src: `package p
func f(items []int) int {
	sum := 0
	for _, v := range items {
		sum += v
	}
	return sum
}`,
			wantMin: 0,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			count := countFindings(t, tc.src, "PERF003")
			if tc.wantMin > 0 && count < tc.wantMin {
				t.Errorf("PERF003: expected at least %d finding(s), got %d", tc.wantMin, count)
			}
			if tc.wantMin == 0 && count > 0 {
				t.Errorf("PERF003: expected 0 findings, got %d", count)
			}
		})
	}
}

// ─── PERF004 ─────────────────────────────────────────────────────────────────

func TestPERF004_AppendWithoutPrealloc(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantMin int
	}{
		{
			name: "positive: append inside range loop, no make with cap",
			src: `package p
func f(items []int) []int {
	var out []int
	for _, v := range items {
		out = append(out, v*2)
	}
	return out
}`,
			wantMin: 1,
		},
		{
			name: "positive: append inside for loop, no make with cap",
			src: `package p
func f(n int) []int {
	var out []int
	for i := 0; i < n; i++ {
		out = append(out, i)
	}
	return out
}`,
			wantMin: 1,
		},
		{
			name: "negative: make with capacity before loop",
			src: `package p
func f(items []int) []int {
	out := make([]int, 0, len(items))
	for _, v := range items {
		out = append(out, v*2)
	}
	return out
}`,
			wantMin: 0,
		},
		{
			name: "negative: no append in loop",
			src: `package p
func f(items []int) int {
	sum := 0
	for _, v := range items {
		sum += v
	}
	return sum
}`,
			wantMin: 0,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			count := countFindings(t, tc.src, "PERF004")
			if tc.wantMin > 0 && count < tc.wantMin {
				t.Errorf("PERF004: expected at least %d finding(s), got %d", tc.wantMin, count)
			}
			if tc.wantMin == 0 && count > 0 {
				t.Errorf("PERF004: expected 0 findings, got %d", count)
			}
		})
	}
}

// ─── PERF005 ─────────────────────────────────────────────────────────────────

func TestPERF005_LargeStructByValue(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantMin int
	}{
		{
			name: "positive: named struct with 6 fields passed by value",
			src: `package p
type BigStruct struct {
	A, B, C, D, E, F int
}
func process(s BigStruct) {}`,
			wantMin: 1,
		},
		{
			name: "positive: inline anonymous struct with 6 fields passed by value",
			src: `package p
func process(s struct{ A, B, C, D, E, F int }) {}`,
			wantMin: 1,
		},
		{
			name: "negative: struct with 5 fields (exactly at limit)",
			src: `package p
type SmallStruct struct {
	A, B, C, D, E int
}
func process(s SmallStruct) {}`,
			wantMin: 0,
		},
		{
			name: "negative: large struct passed by pointer",
			src: `package p
type BigStruct struct {
	A, B, C, D, E, F int
}
func process(s *BigStruct) {}`,
			wantMin: 0,
		},
		{
			name: "negative: no struct parameters",
			src: `package p
func add(a, b int) int { return a + b }`,
			wantMin: 0,
		},
		{
			name: "positive: 7-field struct by value",
			src: `package p
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
	Timeout  int
}
func connect(cfg Config) {}`,
			wantMin: 1,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			count := countFindings(t, tc.src, "PERF005")
			if tc.wantMin > 0 && count < tc.wantMin {
				t.Errorf("PERF005: expected at least %d finding(s), got %d", tc.wantMin, count)
			}
			if tc.wantMin == 0 && count > 0 {
				t.Errorf("PERF005: expected 0 findings, got %d", count)
			}
		})
	}
}

// ─── PERF006 ─────────────────────────────────────────────────────────────────

func TestPERF006_FmtSprintfSingleVerb(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantMin int
	}{
		{
			name: "positive: fmt.Sprintf with %v and single arg",
			src: `package p
import "fmt"
func f(n int) string { return fmt.Sprintf("%v", n) }`,
			wantMin: 1,
		},
		{
			name: "positive: fmt.Sprintf with %d and single arg",
			src: `package p
import "fmt"
func f(n int) string { return fmt.Sprintf("%d", n) }`,
			wantMin: 1,
		},
		{
			name: "positive: fmt.Sprintf with %s and single arg",
			src: `package p
import "fmt"
func f(s string) string { return fmt.Sprintf("%s", s) }`,
			wantMin: 1,
		},
		{
			name: "negative: fmt.Sprintf with composite format string",
			src: `package p
import "fmt"
func f(name string, age int) string { return fmt.Sprintf("name=%s age=%d", name, age) }`,
			wantMin: 0,
		},
		{
			name: "negative: fmt.Sprintf with multiple args and single verb (not caught)",
			src: `package p
import "fmt"
func f(a, b int) string { return fmt.Sprintf("%d %d", a, b) }`,
			wantMin: 0,
		},
		{
			name: "negative: fmt.Sprint (not Sprintf)",
			src: `package p
import "fmt"
func f(n int) string { return fmt.Sprint(n) }`,
			wantMin: 0,
		},
		{
			name: "positive: fmt.Sprintf with %f and single arg",
			src: `package p
import "fmt"
func f(x float64) string { return fmt.Sprintf("%f", x) }`,
			wantMin: 1,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			count := countFindings(t, tc.src, "PERF006")
			if tc.wantMin > 0 && count < tc.wantMin {
				t.Errorf("PERF006: expected at least %d finding(s), got %d", tc.wantMin, count)
			}
			if tc.wantMin == 0 && count > 0 {
				t.Errorf("PERF006: expected 0 findings, got %d", count)
			}
		})
	}
}

// ─── Integration: Run() against testdata/sample ───────────────────────────────

// TestRun_AgainstSampleDir verifies that the full Run() method detects the
// violations planted in testdata/sample/main.go.
func TestRun_AgainstSampleDir(t *testing.T) {
	a := New()
	// The testdata/sample directory is three levels up from internal/analyzer/perf.
	// go test sets the working directory to the package directory, so we use
	// a relative path: internal/analyzer/perf -> ../../../ = module root.
	dir := "../../../testdata/sample"

	findings, err := a.Run(dir)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}

	ruleHits := make(map[string]int)
	for _, f := range findings {
		ruleHits[f.RuleID]++
	}

	expected := []string{"PERF001", "PERF002"}
	for _, ruleID := range expected {
		if ruleHits[ruleID] == 0 {
			t.Errorf("Run(): expected at least one %s finding in testdata/sample, got none (all findings: %v)", ruleID, ruleHits)
		}
	}
}

// ─── Metadata ────────────────────────────────────────────────────────────────

func TestAnalyzerMetadata(t *testing.T) {
	a := New()
	if a.Name() != "perf" {
		t.Errorf("Name() = %q, want %q", a.Name(), "perf")
	}
	if a.Description() == "" {
		t.Error("Description() returned empty string")
	}
}

// TestRun_NonExistentDir verifies that Run() returns an error for a
// directory that does not exist.
func TestRun_NonExistentDir(t *testing.T) {
	a := New()
	_, err := a.Run("/non/existent/path/that/cannot/exist")
	if err == nil {
		t.Error("Run() on non-existent directory: expected error, got nil")
	}
}

// TestRun_EmptyDir verifies that Run() on an empty (or Go-file-free) directory
// returns an empty finding list without error.
func TestRun_EmptyDir(t *testing.T) {
	a := New()
	// Use the os temp dir — it contains no .go files.
	findings, err := a.Run(t.TempDir())
	if err != nil {
		t.Fatalf("Run() on empty dir: unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("Run() on empty dir: expected 0 findings, got %d", len(findings))
	}
}

// ─── Finding field completeness ───────────────────────────────────────────────

// TestFindingFields checks that every finding returned for a known-triggering
// source has all required fields populated.
func TestFindingFields(t *testing.T) {
	sources := []struct {
		ruleID string
		src    string
	}{
		{
			ruleID: "PERF001",
			src: `package p
func f(items []string) string {
	result := ""
	for _, item := range items { result += item }
	return result
}`,
		},
		{
			ruleID: "PERF002",
			src: `package p
import "regexp"
func f(s string) bool {
	re := regexp.MustCompile(` + "`x`" + `)
	return re.MatchString(s)
}`,
		},
		{
			ruleID: "PERF003",
			src: `package p
import "os"
func f(files []string) {
	for _, name := range files {
		f, _ := os.Open(name)
		defer f.Close()
	}
}`,
		},
		{
			ruleID: "PERF004",
			src: `package p
func f(items []int) []int {
	var out []int
	for _, v := range items { out = append(out, v) }
	return out
}`,
		},
		{
			ruleID: "PERF005",
			src: `package p
type Big struct{ A, B, C, D, E, F int }
func process(s Big) {}`,
		},
		{
			ruleID: "PERF006",
			src: `package p
import "fmt"
func f(n int) string { return fmt.Sprintf("%d", n) }`,
		},
	}

	for _, tc := range sources {
		tc := tc
		t.Run(tc.ruleID, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "test.go", tc.src, 0)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := analyzeFile(fset, f, "test.go")
			var matched []string
			for _, finding := range findings {
				if finding.RuleID != tc.ruleID {
					continue
				}
				if finding.Severity == "" {
					t.Errorf("%s: Severity is empty", tc.ruleID)
				}
				if finding.Message == "" {
					t.Errorf("%s: Message is empty", tc.ruleID)
				}
				if finding.File == "" {
					t.Errorf("%s: File is empty", tc.ruleID)
				}
				if finding.Line == 0 {
					t.Errorf("%s: Line is 0", tc.ruleID)
				}
				if finding.Suggestion == "" {
					t.Errorf("%s: Suggestion is empty", tc.ruleID)
				}
				matched = append(matched, finding.RuleID)
			}
			if len(matched) == 0 {
				t.Errorf("%s: expected at least one finding, got none", tc.ruleID)
			}
		})
	}
}
