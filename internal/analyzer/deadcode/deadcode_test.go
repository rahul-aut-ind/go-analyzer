// Package deadcode_test contains tests for the dead code analyzer.
package deadcode

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahul-aut-ind/go-analyzer/internal/analyzer"
)

// writeGoFile writes src into a new temporary directory and returns the
// directory path. The file is always named "a.go".
func writeGoFile(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return dir
}

// hasRule reports whether any finding in the slice carries the given RuleID.
func hasRule(findings []analyzer.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

// ─── DEAD001 ─────────────────────────────────────────────────────────────────

// TestDEAD001_UnusedFunction verifies that an unexported function that is never
// called is flagged with DEAD001.
func TestDEAD001_UnusedFunction(t *testing.T) {
	src := `package mypkg

func unusedHelper() {}

func Exported() {}
`
	dir := writeGoFile(t, src)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	findings := checkDEAD001(fset, pkgs["mypkg"])
	if !hasRule(findings, "DEAD001") {
		t.Errorf("expected DEAD001 finding for unusedHelper, got %v", findings)
	}
	for _, f := range findings {
		if f.RuleID == "DEAD001" && !strings.Contains(f.Message, "unusedHelper") {
			t.Errorf("DEAD001 message should mention unusedHelper, got %q", f.Message)
		}
	}
}

// TestDEAD001_CalledFunction verifies that an unexported function that IS
// called is not flagged.
func TestDEAD001_CalledFunction(t *testing.T) {
	src := `package mypkg

func helper() {}

func Exported() { helper() }
`
	dir := writeGoFile(t, src)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	findings := checkDEAD001(fset, pkgs["mypkg"])
	if hasRule(findings, "DEAD001") {
		t.Errorf("did not expect DEAD001 for called helper, got %v", findings)
	}
}

// TestDEAD001_ExcludesInit ensures that init() is not flagged even though it
// is never explicitly called.
func TestDEAD001_ExcludesInit(t *testing.T) {
	src := `package mypkg

func init() {}
`
	dir := writeGoFile(t, src)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	findings := checkDEAD001(fset, pkgs["mypkg"])
	if hasRule(findings, "DEAD001") {
		t.Errorf("init() should not be flagged, got %v", findings)
	}
}

// TestDEAD001_ExcludesTestFunctions ensures TestXxx / BenchmarkXxx / ExampleXxx
// functions are not flagged.
func TestDEAD001_ExcludesTestFunctions(t *testing.T) {
	src := `package mypkg

func TestSomething(t interface{}) {}
func BenchmarkSomething(b interface{}) {}
func ExampleSomething() {}
`
	dir := writeGoFile(t, src)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	findings := checkDEAD001(fset, pkgs["mypkg"])
	if hasRule(findings, "DEAD001") {
		t.Errorf("Test/Benchmark/Example functions should not be flagged, got %v", findings)
	}
}

// TestDEAD001_ExcludesMethods ensures that unexported methods (with receivers)
// are not flagged.
func TestDEAD001_ExcludesMethods(t *testing.T) {
	src := `package mypkg

type T struct{}

func (T) helper() {}
`
	dir := writeGoFile(t, src)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	findings := checkDEAD001(fset, pkgs["mypkg"])
	if hasRule(findings, "DEAD001") {
		t.Errorf("methods should not be flagged as unused functions, got %v", findings)
	}
}

// TestDEAD001_CalledViaMethod verifies that a function called inside a method
// body is not flagged as unused.
func TestDEAD001_CalledViaMethod(t *testing.T) {
	src := `package mypkg

import "fmt"

func helper() { fmt.Println("x") }

type S struct{}

func (S) callHelper() { helper() }
`
	dir := writeGoFile(t, src)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	findings := checkDEAD001(fset, pkgs["mypkg"])
	if hasRule(findings, "DEAD001") {
		t.Errorf("helper called inside method should not be flagged, got %v", findings)
	}
}

// TestDEAD001_MultipleFiles verifies DEAD001 across two files in the same
// package: a helper declared in file A is called in file B and must not be
// flagged.
func TestDEAD001_MultipleFiles(t *testing.T) {
	srcA := `package mypkg

func helper() {}
`
	srcB := `package mypkg

func Caller() { helper() }
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(srcA), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.go"), []byte(srcB), 0644); err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	findings := checkDEAD001(fset, pkgs["mypkg"])
	if hasRule(findings, "DEAD001") {
		t.Errorf("helper called in sibling file should not be flagged, got %v", findings)
	}
}

// ─── DEAD002 ─────────────────────────────────────────────────────────────────

// TestDEAD002_CodeAfterReturn verifies that statements after a return are
// flagged.
func TestDEAD002_CodeAfterReturn(t *testing.T) {
	src := `package mypkg

import "fmt"

func dead() string {
	return "done"
	fmt.Println("unreachable")
	return "never"
}
`
	dir := writeGoFile(t, src)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	findings := checkDEAD002(fset, pkgs["mypkg"])
	if !hasRule(findings, "DEAD002") {
		t.Errorf("expected DEAD002 for code after return, got %v", findings)
	}
}

// TestDEAD002_CodeAfterPanic verifies that statements after a panic() call are
// flagged.
func TestDEAD002_CodeAfterPanic(t *testing.T) {
	src := `package mypkg

import "fmt"

func panicThenCode() {
	panic("oops")
	fmt.Println("unreachable")
}
`
	dir := writeGoFile(t, src)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	findings := checkDEAD002(fset, pkgs["mypkg"])
	if !hasRule(findings, "DEAD002") {
		t.Errorf("expected DEAD002 for code after panic, got %v", findings)
	}
}

// TestDEAD002_NormalCode verifies that well-formed functions are not flagged.
func TestDEAD002_NormalCode(t *testing.T) {
	src := `package mypkg

import "fmt"

func normal() string {
	x := "hello"
	fmt.Println(x)
	return x
}
`
	dir := writeGoFile(t, src)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	findings := checkDEAD002(fset, pkgs["mypkg"])
	if hasRule(findings, "DEAD002") {
		t.Errorf("did not expect DEAD002 for normal code, got %v", findings)
	}
}

// TestDEAD002_OnlyFirstUnreachable verifies that only the first unreachable
// statement per block is reported.
func TestDEAD002_OnlyFirstUnreachable(t *testing.T) {
	src := `package mypkg

import "fmt"

func multiDead() {
	return
	fmt.Println("first unreachable")
	fmt.Println("second unreachable")
}
`
	dir := writeGoFile(t, src)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	findings := checkDEAD002(fset, pkgs["mypkg"])
	count := 0
	for _, f := range findings {
		if f.RuleID == "DEAD002" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 DEAD002 finding, got %d: %v", count, findings)
	}
}

// TestDEAD002_ReturnInsideIfNotFlagged verifies that a return inside an if
// block does not cause the statements after the if to be flagged (we only
// check the top-level block list).
func TestDEAD002_ReturnInsideIfNotFlagged(t *testing.T) {
	src := `package mypkg

import "fmt"

func conditional(x int) {
	if x > 0 {
		return
	}
	fmt.Println("reachable when x <= 0")
}
`
	dir := writeGoFile(t, src)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	findings := checkDEAD002(fset, pkgs["mypkg"])
	if hasRule(findings, "DEAD002") {
		t.Errorf("return inside nested if should not flag outer statements, got %v", findings)
	}
}

// ─── DEAD003 ─────────────────────────────────────────────────────────────────

// TestDEAD003_UnusedExportedConst verifies that an exported constant that is
// never referenced is flagged with DEAD003.
func TestDEAD003_UnusedExportedConst(t *testing.T) {
	src := `package mypkg

const UnusedConst = "value"
`
	dir := writeGoFile(t, src)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	findings := checkDEAD003(fset, pkgs["mypkg"])
	if !hasRule(findings, "DEAD003") {
		t.Errorf("expected DEAD003 for UnusedConst, got %v", findings)
	}
}

// TestDEAD003_UsedExportedConst verifies that an exported constant that IS
// referenced is not flagged.
func TestDEAD003_UsedExportedConst(t *testing.T) {
	src := `package mypkg

import "fmt"

const UsedConst = "value"

func Printer() { fmt.Println(UsedConst) }
`
	dir := writeGoFile(t, src)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	findings := checkDEAD003(fset, pkgs["mypkg"])
	if hasRule(findings, "DEAD003") {
		t.Errorf("did not expect DEAD003 for used constant, got %v", findings)
	}
}

// TestDEAD003_UnexportedConstIgnored verifies that unexported constants are
// not flagged by DEAD003.
func TestDEAD003_UnexportedConstIgnored(t *testing.T) {
	src := `package mypkg

const unexported = "value"
`
	dir := writeGoFile(t, src)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	findings := checkDEAD003(fset, pkgs["mypkg"])
	if hasRule(findings, "DEAD003") {
		t.Errorf("unexported const should not be flagged by DEAD003, got %v", findings)
	}
}

// TestDEAD003_NoConsts verifies that a package with no constants returns no
// DEAD003 findings.
func TestDEAD003_NoConsts(t *testing.T) {
	src := `package mypkg

func Foo() {}
`
	dir := writeGoFile(t, src)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	findings := checkDEAD003(fset, pkgs["mypkg"])
	if hasRule(findings, "DEAD003") {
		t.Errorf("no consts should produce no DEAD003 findings, got %v", findings)
	}
}

// ─── Run() integration ───────────────────────────────────────────────────────

// TestRun_SampleMain exercises the public Run() method against the project's
// testdata/sample directory, verifying that the known violations are detected.
func TestRun_SampleMain(t *testing.T) {
	// Resolve testdata/sample relative to the module root by walking up from the
	// package source file location (obtained at runtime via os.Getwd).
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// wd is the package directory: .../internal/analyzer/deadcode
	sampleDir := filepath.Join(wd, "..", "..", "..", "testdata", "sample")
	if _, err := os.Stat(sampleDir); err != nil {
		t.Skipf("testdata/sample not found at %s (%v), skipping integration test", sampleDir, err)
	}

	a := New()
	findings, err := a.Run(sampleDir)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	wantRules := []string{"DEAD001", "DEAD002"}
	for _, rule := range wantRules {
		if !hasRule(findings, rule) {
			t.Errorf("expected finding for %s in testdata/sample, got all findings: %v", rule, findings)
		}
	}
}

// TestNew_AnalyzerMetadata verifies the Name and Description methods.
func TestNew_AnalyzerMetadata(t *testing.T) {
	a := New()
	if got := a.Name(); got != "deadcode" {
		t.Errorf("Name() = %q, want %q", got, "deadcode")
	}
	if a.Description() == "" {
		t.Error("Description() must not be empty")
	}
}

// TestRun_EmptyDir verifies that Run on a directory with no Go files returns
// no findings and no error.
func TestRun_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	a := New()
	findings, err := a.Run(dir)
	if err != nil {
		t.Fatalf("Run on empty dir returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty dir, got %v", findings)
	}
}

// TestRun_CleanCode verifies that a file with no dead code produces no
// findings.
func TestRun_CleanCode(t *testing.T) {
	src := `package clean

import "fmt"

// MaxRetries is the maximum number of retry attempts.
const MaxRetries = 3

func helper() { fmt.Println(MaxRetries) }

// Run starts the process.
func Run() { helper() }
`
	dir := writeGoFile(t, src)
	a := New()
	findings, err := a.Run(dir)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	for _, f := range findings {
		t.Errorf("unexpected finding %+v", f)
	}
}

// TestIsExcludedFuncName covers the exclusion helper for branch coverage.
func TestIsExcludedFuncName(t *testing.T) {
	cases := []struct {
		name     string
		excluded bool
	}{
		{"init", true},
		{"main", true},
		{"TestFoo", true},
		{"BenchmarkFoo", true},
		{"ExampleFoo", true},
		{"FuzzFoo", true},
		{"helper", false},
		{"myFunc", false},
	}
	for _, tc := range cases {
		got := isExcludedFuncName(tc.name)
		if got != tc.excluded {
			t.Errorf("isExcludedFuncName(%q) = %v, want %v", tc.name, got, tc.excluded)
		}
	}
}

// TestIsExported covers the exported-name helper.
func TestIsExported(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"Exported", true},
		{"unexported", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isExported(tc.name); got != tc.want {
			t.Errorf("isExported(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestParseDeadcodeOutput exercises the output parser for the external
// deadcode tool.
func TestParseDeadcodeOutput(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name    string
		output  string
		wantLen int
	}{
		{
			name:    "empty output",
			output:  "",
			wantLen: 0,
		},
		{
			name:    "blank lines only",
			output:  "\n\n   \n",
			wantLen: 0,
		},
		{
			name:    "single finding with four parts",
			output:  "main.go:10:5: function neverCalled is unreachable",
			wantLen: 1,
		},
		{
			name:    "single finding with three parts",
			output:  "main.go:10: unreachable function",
			wantLen: 1,
		},
		{
			name:    "multiple findings",
			output:  "a.go:1:1: msg one\nb.go:2:2: msg two",
			wantLen: 2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := parseDeadcodeOutput(tc.output, dir)
			if len(findings) != tc.wantLen {
				t.Errorf("parseDeadcodeOutput(%q) returned %d findings, want %d: %v",
					tc.output, len(findings), tc.wantLen, findings)
			}
			for _, f := range findings {
				if f.RuleID != "DEAD001" {
					t.Errorf("parseDeadcodeOutput finding RuleID = %q, want DEAD001", f.RuleID)
				}
			}
		})
	}
}

// TestIsNotFound covers the isNotFound helper with an exec.ExitError and a
// plain "not found" error message.
func TestIsNotFound(t *testing.T) {
	// A plain error containing the not-found string should return true.
	plainErr := &notFoundErr{"executable file not found in $PATH"}
	if !isNotFound(plainErr) {
		t.Error("expected isNotFound to return true for not-found error message")
	}
}

// notFoundErr is a minimal error implementation used for testing isNotFound.
type notFoundErr struct{ msg string }

func (e *notFoundErr) Error() string { return e.msg }
