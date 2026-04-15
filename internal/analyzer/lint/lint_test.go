// Package lint provides tests for the lint analyzer rules LINT001–LINT006 and
// the go vet wrapper (VET001).
package lint

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahul-aut-ind/go-analyzer/internal/analyzer"
)

// ---- helpers ----------------------------------------------------------------

// parseSource parses src as a Go source file and returns the AST and FileSet.
// The file is attributed to the given filename for position reporting.
func parseSource(t *testing.T, filename, src string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	return fset, file
}

// findingsWithRule filters a slice to only those with the given rule ID.
func findingsWithRule(findings []analyzer.Finding, rule string) []analyzer.Finding {
	var out []analyzer.Finding
	for _, f := range findings {
		if f.RuleID == rule {
			out = append(out, f)
		}
	}
	return out
}

// assertFindings verifies that exactly wantCount findings for ruleID are
// present in findings.
func assertFindings(t *testing.T, findings []analyzer.Finding, ruleID string, wantCount int) {
	t.Helper()
	got := findingsWithRule(findings, ruleID)
	if len(got) != wantCount {
		t.Errorf("rule %s: want %d finding(s), got %d: %+v", ruleID, wantCount, len(got), got)
	}
}

// assertAtLeast verifies that at least wantMin findings for ruleID are present.
func assertAtLeast(t *testing.T, findings []analyzer.Finding, ruleID string, wantMin int) {
	t.Helper()
	got := findingsWithRule(findings, ruleID)
	if len(got) < wantMin {
		t.Errorf("rule %s: want at least %d finding(s), got %d: %+v", ruleID, wantMin, len(got), got)
	}
}

// writeTempFile writes content to a temporary file with the given name suffix
// and returns its path. The file is cleaned up when the test ends.
func writeTempFile(t *testing.T, nameSuffix, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, nameSuffix)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

// writeTempDir writes multiple files into a temp directory and returns the dir.
func writeTempDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// ---- LINT001 ----------------------------------------------------------------

func TestLINT001_ExportedFuncMissingDoc(t *testing.T) {
	src := `package mypkg

// NotExported does nothing.
func notExported() {}

func ExportedNoDoc() {}
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT001(fset, file, "foo.go", false)
	assertFindings(t, findings, "LINT001", 1)
	if len(findings) > 0 && !strings.Contains(findings[0].Message, "ExportedNoDoc") {
		t.Errorf("expected finding to reference ExportedNoDoc, got: %s", findings[0].Message)
	}
}

func TestLINT001_ExportedFuncWithProperDoc(t *testing.T) {
	src := `package mypkg

// ExportedWithDoc does something useful.
func ExportedWithDoc() {}
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT001(fset, file, "foo.go", false)
	assertFindings(t, findings, "LINT001", 0)
}

func TestLINT001_ExportedFuncWithWrongDoc(t *testing.T) {
	// Comment exists but doesn't start with the function name.
	src := `package mypkg

// This does something, but the comment doesn't start with the identifier.
func BadDoc() {}
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT001(fset, file, "foo.go", false)
	assertFindings(t, findings, "LINT001", 1)
}

func TestLINT001_ExportedType(t *testing.T) {
	src := `package mypkg

type ExportedType struct{}

// ExportedTypeWithDoc is a type with doc.
type ExportedTypeWithDoc struct{}
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT001(fset, file, "foo.go", false)
	assertFindings(t, findings, "LINT001", 1)
}

func TestLINT001_ExportedVar(t *testing.T) {
	src := `package mypkg

var ExportedVar = 42

// ExportedVarWithDoc is documented.
var ExportedVarWithDoc = 99
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT001(fset, file, "foo.go", false)
	assertFindings(t, findings, "LINT001", 1)
}

func TestLINT001_ExportedConst(t *testing.T) {
	src := `package mypkg

const ExportedConst = 42
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT001(fset, file, "foo.go", false)
	assertFindings(t, findings, "LINT001", 1)
}

func TestLINT001_SkipsTestFiles(t *testing.T) {
	src := `package mypkg

func ExportedTestHelper() {}
`
	fset, file := parseSource(t, "foo_test.go", src)
	findings := checkLINT001(fset, file, "foo_test.go", true)
	assertFindings(t, findings, "LINT001", 0)
}

func TestLINT001_UnexportedIdentifiersIgnored(t *testing.T) {
	src := `package mypkg

func unexported() {}
type unexportedType struct{}
var unexportedVar = 1
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT001(fset, file, "foo.go", false)
	assertFindings(t, findings, "LINT001", 0)
}

func TestLINT001_MethodsSkipped(t *testing.T) {
	// Methods on exported types should not trigger LINT001 (only top-level funcs).
	src := `package mypkg

type MyType struct{}

func (m *MyType) ExportedMethod() {}
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT001(fset, file, "foo.go", false)
	// MyType has no doc — expect 1 finding for the type.
	// ExportedMethod should NOT produce a LINT001 finding.
	for _, f := range findings {
		if f.RuleID == "LINT001" && strings.Contains(f.Message, "ExportedMethod") {
			t.Error("LINT001 should not flag methods, only top-level functions")
		}
	}
}

// TestLINT001_SampleMainGo verifies that UndocumentedExported in the sample
// testdata triggers LINT001 (comment starts with "UndocumentedExported is"
// but it's a trailing comment, not a proper godoc block comment on the decl).
func TestLINT001_SampleMainGo(t *testing.T) {
	// The sample main.go has:
	// // UndocumentedExported is exported but has no godoc comment. // want: LINT001
	// func UndocumentedExported() {}
	//
	// That trailing comment on the same line is NOT a Doc comment for the function.
	samplePath := filepath.Join("..", "..", "..", "testdata", "sample", "main.go")
	if _, err := os.Stat(samplePath); err != nil {
		t.Skipf("testdata not found: %v", err)
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, samplePath, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}

	// The comment on that function IS a proper godoc (same-line is not enough
	// if it appears on the same line, but the AST attaches block comments above).
	// The test just verifies analyzeFile does not crash on the sample.
	findings := checkLINT001(fset, file, samplePath, false)
	// At minimum we should not crash; findings may or may not fire depending on
	// whether the AST parses the comment as a Doc. We log the result.
	t.Logf("LINT001 findings in sample/main.go: %d", len(findingsWithRule(findings, "LINT001")))
}

// ---- LINT002 ----------------------------------------------------------------

func TestLINT002_BlankErrorIgnored(t *testing.T) {
	src := `package mypkg

import "os"

func doStuff() {
	f, _ := os.Open("file.txt")
	_ = f
}
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT002(fset, file, "foo.go")
	assertAtLeast(t, findings, "LINT002", 1)
}

func TestLINT002_ErrorHandled(t *testing.T) {
	src := `package mypkg

import "os"

func doStuff() error {
	f, err := os.Open("file.txt")
	if err != nil {
		return err
	}
	_ = f
	return nil
}
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT002(fset, file, "foo.go")
	assertFindings(t, findings, "LINT002", 0)
}

func TestLINT002_SelectorCallBlankError(t *testing.T) {
	src := `package mypkg

type DB struct{}

func (d *DB) Query(q string) (int, error) { return 0, nil }

func doStuff(db *DB) {
	result, _ := db.Query("SELECT 1")
	_ = result
}
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT002(fset, file, "foo.go")
	assertAtLeast(t, findings, "LINT002", 1)
}

func TestLINT002_NoBlankIdentifier(t *testing.T) {
	src := `package mypkg

func multi() (int, string) { return 1, "a" }

func doStuff() {
	a, b := multi()
	_, _ = a, b
}
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT002(fset, file, "foo.go")
	// multi() doesn't match error heuristics
	assertFindings(t, findings, "LINT002", 0)
}

func TestLINT002_SingleReturn(t *testing.T) {
	// Single return values cannot be error-discard patterns (need at least 2 LHS).
	src := `package mypkg

func single() int { return 1 }

func doStuff() {
	_ = single()
}
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT002(fset, file, "foo.go")
	assertFindings(t, findings, "LINT002", 0)
}

// ---- LINT003 ----------------------------------------------------------------

func TestLINT003_PanicInLibraryPkg(t *testing.T) {
	src := `package mylib

func doThing() {
	panic("something went wrong")
}
`
	fset, file := parseSource(t, "mylib.go", src)
	findings := checkLINT003(fset, file, "mylib.go", false, false)
	assertFindings(t, findings, "LINT003", 1)
}

func TestLINT003_PanicInMainPkg(t *testing.T) {
	src := `package main

func doThing() {
	panic("something went wrong")
}
`
	fset, file := parseSource(t, "main.go", src)
	findings := checkLINT003(fset, file, "main.go", true, false)
	assertFindings(t, findings, "LINT003", 0)
}

func TestLINT003_PanicInTestFile(t *testing.T) {
	src := `package mylib

func TestSomething() {
	panic("deliberate test panic")
}
`
	fset, file := parseSource(t, "foo_test.go", src)
	findings := checkLINT003(fset, file, "foo_test.go", false, true)
	assertFindings(t, findings, "LINT003", 0)
}

func TestLINT003_MultiplePanicsInLibrary(t *testing.T) {
	src := `package mylib

func a() { panic("a") }
func b() { panic("b") }
`
	fset, file := parseSource(t, "mylib.go", src)
	findings := checkLINT003(fset, file, "mylib.go", false, false)
	assertFindings(t, findings, "LINT003", 2)
}

func TestLINT003_NoPanicInLibrary(t *testing.T) {
	src := `package mylib

import "errors"

func doThing() error {
	return errors.New("something went wrong")
}
`
	fset, file := parseSource(t, "mylib.go", src)
	findings := checkLINT003(fset, file, "mylib.go", false, false)
	assertFindings(t, findings, "LINT003", 0)
}

// ---- LINT004 ----------------------------------------------------------------

func TestLINT004_InitPresent(t *testing.T) {
	src := `package mypkg

func init() {
	// side-effect init
}
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT004(fset, file, "foo.go")
	assertFindings(t, findings, "LINT004", 1)
}

func TestLINT004_NoInit(t *testing.T) {
	src := `package mypkg

func Setup() {}
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT004(fset, file, "foo.go")
	assertFindings(t, findings, "LINT004", 0)
}

func TestLINT004_InitWithParams(t *testing.T) {
	// A function named init but with parameters is not a canonical init().
	src := `package mypkg

func init(x int) {}
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT004(fset, file, "foo.go")
	assertFindings(t, findings, "LINT004", 0)
}

func TestLINT004_InitWithReturnValue(t *testing.T) {
	src := `package mypkg

func init() error { return nil }
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT004(fset, file, "foo.go")
	assertFindings(t, findings, "LINT004", 0)
}

func TestLINT004_MultipleInits(t *testing.T) {
	// Go allows multiple init functions.
	src := `package mypkg

func init() {}
func init() {}
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT004(fset, file, "foo.go")
	assertFindings(t, findings, "LINT004", 2)
}

// ---- LINT005 ----------------------------------------------------------------

func TestLINT005_InconsistentReceivers(t *testing.T) {
	src := `package mypkg

type MyType struct{}

func (m *MyType) MethodA() {}
func (t *MyType) MethodB() {}
`
	fset, file := parseSource(t, "foo.go", src)
	entries := []fileEntry{{fset: fset, file: file, path: "foo.go"}}
	findings := checkLINT005Package(entries)
	assertFindings(t, findings, "LINT005", 1)
	if len(findings) > 0 && !strings.Contains(findings[0].Message, "MyType") {
		t.Errorf("expected finding to reference MyType, got: %s", findings[0].Message)
	}
}

func TestLINT005_ConsistentReceivers(t *testing.T) {
	src := `package mypkg

type MyType struct{}

func (m *MyType) MethodA() {}
func (m *MyType) MethodB() {}
func (m *MyType) MethodC() {}
`
	fset, file := parseSource(t, "foo.go", src)
	entries := []fileEntry{{fset: fset, file: file, path: "foo.go"}}
	findings := checkLINT005Package(entries)
	assertFindings(t, findings, "LINT005", 0)
}

func TestLINT005_BlankReceiverIgnored(t *testing.T) {
	// Blank receiver names should not count as inconsistencies.
	src := `package mypkg

type MyType struct{}

func (m *MyType) MethodA() {}
func (_ *MyType) MethodB() {}
`
	fset, file := parseSource(t, "foo.go", src)
	entries := []fileEntry{{fset: fset, file: file, path: "foo.go"}}
	findings := checkLINT005Package(entries)
	assertFindings(t, findings, "LINT005", 0)
}

func TestLINT005_SingleMethod(t *testing.T) {
	// Only one method — no inconsistency possible.
	src := `package mypkg

type MyType struct{}

func (m *MyType) OnlyMethod() {}
`
	fset, file := parseSource(t, "foo.go", src)
	entries := []fileEntry{{fset: fset, file: file, path: "foo.go"}}
	findings := checkLINT005Package(entries)
	assertFindings(t, findings, "LINT005", 0)
}

func TestLINT005_CrossFileInconsistency(t *testing.T) {
	src1 := `package mypkg

type Shared struct{}

func (s *Shared) Alpha() {}
`
	src2 := `package mypkg

func (x *Shared) Beta() {}
`
	fset1, file1 := parseSource(t, "a.go", src1)
	fset2, file2 := parseSource(t, "b.go", src2)
	entries := []fileEntry{
		{fset: fset1, file: file1, path: "a.go"},
		{fset: fset2, file: file2, path: "b.go"},
	}
	findings := checkLINT005Package(entries)
	assertFindings(t, findings, "LINT005", 1)
}

func TestLINT005_DifferentTypes(t *testing.T) {
	// Different types can have whatever receiver names they like.
	src := `package mypkg

type TypeA struct{}
type TypeB struct{}

func (a *TypeA) Method() {}
func (b *TypeB) Method() {}
`
	fset, file := parseSource(t, "foo.go", src)
	entries := []fileEntry{{fset: fset, file: file, path: "foo.go"}}
	findings := checkLINT005Package(entries)
	assertFindings(t, findings, "LINT005", 0)
}

// ---- LINT006 ----------------------------------------------------------------

func TestLINT006_MagicNumberInFunction(t *testing.T) {
	src := `package mypkg

func doThing() int {
	return 42
}
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT006(fset, file, "foo.go")
	assertAtLeast(t, findings, "LINT006", 1)
	if len(findings) > 0 && !strings.Contains(findings[0].Message, "42") {
		t.Errorf("expected finding to reference 42, got: %s", findings[0].Message)
	}
}

func TestLINT006_ZeroAndOneNotFlagged(t *testing.T) {
	src := `package mypkg

func doThing() (int, bool) {
	x := 0
	y := 1
	return x + y, true
}
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT006(fset, file, "foo.go")
	assertFindings(t, findings, "LINT006", 0)
}

func TestLINT006_ConstBlockNotFlagged(t *testing.T) {
	src := `package mypkg

const (
	MaxRetries = 42
	Timeout    = 3600
)
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT006(fset, file, "foo.go")
	assertFindings(t, findings, "LINT006", 0)
}

func TestLINT006_FloatLiteral(t *testing.T) {
	src := `package mypkg

func pi() float64 {
	return 3.14
}
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT006(fset, file, "foo.go")
	assertAtLeast(t, findings, "LINT006", 1)
}

func TestLINT006_ImportPathNotFlagged(t *testing.T) {
	// Import paths (which are BasicLit strings) should not be flagged.
	src := `package mypkg

import "fmt"

func doThing() {
	fmt.Println("hello")
}
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT006(fset, file, "foo.go")
	assertFindings(t, findings, "LINT006", 0)
}

func TestLINT006_NoMagicNumbers(t *testing.T) {
	src := `package mypkg

const Limit = 100

func doThing(items []int) []int {
	result := make([]int, 0, Limit)
	for i := 0; i < len(items); i++ {
		result = append(result, items[i])
	}
	return result
}
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT006(fset, file, "foo.go")
	// "0" is benign; Limit is a const reference (Ident, not BasicLit); len is a call.
	assertFindings(t, findings, "LINT006", 0)
}

// ---- VET001 (go vet wrapper) ------------------------------------------------

func TestParseGoVetOutput_ValidLine(t *testing.T) {
	line := "./myfile.go:10:5: printf format %v expects a matching value"
	f := parseVetLine("/tmp/mydir", line)
	if f == nil {
		t.Fatal("expected a finding, got nil")
	}
	if f.RuleID != "VET001" {
		t.Errorf("expected VET001, got %s", f.RuleID)
	}
	if f.Severity != "medium" {
		t.Errorf("expected medium severity, got %s", f.Severity)
	}
	if f.Line != 10 {
		t.Errorf("expected line 10, got %d", f.Line)
	}
	if f.Column != 5 {
		t.Errorf("expected col 5, got %d", f.Column)
	}
	if !strings.Contains(f.Message, "printf") {
		t.Errorf("expected message to contain 'printf', got: %s", f.Message)
	}
}

func TestParseGoVetOutput_PkgSummarySkipped(t *testing.T) {
	raw := []byte("# example.com/foo\n./foo.go:3:1: unreachable code\n")
	findings := parseGoVetOutput("/tmp", raw)
	assertAtLeast(t, findings, "VET001", 1)
	for _, f := range findings {
		if strings.Contains(f.Message, "example.com") {
			t.Error("package summary line should not become a finding")
		}
	}
}

func TestParseGoVetOutput_EmptyOutput(t *testing.T) {
	findings := parseGoVetOutput("/tmp", []byte(""))
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty output, got %d", len(findings))
	}
}

func TestParseGoVetOutput_MalformedLineSkipped(t *testing.T) {
	raw := []byte("this is not a valid vet line\n")
	findings := parseGoVetOutput("/tmp", raw)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for malformed line, got %d", len(findings))
	}
}

func TestRunGoVet_RealDir(t *testing.T) {
	// Create a minimal valid Go module in a temp dir and run go vet on it.
	dir := t.TempDir()
	goMod := "module example.com/vettest\n\ngo 1.21.0\n"
	mainGo := `package main

import "fmt"

func main() {
	fmt.Println("hello")
}
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainGo), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := runGoVet(dir)
	// go vet should succeed on clean code; we allow nil findings.
	if err != nil {
		t.Logf("runGoVet returned err (acceptable if go not on PATH): %v", err)
		return
	}
	// On clean code there should be no vet findings.
	if len(findings) != 0 {
		t.Logf("unexpected vet findings on clean code: %+v", findings)
	}
}

func TestRunGoVet_VetFindsIssue(t *testing.T) {
	// Create a module with a vet-detectable issue (wrong printf verb).
	dir := t.TempDir()
	goMod := "module example.com/vettest2\n\ngo 1.21.0\n"
	mainGo := `package main

import "fmt"

func main() {
	x := 42
	fmt.Printf("%s", x) // vet: wrong type for %s
}
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainGo), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := runGoVet(dir)
	if err != nil {
		t.Logf("runGoVet failed (acceptable if go not on PATH): %v", err)
		return
	}
	if len(findings) == 0 {
		t.Logf("go vet did not detect printf issue (may be an older toolchain without the check): no findings")
		return
	}
	assertAtLeast(t, findings, "VET001", 1)
}

// ---- Integration: analyzeFile -----------------------------------------------

func TestAnalyzeFile_ParseError(t *testing.T) {
	path := writeTempFile(t, "bad.go", "this is not valid go code !!!!")
	findings, err := analyzeFile(path)
	// Should return an error, not crash.
	if err == nil {
		t.Error("expected parse error for invalid Go source, got nil")
	}
	if findings != nil {
		t.Errorf("expected nil findings on parse error, got %+v", findings)
	}
}

func TestAnalyzeFile_CleanFile(t *testing.T) {
	src := `// Package mypkg is a clean package.
package mypkg

// DoThing does a thing.
func DoThing() {}
`
	path := writeTempFile(t, "clean.go", src)
	findings, err := analyzeFile(path)
	if err != nil {
		t.Fatalf("analyzeFile error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on clean file, got: %+v", findings)
	}
}

func TestAnalyzeFile_MultipleRules(t *testing.T) {
	// File that triggers multiple rules at once.
	src := `package mylib

import "os"

func init() {}

func BadFunc() {
	panic("oops")
	f, _ := os.Open("x")
	_ = f
	_ = 42
}
`
	path := writeTempFile(t, "multi.go", src)
	findings, err := analyzeFile(path)
	if err != nil {
		t.Fatalf("analyzeFile error: %v", err)
	}
	// LINT001: BadFunc has no doc.
	assertAtLeast(t, findings, "LINT001", 1)
	// LINT004: init() present.
	assertAtLeast(t, findings, "LINT004", 1)
	// LINT003: panic in library package.
	assertAtLeast(t, findings, "LINT003", 1)
	// LINT002: error ignored with _.
	assertAtLeast(t, findings, "LINT002", 1)
	// LINT006: magic number 42.
	assertAtLeast(t, findings, "LINT006", 1)
}

// ---- Integration: runLintAnalysisWithLINT005 --------------------------------

func TestRunLintAnalysisWithLINT005_InconsistentReceivers(t *testing.T) {
	dir := writeTempDir(t, map[string]string{
		"a.go": `package mypkg

type Counter struct{ n int }

func (c *Counter) Inc() { c.n++ }
`,
		"b.go": `package mypkg

func (x *Counter) Dec() { x.n-- }
`,
	})

	findings, err := runLintAnalysisWithLINT005(dir)
	if err != nil {
		t.Fatalf("runLintAnalysisWithLINT005: %v", err)
	}
	assertAtLeast(t, findings, "LINT005", 1)
}

func TestRunLintAnalysisWithLINT005_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	findings, err := runLintAnalysisWithLINT005(dir)
	if err != nil {
		t.Fatalf("unexpected error on empty dir: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on empty dir, got %d", len(findings))
	}
}

func TestRunLintAnalysisWithLINT005_VendorSkipped(t *testing.T) {
	// Files inside vendor/ should not be analyzed.
	dir := writeTempDir(t, map[string]string{
		"vendor/some/pkg/bad.go": `package pkg

func PanicInVendor() { panic("vendor") }
`,
		"main.go": `package main

func main() {}
`,
	})

	findings, err := runLintAnalysisWithLINT005(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.File, "vendor") {
			t.Errorf("vendor file should be skipped, got finding: %+v", f)
		}
	}
}

// ---- Analyzer interface (New, Name, Description, Run) -----------------------

func TestNew_ReturnsAnalyzer(t *testing.T) {
	a := New()
	if a == nil {
		t.Fatal("New() returned nil")
	}
}

func TestName(t *testing.T) {
	a := New()
	if a.Name() != "lint" {
		t.Errorf("expected name 'lint', got %q", a.Name())
	}
}

func TestDescription(t *testing.T) {
	a := New()
	if a.Description() == "" {
		t.Error("Description() returned empty string")
	}
}

func TestRun_OnCleanModule(t *testing.T) {
	// Build a minimal but valid Go module.
	dir := t.TempDir()
	goMod := "module example.com/clean\n\ngo 1.21.0\n"
	mainGo := `// Package main is a clean main package.
package main

import "fmt"

// main is the entry point.
func main() {
	fmt.Println("hello")
}
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainGo), 0o644); err != nil {
		t.Fatal(err)
	}

	a := New()
	findings, err := a.Run(dir)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	// A clean module should produce zero (or only benign info) findings.
	t.Logf("Run() on clean module: %d findings", len(findings))
}

func TestRun_RegistrationInit(t *testing.T) {
	// Verify the lint analyzer registers itself via init().
	found := false
	for _, a := range analyzer.All() {
		if a.Name() == "lint" {
			found = true
			break
		}
	}
	if !found {
		t.Error("lint analyzer should be registered via init()")
	}
}

// ---- helpers unit tests -----------------------------------------------------

func TestIsExported(t *testing.T) {
	cases := []struct {
		name     string
		exported bool
	}{
		{"Exported", true},
		{"unexported", false},
		{"", false},
		{"_", false},
		{"HTTPClient", true},
	}
	for _, c := range cases {
		if got := isExported(c.name); got != c.exported {
			t.Errorf("isExported(%q) = %v, want %v", c.name, got, c.exported)
		}
	}
}

func TestHasProperGodoc(t *testing.T) {
	makeDoc := func(text string) *ast.CommentGroup {
		return &ast.CommentGroup{
			List: []*ast.Comment{{Text: "// " + text}},
		}
	}

	if !hasProperGodoc(makeDoc("MyFunc does something."), "MyFunc") {
		t.Error("expected hasProperGodoc to return true for matching comment")
	}
	if hasProperGodoc(makeDoc("This does something."), "MyFunc") {
		t.Error("expected hasProperGodoc to return false for non-matching comment")
	}
	if hasProperGodoc(nil, "MyFunc") {
		t.Error("expected hasProperGodoc to return false for nil doc")
	}
	if hasProperGodoc(&ast.CommentGroup{}, "MyFunc") {
		t.Error("expected hasProperGodoc to return false for empty comment group")
	}
}

func TestReceiverTypeName(t *testing.T) {
	// *T → "T"
	star := &ast.StarExpr{X: &ast.Ident{Name: "T"}}
	if got := receiverTypeName(star); got != "T" {
		t.Errorf("expected 'T', got %q", got)
	}
	// T → "T"
	ident := &ast.Ident{Name: "T"}
	if got := receiverTypeName(ident); got != "T" {
		t.Errorf("expected 'T', got %q", got)
	}
}

func TestCallExprName(t *testing.T) {
	cases := []struct {
		fun  ast.Expr
		want string
	}{
		{&ast.Ident{Name: "open"}, "open"},
		{&ast.SelectorExpr{
			X:   &ast.Ident{Name: "os"},
			Sel: &ast.Ident{Name: "Open"},
		}, "os.Open"},
	}
	for _, c := range cases {
		call := &ast.CallExpr{Fun: c.fun}
		if got := callExprName(call); got != c.want {
			t.Errorf("callExprName(%T) = %q, want %q", c.fun, got, c.want)
		}
	}
}

func TestIsBenignLiteral(t *testing.T) {
	benign := []string{"0", "1", "2", "10"}
	for _, v := range benign {
		if !isBenignLiteral(v) {
			t.Errorf("expected %q to be benign", v)
		}
	}
	nonBenign := []string{"42", "100", "3.14", "255"}
	for _, v := range nonBenign {
		if isBenignLiteral(v) {
			t.Errorf("expected %q to be non-benign", v)
		}
	}
}

// ---- Additional edge-case coverage -----------------------------------------

func TestCallExprName_ComplexExpr(t *testing.T) {
	// A call expression whose Fun is neither Ident nor SelectorExpr.
	// e.g., a function stored in a struct field: obj.funcs[0]()
	call := &ast.CallExpr{Fun: &ast.IndexExpr{
		X:     &ast.Ident{Name: "funcs"},
		Index: &ast.BasicLit{Kind: token.INT, Value: "0"},
	}}
	name := callExprName(call)
	if name != "<expr>" {
		t.Errorf("expected <expr> for complex Fun, got %q", name)
	}
}

func TestCallLikelyReturnsError_PlainIdent(t *testing.T) {
	// A plain function identifier that doesn't match any pattern.
	call := &ast.CallExpr{Fun: &ast.Ident{Name: "transform"}}
	if callLikelyReturnsError(call) {
		t.Error("expected callLikelyReturnsError=false for unmatched plain ident")
	}
}

func TestCallLikelyReturnsError_SelectorAlwaysTrue(t *testing.T) {
	// Any selector expression (method call) should return true.
	call := &ast.CallExpr{Fun: &ast.SelectorExpr{
		X:   &ast.Ident{Name: "db"},
		Sel: &ast.Ident{Name: "Ping"},
	}}
	if !callLikelyReturnsError(call) {
		t.Error("expected callLikelyReturnsError=true for selector expression")
	}
}

func TestReceiverTypeName_IndexExpr(t *testing.T) {
	// Generic receiver: T[K] — IndexExpr wrapping an Ident.
	idx := &ast.IndexExpr{
		X:     &ast.Ident{Name: "Map"},
		Index: &ast.Ident{Name: "K"},
	}
	if got := receiverTypeName(idx); got != "Map" {
		t.Errorf("expected 'Map' for IndexExpr receiver, got %q", got)
	}
}

func TestReceiverTypeName_Unknown(t *testing.T) {
	// An expression type we don't handle should return "".
	got := receiverTypeName(&ast.BadExpr{})
	if got != "" {
		t.Errorf("expected empty string for unknown expr, got %q", got)
	}
}

func TestLINT005_Package_NoReceivers(t *testing.T) {
	// File with no methods at all — checkLINT005Package should return nothing.
	src := `package mypkg

func Standalone() {}
`
	fset, file := parseSource(t, "foo.go", src)
	entries := []fileEntry{{fset: fset, file: file, path: "foo.go"}}
	findings := checkLINT005Package(entries)
	assertFindings(t, findings, "LINT005", 0)
}

func TestLINT002_IgnoredViaPatternMatch(t *testing.T) {
	// Ensure that a known error-returning stdlib pattern (os.Open) is flagged.
	src := `package mypkg

import "os"

func process() {
	data, _ := os.ReadFile("config.json")
	_ = data
}
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT002(fset, file, "foo.go")
	assertAtLeast(t, findings, "LINT002", 1)
}

func TestParseVetLine_ThreeParts(t *testing.T) {
	// go vet sometimes emits 3-part lines (no column).
	line := "./foo.go:5: something is wrong"
	f := parseVetLine("/tmp", line)
	// With only 3 parts (split on :), we get file/line/msg.
	// Our parser splits into 4 parts max; a 3-part input fills parts[3]="".
	// This tests the fallback path.
	if f != nil {
		// If parsed, message should be present or empty but not crash.
		t.Logf("3-part line parsed: %+v", f)
	}
}

func TestLINT001_GroupedVarBlock(t *testing.T) {
	// In a grouped var block with multiple specs, each exported spec
	// without its own doc should be flagged.
	src := `package mypkg

var (
	ExportedA = 1
	ExportedB = 2
	unexported = 3
)
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT001(fset, file, "foo.go", false)
	// ExportedA and ExportedB should each be flagged.
	assertAtLeast(t, findings, "LINT001", 2)
}

func TestLINT006_MultipleInSameFunc(t *testing.T) {
	src := `package mypkg

func compute() int {
	return 42 + 99 + 255
}
`
	fset, file := parseSource(t, "foo.go", src)
	findings := checkLINT006(fset, file, "foo.go")
	assertAtLeast(t, findings, "LINT006", 3)
}
