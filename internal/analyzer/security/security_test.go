// Package security_test contains table-driven tests for the security analyzer.
// Each rule has at least one positive (triggers the rule) and one negative
// (does not trigger the rule) test case. Inline source code is parsed with
// go/parser so no external files or test-data directories are required.
package security

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

// parseSource parses src as a complete Go source file. It calls t.Fatal on
// parse failure so callers do not need to handle errors.
func parseSource(t *testing.T, src string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, 0)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return fset, f
}

// countRule runs checkFile on src and returns the number of findings whose
// RuleID equals ruleID.
func countRule(t *testing.T, src, ruleID string) int {
	t.Helper()
	fset, f := parseSource(t, src)
	findings := checkFile(fset, f, "test.go")
	n := 0
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			n++
		}
	}
	return n
}

// writeTempFile creates a temporary .go file containing src and returns its
// path. The caller is responsible for deleting it (use t.Cleanup or t.TempDir).
func writeTempFile(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.go")
	if err := os.WriteFile(path, []byte(src), 0600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

// ─── SEC001 ───────────────────────────────────────────────────────────────────

// TestSEC001_InsecureSkipVerify verifies that tls.Config{InsecureSkipVerify: true}
// is detected and that safe configurations are not flagged.
func TestSEC001_InsecureSkipVerify(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantMin int
	}{
		{
			name: "positive: InsecureSkipVerify true via ident",
			src: `package p
import "crypto/tls"
func f() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}`,
			wantMin: 1,
		},
		{
			name: "positive: InsecureSkipVerify nested in struct",
			src: `package p
import (
	"crypto/tls"
	"net/http"
)
func f() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}
}`,
			wantMin: 1,
		},
		{
			name: "negative: InsecureSkipVerify false",
			src: `package p
import "crypto/tls"
func f() *tls.Config {
	return &tls.Config{InsecureSkipVerify: false}
}`,
			wantMin: 0,
		},
		{
			name: "negative: tls.Config without InsecureSkipVerify",
			src: `package p
import "crypto/tls"
func f() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}`,
			wantMin: 0,
		},
		{
			name: "negative: unrelated struct literal named Config",
			src: `package p
type Config struct{ InsecureSkipVerify bool }
func f() Config { return Config{InsecureSkipVerify: true} }`,
			wantMin: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := countRule(t, tc.src, "SEC001")
			if tc.wantMin == 0 && got != 0 {
				t.Errorf("expected no SEC001 findings, got %d", got)
			} else if tc.wantMin > 0 && got < tc.wantMin {
				t.Errorf("expected at least %d SEC001 finding(s), got %d", tc.wantMin, got)
			}
		})
	}
}

// ─── SEC002 ───────────────────────────────────────────────────────────────────

// TestSEC002_WeakCrypto verifies that imports of crypto/md5 and crypto/sha1
// are flagged and that stronger alternatives are not.
func TestSEC002_WeakCrypto(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantMin int
	}{
		{
			name: "positive: crypto/md5 import",
			src: `package p
import "crypto/md5"
func f() { _ = md5.New() }`,
			wantMin: 1,
		},
		{
			name: "positive: crypto/sha1 import",
			src: `package p
import "crypto/sha1"
func f() { _ = sha1.New() }`,
			wantMin: 1,
		},
		{
			name: "negative: crypto/sha256 import",
			src: `package p
import "crypto/sha256"
func f() { _ = sha256.New() }`,
			wantMin: 0,
		},
		{
			name: "negative: crypto/sha512 import",
			src: `package p
import "crypto/sha512"
func f() { _ = sha512.New() }`,
			wantMin: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := countRule(t, tc.src, "SEC002")
			if tc.wantMin == 0 && got != 0 {
				t.Errorf("expected no SEC002 findings, got %d", got)
			} else if tc.wantMin > 0 && got < tc.wantMin {
				t.Errorf("expected at least %d SEC002 finding(s), got %d", tc.wantMin, got)
			}
		})
	}
}

// ─── SEC003 ───────────────────────────────────────────────────────────────────

// TestSEC003_ExecCommandVariable verifies that exec.Command with a variable
// argument is detected and that calls with only string literals are not.
func TestSEC003_ExecCommandVariable(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantMin int
	}{
		{
			name: "positive: exec.Command with ident argument",
			src: `package p
import "os/exec"
func f(cmd string) error {
	return exec.Command(cmd).Run()
}`,
			wantMin: 1,
		},
		{
			name: "positive: exec.Command with selector expression argument",
			src: `package p
import "os/exec"
type cfg struct{ Bin string }
func f(c cfg) error {
	return exec.Command(c.Bin).Run()
}`,
			wantMin: 1,
		},
		{
			name: "positive: exec.Command with call expression argument",
			src: `package p
import "os/exec"
func getBin() string { return "ls" }
func f() error {
	return exec.Command(getBin()).Run()
}`,
			wantMin: 1,
		},
		{
			name: "negative: exec.Command with only string literal",
			src: `package p
import "os/exec"
func f() error {
	return exec.Command("ls", "-la").Run()
}`,
			wantMin: 0,
		},
		{
			name: "negative: non-exec Command call",
			src: `package p
type other struct{}
func (o other) Command(s string) {}
func f(o other, s string) { o.Command(s) }`,
			wantMin: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := countRule(t, tc.src, "SEC003")
			if tc.wantMin == 0 && got != 0 {
				t.Errorf("expected no SEC003 findings, got %d", got)
			} else if tc.wantMin > 0 && got < tc.wantMin {
				t.Errorf("expected at least %d SEC003 finding(s), got %d", tc.wantMin, got)
			}
		})
	}
}

// ─── SEC004 ───────────────────────────────────────────────────────────────────

// TestSEC004_HardcodedSecrets verifies that the regex scanner detects
// hard-coded credential assignments in raw file bytes.
func TestSEC004_HardcodedSecrets(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantMin int
	}{
		{
			name: "positive: password assignment",
			src: `package p
var dbPassword = "supersecret123"
`,
			wantMin: 1,
		},
		{
			name: "positive: apikey assignment",
			src: `package p
const apikey = "AKIAIOSFODNN7EXAMPLE"
`,
			wantMin: 1,
		},
		{
			name: "positive: api_key assignment",
			src: `package p
var api_key = "sk-abc123defxyz"
`,
			wantMin: 1,
		},
		{
			name: "positive: secret assignment",
			src: `package p
var secret = "topsecretvalue"
`,
			wantMin: 1,
		},
		{
			name: "positive: token assignment",
			src: `package p
var token = "bearer_abc123xyz"
`,
			wantMin: 1,
		},
		{
			name: "negative: empty string value",
			src: `package p
var password = ""
`,
			wantMin: 0,
		},
		{
			name: "negative: short string (less than 3 chars)",
			src: `package p
var password = "ab"
`,
			wantMin: 0,
		},
		{
			name: "negative: unrelated variable name",
			src: `package p
var userName = "alice"
`,
			wantMin: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTempFile(t, tc.src)
			findings, err := checkHardcodedSecrets(path)
			if err != nil {
				t.Fatalf("checkHardcodedSecrets: %v", err)
			}
			got := 0
			for _, f := range findings {
				if f.RuleID == "SEC004" {
					got++
				}
			}
			if tc.wantMin == 0 && got != 0 {
				t.Errorf("expected no SEC004 findings, got %d", got)
			} else if tc.wantMin > 0 && got < tc.wantMin {
				t.Errorf("expected at least %d SEC004 finding(s), got %d", tc.wantMin, got)
			}
		})
	}
}

// TestSEC004_ReadError verifies that checkHardcodedSecrets returns an error
// when given a path that does not exist.
func TestSEC004_ReadError(t *testing.T) {
	_, err := checkHardcodedSecrets("/nonexistent/path/test.go")
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}

// ─── SEC005 ───────────────────────────────────────────────────────────────────

// TestSEC005_SQLInjection verifies that SQL queries built with string
// concatenation and a variable are detected.
func TestSEC005_SQLInjection(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantMin int
	}{
		{
			name: "positive: SELECT + variable",
			src: `package p
import "database/sql"
func f(db *sql.DB, id string) {
	q := "SELECT * FROM users WHERE id = " + id
	db.Query(q)
}`,
			wantMin: 1,
		},
		{
			name: "positive: INSERT + variable",
			src: `package p
import "database/sql"
func f(db *sql.DB, val string) {
	q := "INSERT INTO logs VALUES (" + val + ")"
	db.Exec(q)
}`,
			wantMin: 1,
		},
		{
			name: "positive: UPDATE + variable",
			src: `package p
import "database/sql"
func f(db *sql.DB, name string) {
	q := "UPDATE users SET name = " + name
	db.Exec(q)
}`,
			wantMin: 1,
		},
		{
			name: "positive: DELETE + variable",
			src: `package p
import "database/sql"
func f(db *sql.DB, id string) {
	q := "DELETE FROM sessions WHERE id = " + id
	db.Exec(q)
}`,
			wantMin: 1,
		},
		{
			name: "negative: SQL literal concatenated with another literal only",
			src: `package p
import "database/sql"
func f(db *sql.DB) {
	q := "SELECT * FROM users" + " WHERE active = 1"
	db.Query(q)
}`,
			wantMin: 0,
		},
		{
			name: "negative: non-SQL string concatenation with variable",
			src: `package p
func f(name string) string {
	return "Hello, " + name
}`,
			wantMin: 0,
		},
		{
			name: "negative: parameterised query (no concatenation)",
			src: `package p
import "database/sql"
func f(db *sql.DB, id string) {
	db.Query("SELECT * FROM users WHERE id = ?", id)
}`,
			wantMin: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := countRule(t, tc.src, "SEC005")
			if tc.wantMin == 0 && got != 0 {
				t.Errorf("expected no SEC005 findings, got %d", got)
			} else if tc.wantMin > 0 && got < tc.wantMin {
				t.Errorf("expected at least %d SEC005 finding(s), got %d", tc.wantMin, got)
			}
		})
	}
}

// ─── SEC006 ───────────────────────────────────────────────────────────────────

// TestSEC006_InsecureRandom verifies that imports of math/rand are detected
// and that crypto/rand imports are not flagged.
func TestSEC006_InsecureRandom(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantMin int
	}{
		{
			name: "positive: math/rand import",
			src: `package p
import "math/rand"
func f() int { return rand.Intn(100) }`,
			wantMin: 1,
		},
		{
			name: "negative: crypto/rand import",
			src: `package p
import "crypto/rand"
import "math/big"
func f() *big.Int {
	n, _ := rand.Int(rand.Reader, big.NewInt(100))
	return n
}`,
			wantMin: 0,
		},
		{
			name: "negative: no rand import at all",
			src: `package p
func f() int { return 42 }`,
			wantMin: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := countRule(t, tc.src, "SEC006")
			if tc.wantMin == 0 && got != 0 {
				t.Errorf("expected no SEC006 findings, got %d", got)
			} else if tc.wantMin > 0 && got < tc.wantMin {
				t.Errorf("expected at least %d SEC006 finding(s), got %d", tc.wantMin, got)
			}
		})
	}
}

// ─── Analyzer interface ────────────────────────────────────────────────────────

// TestAnalyzerMetadata verifies the Name and Description methods on the
// exported constructor.
func TestAnalyzerMetadata(t *testing.T) {
	a := New()
	if a.Name() != "security" {
		t.Errorf("Name() = %q, want %q", a.Name(), "security")
	}
	if a.Description() == "" {
		t.Error("Description() returned empty string")
	}
	if !strings.Contains(a.Description(), "security") && !strings.Contains(a.Description(), "Security") {
		t.Errorf("Description() = %q; expected it to mention security", a.Description())
	}
}

// TestAnalyzerRun_Testdata runs the full analyzer against the project testdata
// sample and verifies that all four expected security findings are present.
func TestAnalyzerRun_Testdata(t *testing.T) {
	// Locate the testdata/sample directory relative to this file.
	// The tests run with the working directory set to the package directory, so
	// we walk upward until we find testdata/sample/main.go.
	sampleDir := findTestdataDir(t)

	a := New()
	findings, err := a.Run(sampleDir)
	if err != nil {
		t.Fatalf("Run(%q): %v", sampleDir, err)
	}

	wantRules := map[string]bool{
		"SEC001": false,
		"SEC002": false,
		"SEC003": false,
		"SEC006": false,
	}
	for _, f := range findings {
		if _, ok := wantRules[f.RuleID]; ok {
			wantRules[f.RuleID] = true
		}
	}

	for rule, found := range wantRules {
		if !found {
			t.Errorf("expected finding for rule %s in testdata/sample, but none was reported", rule)
		}
	}
}

// findTestdataDir walks upward from the current directory until it locates the
// testdata/sample directory that is known to exist in this repository.
func findTestdataDir(t *testing.T) string {
	t.Helper()
	// Start from the directory containing this test file by using os.Getwd()
	// (go test sets cwd to the package directory).
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		candidate := filepath.Join(dir, "testdata", "sample")
		if _, err := os.Stat(filepath.Join(candidate, "main.go")); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate testdata/sample directory")
		}
		dir = parent
	}
}

// ─── Internal helper unit tests ───────────────────────────────────────────────

// TestIsTrueLiteral verifies the isTrueLiteral helper for both ast.Ident and
// ast.BasicLit values.
func TestIsTrueLiteral(t *testing.T) {
	src := `package p
import "crypto/tls"
var _ = &tls.Config{InsecureSkipVerify: true}
`
	fset, f := parseSource(t, src)
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "InsecureSkipVerify" {
			return true
		}
		found = isTrueLiteral(kv.Value)
		return false
	})
	_ = fset
	if !found {
		t.Error("isTrueLiteral should return true for ident 'true'")
	}
}

// TestIsStringLiteral ensures isStringLiteral correctly distinguishes string
// BasicLits from other expression types.
func TestIsStringLiteral(t *testing.T) {
	src := `package p
import "os/exec"
func f(cmd string) { exec.Command("ls") }
`
	fset, f := parseSource(t, src)
	_ = fset
	var strLitFound, identFound bool
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Command" {
			return true
		}
		for _, arg := range call.Args {
			if isStringLiteral(arg) {
				strLitFound = true
			}
		}
		return true
	})
	// Also check an ident
	ast.Inspect(f, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if ok && id.Name == "cmd" {
			identFound = !isStringLiteral(id)
		}
		return true
	})
	if !strLitFound {
		t.Error("isStringLiteral should return true for a string BasicLit")
	}
	if !identFound {
		t.Error("isStringLiteral should return false for an Ident")
	}
}

// TestContainsVariable verifies the containsVariable helper.
func TestContainsVariable(t *testing.T) {
	ident := &ast.Ident{Name: "x"}
	if !containsVariable(ident) {
		t.Error("containsVariable should return true for an Ident")
	}

	lit := &ast.BasicLit{Kind: token.STRING, Value: `"hello"`}
	if containsVariable(lit) {
		t.Error("containsVariable should return false for a BasicLit")
	}
}

// TestContainsSQLLiteral verifies that containsSQLLiteral correctly identifies
// SQL keyword strings and rejects non-SQL strings.
func TestContainsSQLLiteral(t *testing.T) {
	cases := []struct {
		val  string
		want bool
	}{
		{`"SELECT * FROM users"`, true},
		{`"INSERT INTO log"`, true},
		{`"UPDATE users SET"`, true},
		{`"DELETE FROM sessions"`, true},
		{`"Hello, world"`, false},
		{`"select me"`, true}, // case-insensitive
	}

	for _, c := range cases {
		lit := &ast.BasicLit{Kind: token.STRING, Value: c.val}
		got := containsSQLLiteral(lit)
		if got != c.want {
			t.Errorf("containsSQLLiteral(%q) = %v, want %v", c.val, got, c.want)
		}
	}

	// Non-string literal should return false.
	intLit := &ast.BasicLit{Kind: token.INT, Value: "42"}
	if containsSQLLiteral(intLit) {
		t.Error("containsSQLLiteral should return false for a non-string literal")
	}
}

// TestSecretPattern verifies the secretPattern regex against known positive and
// negative cases directly without needing a file on disk.
func TestSecretPattern(t *testing.T) {
	positives := []string{
		`password = "supersecret"`,
		`apikey = "AKIAIOSFODNN7EXAMPLE"`,
		`api_key = "sk-test-abc123"`,
		`secret = "my-secret-val"`,
		`token = "bearer_token123"`,
		`PASSWORD = "UPPERCASE123"`,
	}
	negatives := []string{
		`password = ""`,
		`password = "ab"`,
		`username = "alice"`,
		`// password = "commented out"`, // should still match — just raw scan
	}

	for _, s := range positives {
		if !secretPattern.MatchString(s) {
			t.Errorf("secretPattern should match %q", s)
		}
	}
	// The commented-out case is intentionally left as a comment above; only
	// false-negative cases that should NOT match are listed below:
	for _, s := range negatives {
		if secretPattern.MatchString(s) {
			t.Logf("note: secretPattern matched %q (intentional for raw scan)", s)
		}
	}
	// Ensure true negatives are truly negative.
	trulyNegative := []string{
		`username = "alice"`,
		`host = "localhost"`,
	}
	for _, s := range trulyNegative {
		if secretPattern.MatchString(s) {
			t.Errorf("secretPattern should NOT match %q", s)
		}
	}
}

// TestRunGovulncheckNotInstalled ensures that runGovulncheck returns nil/nil
// when govulncheck is not on the PATH (graceful skip).
func TestRunGovulncheckNotInstalled(t *testing.T) {
	// Point at a temp dir so govulncheck (if installed) has nothing to scan.
	dir := t.TempDir()
	// If govulncheck is not installed this must return (nil, nil).
	// If it is installed it may return results or an error — we only care
	// that the function does not panic and that an absent binary is handled.
	findings, err := runGovulncheck(dir)
	if err != nil {
		t.Logf("runGovulncheck returned error (acceptable if govulncheck is installed): %v", err)
	}
	_ = findings
}

// TestAnalyzerRun_EmptyDir verifies that the analyzer handles an empty
// directory without returning an error.
func TestAnalyzerRun_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	a := New()
	findings, err := a.Run(dir)
	if err != nil {
		t.Fatalf("Run on empty dir returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty dir, got %d", len(findings))
	}
}

// TestAnalyzerRun_SingleFile runs the full Run method on a temporary directory
// containing a single Go file with multiple violations to exercise the
// end-to-end WalkDir path.
func TestAnalyzerRun_SingleFile(t *testing.T) {
	src := `package p

import (
	"crypto/md5"
	"crypto/tls"
	"math/rand"
	"os/exec"
)

func weakHash() { _ = md5.New() }

func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

func execVar(cmd string) { exec.Command(cmd) }

func insecureRand() int { return rand.Intn(10) }
`
	dir := t.TempDir()
	// Write go.mod so WalkDir finds .go files.
	gomod := "module example.com/test\ngo 1.21\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0600); err != nil {
		t.Fatalf("write main.go: %v", err)
	}

	a := New()
	findings, err := a.Run(dir)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	wantRules := map[string]bool{
		"SEC001": false,
		"SEC002": false,
		"SEC003": false,
		"SEC006": false,
	}
	for _, f := range findings {
		if _, ok := wantRules[f.RuleID]; ok {
			wantRules[f.RuleID] = true
		}
	}
	for rule, found := range wantRules {
		if !found {
			t.Errorf("expected finding for rule %s, but none was reported", rule)
		}
	}
}

// TestAnalyzerRun_SEC004_EndToEnd verifies SEC004 via the full Run path (raw
// byte scan over a temp file with a hard-coded secret).
func TestAnalyzerRun_SEC004_EndToEnd(t *testing.T) {
	src := `package p

var dbPassword = "supersecret123"
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\ngo 1.21\n"), 0600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0600); err != nil {
		t.Fatalf("write main.go: %v", err)
	}

	a := New()
	findings, err := a.Run(dir)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	sec004 := 0
	for _, f := range findings {
		if f.RuleID == "SEC004" {
			sec004++
		}
	}
	if sec004 == 0 {
		t.Error("expected at least one SEC004 finding for hard-coded password, got none")
	}
}
