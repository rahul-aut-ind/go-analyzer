// Package security implements the security analyzer for go-analyzer.
// It detects common security vulnerabilities in Go source code via AST
// inspection, raw byte regex scanning, and optional govulncheck integration.
//
// Rules implemented:
//
//	SEC001 – tls.Config with InsecureSkipVerify: true (critical)
//	SEC002 – Import of crypto/md5 or crypto/sha1 (high)
//	SEC003 – exec.Command called with a non-literal argument (high)
//	SEC004 – Hard-coded secret literals (password/apikey/secret/token) (critical)
//	SEC005 – SQL query built via string concatenation with a variable (high)
//	SEC006 – Import of math/rand instead of crypto/rand (medium)
package security

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rahul-aut-ind/go-analyzer/internal/analyzer"
)

// securityAnalyzer detects common security vulnerabilities in Go source code.
type securityAnalyzer struct{}

// New returns a new security Analyzer ready for use.
func New() analyzer.Analyzer { return &securityAnalyzer{} }

// Name returns the short identifier for this analyzer.
func (a *securityAnalyzer) Name() string { return "security" }

// Description returns a one-line summary of what this analyzer checks.
func (a *securityAnalyzer) Description() string {
	return "Detects security vulnerabilities: insecure TLS, weak crypto, command injection, hard-coded secrets, SQL injection, and insecure random"
}

// Run executes security analysis on the Go module rooted at dir.
// It performs AST-based checks, raw byte regex scanning for SEC004, and
// optionally runs govulncheck if it is installed on the PATH.
func (a *securityAnalyzer) Run(dir string) ([]analyzer.Finding, error) {
	var findings []analyzer.Finding

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			// Skip files that cannot be parsed (e.g. cgo).
			return nil
		}

		findings = append(findings, checkFile(fset, file, path)...)

		// SEC004: raw byte scan for hard-coded secrets.
		sec004, readErr := checkHardcodedSecrets(path)
		if readErr == nil {
			findings = append(findings, sec004...)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("security: walking directory %s: %w", dir, err)
	}

	// Optional govulncheck integration.
	vulnFindings, _ := runGovulncheck(dir)
	findings = append(findings, vulnFindings...)

	return findings, nil
}

// checkFile runs all AST-based rules (SEC001–SEC003, SEC005–SEC006) on a
// single parsed source file.
func checkFile(fset *token.FileSet, file *ast.File, path string) []analyzer.Finding {
	var findings []analyzer.Finding

	// SEC002 / SEC006: import path checks.
	findings = append(findings, checkImports(fset, file, path)...)

	// Walk AST for SEC001, SEC003, SEC005.
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.CompositeLit:
			findings = append(findings, checkTLSConfig(fset, node, path)...)
		case *ast.CallExpr:
			findings = append(findings, checkExecCommand(fset, node, path)...)
		case *ast.AssignStmt:
			findings = append(findings, checkSQLInjection(fset, node, path)...)
		}
		return true
	})

	return findings
}

// checkImports inspects all import declarations for SEC002 (weak crypto) and
// SEC006 (insecure random).
func checkImports(fset *token.FileSet, file *ast.File, path string) []analyzer.Finding {
	var findings []analyzer.Finding
	for _, imp := range file.Imports {
		if imp.Path == nil {
			continue
		}
		importPath := strings.Trim(imp.Path.Value, `"`)
		pos := fset.Position(imp.Pos())
		switch importPath {
		case "crypto/md5":
			findings = append(findings, analyzer.Finding{
				RuleID:     "SEC002",
				Severity:   "high",
				Message:    "import of crypto/md5 uses a weak hashing algorithm vulnerable to collision attacks",
				File:       path,
				Line:       pos.Line,
				Column:     pos.Column,
				Suggestion: "Replace crypto/md5 with crypto/sha256 or crypto/sha512",
			})
		case "crypto/sha1":
			findings = append(findings, analyzer.Finding{
				RuleID:     "SEC002",
				Severity:   "high",
				Message:    "import of crypto/sha1 uses a weak hashing algorithm vulnerable to collision attacks",
				File:       path,
				Line:       pos.Line,
				Column:     pos.Column,
				Suggestion: "Replace crypto/sha1 with crypto/sha256 or crypto/sha512",
			})
		case "math/rand":
			findings = append(findings, analyzer.Finding{
				RuleID:     "SEC006",
				Severity:   "medium",
				Message:    "import of math/rand provides a pseudo-random generator unsuitable for security-sensitive operations",
				File:       path,
				Line:       pos.Line,
				Column:     pos.Column,
				Suggestion: "Replace math/rand with crypto/rand for cryptographically secure random number generation",
			})
		}
	}
	return findings
}

// checkTLSConfig detects composite literals for tls.Config that set
// InsecureSkipVerify to true (SEC001).
func checkTLSConfig(fset *token.FileSet, lit *ast.CompositeLit, path string) []analyzer.Finding {
	sel, ok := lit.Type.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	if sel.Sel == nil || sel.Sel.Name != "Config" {
		return nil
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok || pkgIdent.Name != "tls" {
		return nil
	}

	var findings []analyzer.Finding
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "InsecureSkipVerify" {
			continue
		}
		if isTrueLiteral(kv.Value) {
			pos := fset.Position(kv.Pos())
			findings = append(findings, analyzer.Finding{
				RuleID:     "SEC001",
				Severity:   "critical",
				Message:    "tls.Config has InsecureSkipVerify set to true, disabling certificate verification",
				File:       path,
				Line:       pos.Line,
				Column:     pos.Column,
				Suggestion: "Remove InsecureSkipVerify or set it to false; validate server certificates properly",
			})
		}
	}
	return findings
}

// isTrueLiteral reports whether expr represents the boolean value true, either
// as a *ast.Ident named "true" or as a *ast.BasicLit with value "true".
func isTrueLiteral(expr ast.Expr) bool {
	switch v := expr.(type) {
	case *ast.Ident:
		return v.Name == "true"
	case *ast.BasicLit:
		return v.Value == "true"
	}
	return false
}

// checkExecCommand detects calls to exec.Command where any argument is not a
// string literal, indicating a potential command injection risk (SEC003).
func checkExecCommand(fset *token.FileSet, call *ast.CallExpr, path string) []analyzer.Finding {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	if sel.Sel == nil || sel.Sel.Name != "Command" {
		return nil
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok || pkgIdent.Name != "exec" {
		return nil
	}
	if len(call.Args) == 0 {
		return nil
	}

	for _, arg := range call.Args {
		if !isStringLiteral(arg) {
			pos := fset.Position(call.Pos())
			return []analyzer.Finding{{
				RuleID:     "SEC003",
				Severity:   "high",
				Message:    "exec.Command called with a non-literal argument; command may be influenced by untrusted input",
				File:       path,
				Line:       pos.Line,
				Column:     pos.Column,
				Suggestion: "Use a hard-coded string literal for the executable path; validate all arguments",
			}}
		}
	}
	return nil
}

// isStringLiteral reports whether expr is a string BasicLit.
func isStringLiteral(expr ast.Expr) bool {
	lit, ok := expr.(*ast.BasicLit)
	return ok && lit.Kind == token.STRING
}

// secretPattern matches assignments of the form:
//
//	password = "somevalue"   (case-insensitive key)
//
// The value must be at least 3 characters long to avoid false positives on
// empty or placeholder strings.
var secretPattern = regexp.MustCompile(`(?i)(password|apikey|api_key|secret|token)\s*=\s*"[^"]{3,}"`)

// checkHardcodedSecrets scans the raw bytes of the file at path for patterns
// that look like hard-coded secret assignments (SEC004).
func checkHardcodedSecrets(path string) ([]analyzer.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var findings []analyzer.Finding
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if secretPattern.MatchString(line) {
			match := secretPattern.FindString(line)
			col := strings.Index(line, match) + 1
			findings = append(findings, analyzer.Finding{
				RuleID:     "SEC004",
				Severity:   "critical",
				Message:    fmt.Sprintf("potential hard-coded secret detected: %s", strings.TrimSpace(match)),
				File:       path,
				Line:       i + 1,
				Column:     col,
				Suggestion: "Store secrets in environment variables or a secrets manager; never commit credentials to source control",
			})
		}
	}
	return findings, nil
}

// sqlKeywords are the SQL DML keywords that indicate a string literal is part
// of a SQL query.
var sqlKeywords = []string{"SELECT", "INSERT", "UPDATE", "DELETE"}

// checkSQLInjection detects assignments where the RHS is a binary addition
// expression that combines a SQL string literal with a variable (SEC005).
func checkSQLInjection(fset *token.FileSet, assign *ast.AssignStmt, path string) []analyzer.Finding {
	var findings []analyzer.Finding
	for _, rhs := range assign.Rhs {
		if f := inspectBinaryForSQL(fset, rhs, path); f != nil {
			findings = append(findings, *f)
		}
	}
	return findings
}

// inspectBinaryForSQL recursively walks a binary expression tree looking for
// an addition that concatenates a SQL keyword literal with a variable.
func inspectBinaryForSQL(fset *token.FileSet, expr ast.Expr, path string) *analyzer.Finding {
	bin, ok := expr.(*ast.BinaryExpr)
	if !ok {
		return nil
	}
	if bin.Op != token.ADD {
		return nil
	}

	// Check whether one side is a SQL literal and the other contains a variable.
	if containsSQLLiteral(bin.X) && containsVariable(bin.Y) {
		pos := fset.Position(bin.Pos())
		return &analyzer.Finding{
			RuleID:     "SEC005",
			Severity:   "high",
			Message:    "SQL query built via string concatenation with a variable; potential SQL injection",
			File:       path,
			Line:       pos.Line,
			Column:     pos.Column,
			Suggestion: "Use parameterised queries (db.Query with ? placeholders) instead of string concatenation",
		}
	}
	if containsSQLLiteral(bin.Y) && containsVariable(bin.X) {
		pos := fset.Position(bin.Pos())
		return &analyzer.Finding{
			RuleID:     "SEC005",
			Severity:   "high",
			Message:    "SQL query built via string concatenation with a variable; potential SQL injection",
			File:       path,
			Line:       pos.Line,
			Column:     pos.Column,
			Suggestion: "Use parameterised queries (db.Query with ? placeholders) instead of string concatenation",
		}
	}

	// Recurse into nested binary expressions (e.g. "SELECT" + x + y).
	if f := inspectBinaryForSQL(fset, bin.X, path); f != nil {
		return f
	}
	return inspectBinaryForSQL(fset, bin.Y, path)
}

// containsSQLLiteral reports whether expr is a string BasicLit whose value
// contains one of the SQL DML keywords.
func containsSQLLiteral(expr ast.Expr) bool {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	upper := strings.ToUpper(lit.Value)
	for _, kw := range sqlKeywords {
		if strings.Contains(upper, kw) {
			return true
		}
	}
	return false
}

// containsVariable reports whether expr is a non-literal expression that could
// carry user-controlled data (Ident, SelectorExpr, CallExpr, IndexExpr, etc.).
func containsVariable(expr ast.Expr) bool {
	switch expr.(type) {
	case *ast.BasicLit:
		return false
	default:
		return true
	}
}

// runGovulncheck optionally executes govulncheck on the module at dir and
// returns any findings it produces. If govulncheck is not installed, the
// function returns (nil, nil) so the absence of the tool is not treated as an
// analysis error.
func runGovulncheck(dir string) ([]analyzer.Finding, error) {
	cmd := exec.Command("govulncheck", "./...")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(err.Error(), "executable file not found") {
			return nil, nil // govulncheck not installed – skip gracefully
		}
		// govulncheck found vulnerabilities or exited non-zero; parse output below.
	}

	output := string(out)
	if output == "" {
		return nil, nil
	}

	var findings []analyzer.Finding
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Vulnerability") {
			continue
		}
		// Best-effort: report each "Vulnerability #N: …" line as a finding.
		findings = append(findings, analyzer.Finding{
			RuleID:     "VULN001",
			Severity:   "high",
			Message:    line,
			File:       filepath.Join(dir, "go.mod"),
			Line:       1,
			Column:     1,
			Suggestion: "Run `go get` to update the affected module to a non-vulnerable version",
		})
	}
	return findings, nil
}

func init() {
	analyzer.Register(New())
}
