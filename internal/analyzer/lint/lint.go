// Package lint implements the lint analyzer for go-analyzer.
// It detects common Go style and quality issues via AST inspection and
// also wraps `go vet ./...` to surface tool-detected problems.
package lint

import (
	"bufio"
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/rahul-aut-ind/go-analyzer/internal/analyzer"
)

// lintAnalyzer implements analyzer.Analyzer for lint checks.
type lintAnalyzer struct{}

// New returns a new lint Analyzer.
func New() analyzer.Analyzer { return &lintAnalyzer{} }

// Name returns the analyzer's short identifier.
func (a *lintAnalyzer) Name() string { return "lint" }

// Description returns a one-line summary of what this analyzer checks.
func (a *lintAnalyzer) Description() string {
	return "Detects lint issues: missing godoc, ignored errors, panic in library code, init functions, inconsistent receivers, magic numbers, and go vet violations"
}

// Run executes lint analysis on the Go module rooted at dir.
func (a *lintAnalyzer) Run(dir string) ([]analyzer.Finding, error) {
	findings, err := runLintAnalysisWithLINT005(dir)
	if err != nil {
		return nil, err
	}

	vetFindings, _ := runGoVet(dir) // go vet errors are non-fatal; best-effort
	findings = append(findings, vetFindings...)
	return findings, nil
}

func init() {
	analyzer.Register(New())
}

// analyzeFile parses a single Go source file and applies all lint rules.
func analyzeFile(path string) ([]analyzer.Finding, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	isTestFile := strings.HasSuffix(path, "_test.go")
	pkgName := file.Name.Name
	isMainPkg := pkgName == "main"

	var findings []analyzer.Finding

	findings = append(findings, checkLINT001(fset, file, path, isTestFile)...)
	findings = append(findings, checkLINT002(fset, file, path)...)
	findings = append(findings, checkLINT003(fset, file, path, isMainPkg, isTestFile)...)
	findings = append(findings, checkLINT004(fset, file, path)...)
	findings = append(findings, checkLINT006(fset, file, path)...)

	return findings, nil
}

// checkLINT001 flags exported identifiers (functions, types, variables, constants)
// that are missing a proper godoc comment. Test files are skipped entirely.
//
// A proper godoc comment starts with the identifier name.
func checkLINT001(fset *token.FileSet, file *ast.File, path string, isTestFile bool) []analyzer.Finding {
	if isTestFile {
		return nil
	}

	var findings []analyzer.Finding

	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			// Skip methods (they have a receiver); only check top-level functions.
			if d.Recv != nil {
				continue
			}
			name := d.Name.Name
			if !isExported(name) {
				continue
			}
			if !hasProperGodoc(d.Doc, name) {
				pos := fset.Position(d.Pos())
				findings = append(findings, analyzer.Finding{
					RuleID:     "LINT001",
					Severity:   "low",
					Message:    fmt.Sprintf("exported function %q is missing a godoc comment starting with %q", name, name),
					File:       path,
					Line:       pos.Line,
					Column:     pos.Column,
					Suggestion: fmt.Sprintf("Add a comment: // %s ...", name),
				})
			}

		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					name := s.Name.Name
					if !isExported(name) {
						continue
					}
					// Use the spec doc first, then fall back to the group decl doc.
					doc := s.Doc
					if doc == nil {
						doc = d.Doc
					}
					if !hasProperGodoc(doc, name) {
						pos := fset.Position(s.Pos())
						findings = append(findings, analyzer.Finding{
							RuleID:     "LINT001",
							Severity:   "low",
							Message:    fmt.Sprintf("exported type %q is missing a godoc comment starting with %q", name, name),
							File:       path,
							Line:       pos.Line,
							Column:     pos.Column,
							Suggestion: fmt.Sprintf("Add a comment: // %s ...", name),
						})
					}

				case *ast.ValueSpec:
					for _, ident := range s.Names {
						name := ident.Name
						if !isExported(name) {
							continue
						}
						// For grouped decls (var/const blocks) use the group doc
						// when the individual spec has none.
						doc := s.Doc
						if doc == nil && len(d.Specs) == 1 {
							doc = d.Doc
						}
						if !hasProperGodoc(doc, name) {
							pos := fset.Position(ident.Pos())
							kind := "variable"
							if d.Tok == token.CONST {
								kind = "constant"
							}
							findings = append(findings, analyzer.Finding{
								RuleID:     "LINT001",
								Severity:   "low",
								Message:    fmt.Sprintf("exported %s %q is missing a godoc comment starting with %q", kind, name, name),
								File:       path,
								Line:       pos.Line,
								Column:     pos.Column,
								Suggestion: fmt.Sprintf("Add a comment: // %s ...", name),
							})
						}
					}
				}
			}
		}
	}

	return findings
}

// checkLINT002 flags assignments where an error return value is explicitly
// discarded with the blank identifier `_`.
//
// It detects:
//   - `x, _ = f()` or `x, _ := f()` where f's last argument is likely an error.
//   - `_, _ = f()` patterns are also flagged if the second blank is the error position.
func checkLINT002(fset *token.FileSet, file *ast.File, path string) []analyzer.Finding {
	var findings []analyzer.Finding

	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}

		// We need at least 2 LHS values and at least 1 RHS (multi-return call).
		if len(assign.Lhs) < 2 || len(assign.Rhs) != 1 {
			return true
		}

		// Check if the last LHS is the blank identifier.
		lastLhs := assign.Lhs[len(assign.Lhs)-1]
		blank, isBlank := lastLhs.(*ast.Ident)
		if !isBlank || blank.Name != "_" {
			return true
		}

		// Check that RHS is a function call (not a type conversion).
		call, isCall := assign.Rhs[0].(*ast.CallExpr)
		if !isCall {
			return true
		}

		// Heuristic: flag if the function name suggests error-returning calls.
		// We check the function identifier name for common patterns.
		if !callLikelyReturnsError(call) {
			return true
		}

		pos := fset.Position(assign.Pos())
		funcName := callExprName(call)
		findings = append(findings, analyzer.Finding{
			RuleID:   "LINT002",
			Severity: "medium",
			Message:  fmt.Sprintf("error return value from %q is explicitly ignored with '_'", funcName),
			File:     path,
			Line:     pos.Line,
			Column:   pos.Column,
			Suggestion: "Handle the error explicitly or use a named variable and log/wrap it; " +
				"use //nolint:errcheck if intentional",
		})

		return true
	})

	return findings
}

// callLikelyReturnsError applies heuristics to decide whether a call expression
// likely returns an error as its last result.
func callLikelyReturnsError(call *ast.CallExpr) bool {
	name := strings.ToLower(callExprName(call))

	// Common standard-library and idiomatic Go functions that return (T, error).
	errorPatterns := []string{
		"open", "create", "read", "write", "close", "query", "exec",
		"parse", "decode", "encode", "scan", "connect", "dial",
		"marshal", "unmarshal", "get", "post", "do", "run",
		"load", "save", "fetch", "send", "receive", "listen",
		"join", "stat", "mkdir", "remove", "rename", "copy",
		"new", "init", "start", "stop", "wait",
	}
	for _, p := range errorPatterns {
		if strings.Contains(name, p) {
			return true
		}
	}

	// If the function is a selector (e.g. file.Read, db.Query), assume it
	// may return an error — this is the conservative/safe approach.
	if _, ok := call.Fun.(*ast.SelectorExpr); ok {
		return true
	}

	return false
}

// callExprName returns a human-readable name for a call expression.
func callExprName(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if x, ok := f.X.(*ast.Ident); ok {
			return x.Name + "." + f.Sel.Name
		}
		return f.Sel.Name
	default:
		return "<expr>"
	}
}

// checkLINT003 flags calls to panic() in non-main, non-test packages.
func checkLINT003(fset *token.FileSet, file *ast.File, path string, isMainPkg, isTestFile bool) []analyzer.Finding {
	if isMainPkg || isTestFile {
		return nil
	}

	var findings []analyzer.Finding

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		ident, ok := call.Fun.(*ast.Ident)
		if !ok || ident.Name != "panic" {
			return true
		}

		pos := fset.Position(call.Pos())
		findings = append(findings, analyzer.Finding{
			RuleID:   "LINT003",
			Severity: "high",
			Message:  "panic() called in library package; prefer returning an error instead",
			File:     path,
			Line:     pos.Line,
			Column:   pos.Column,
			Suggestion: "Replace panic() with an error return. Reserve panic for truly " +
				"unrecoverable programmer errors in package main.",
		})

		return true
	})

	return findings
}

// checkLINT004 flags init() functions (presence, not an error — severity info).
func checkLINT004(fset *token.FileSet, file *ast.File, path string) []analyzer.Finding {
	var findings []analyzer.Finding

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Name.Name != "init" {
			continue
		}
		// Canonical init: no parameters, no return values.
		if fn.Type.Params != nil && fn.Type.Params.NumFields() > 0 {
			continue
		}
		if fn.Type.Results != nil && fn.Type.Results.NumFields() > 0 {
			continue
		}

		pos := fset.Position(fn.Pos())
		findings = append(findings, analyzer.Finding{
			RuleID:   "LINT004",
			Severity: "info",
			Message:  "init() function present; consider whether side-effect initialization can be made explicit",
			File:     path,
			Line:     pos.Line,
			Column:   pos.Column,
			Suggestion: "Prefer explicit initialization functions called by the consumer " +
				"over automatic init() side effects.",
		})
	}

	return findings
}

// checkLINT005 flags types whose methods use inconsistent receiver names.
// It is invoked once per file-set (all files in a directory walk share the call),
// but for simplicity we return per-file findings based on the declarations in
// this file.  Cross-file consistency would require a two-pass walk; the spec
// says "methods of same type" so we collect within the walked set.
//
// This function is called from a package-level pass; individual file calls
// contribute to a shared map via collectReceivers, then emitLINT005 finalises.
func checkLINT005(_ *token.FileSet, _ *ast.File, _ string) []analyzer.Finding {
	// Handled via the package-level pass in checkLINT005Package.
	return nil
}

// receiverEntry stores a receiver name and the file/line it appears on.
type receiverEntry struct {
	name string
	file string
	line int
	col  int
}

// checkLINT005Package performs a cross-file LINT005 analysis over the given
// set of (fset, file, path) triples that all belong to the same package.
func checkLINT005Package(entries []fileEntry) []analyzer.Finding {
	// Map: typeName → list of (receiverName, position)
	typeReceivers := make(map[string][]receiverEntry)

	for _, fe := range entries {
		fset, file, path := fe.fset, fe.file, fe.path
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Recv.NumFields() == 0 {
				continue
			}
			field := fn.Recv.List[0]
			// Receiver type name (strip pointer).
			typeName := receiverTypeName(field.Type)
			if typeName == "" {
				continue
			}
			// Receiver variable name (may be blank or absent).
			varName := ""
			if len(field.Names) > 0 {
				varName = field.Names[0].Name
			}
			if varName == "_" || varName == "" {
				continue // blank receivers are ignored
			}

			pos := fset.Position(fn.Pos())
			typeReceivers[typeName] = append(typeReceivers[typeName], receiverEntry{
				name: varName,
				file: path,
				line: pos.Line,
				col:  pos.Column,
			})
		}
	}

	var findings []analyzer.Finding

	for typeName, recvs := range typeReceivers {
		if len(recvs) < 2 {
			continue
		}
		// Collect distinct names.
		seen := make(map[string]struct{})
		for _, r := range recvs {
			seen[r.name] = struct{}{}
		}
		if len(seen) < 2 {
			continue // consistent
		}

		// Build sorted name list for a stable message.
		var names []string
		for n := range seen {
			names = append(names, n)
		}

		// Report on the first occurrence.
		first := recvs[0]
		findings = append(findings, analyzer.Finding{
			RuleID:   "LINT005",
			Severity: "low",
			Message: fmt.Sprintf("inconsistent receiver names for type %q: found %s",
				typeName, strings.Join(names, ", ")),
			File:       first.file,
			Line:       first.line,
			Column:     first.col,
			Suggestion: fmt.Sprintf("Use a single consistent receiver name for all methods of %q.", typeName),
		})
	}

	return findings
}

// fileEntry bundles the three pieces needed per file for cross-file analysis.
type fileEntry struct {
	fset *token.FileSet
	file *ast.File
	path string
}

// receiverTypeName extracts the base type name from a receiver field type,
// stripping any star (pointer) indirection.
func receiverTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return receiverTypeName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr: // generic receiver T[X]
		return receiverTypeName(t.X)
	default:
		return ""
	}
}

// checkLINT006 flags magic numeric literals (integer or float constants that
// are not 0, 1, or -1) used outside a const declaration block.
//
// Strategy: collect all BasicLit positions that live inside a const GenDecl or
// import GenDecl, then walk the whole file and skip those positions.
func checkLINT006(fset *token.FileSet, file *ast.File, path string) []analyzer.Finding {
	// First pass: collect positions of all literals inside const/import decls.
	exempt := make(map[token.Pos]struct{})
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		if gd.Tok != token.CONST && gd.Tok != token.IMPORT {
			continue
		}
		ast.Inspect(gd, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok {
				exempt[lit.Pos()] = struct{}{}
			}
			return true
		})
	}

	var findings []analyzer.Finding

	ast.Inspect(file, func(n ast.Node) bool {
		node, ok := n.(*ast.BasicLit)
		if !ok {
			return true
		}
		if node.Kind != token.INT && node.Kind != token.FLOAT {
			return false
		}
		// Skip literals that live inside const or import blocks.
		if _, skip := exempt[node.Pos()]; skip {
			return false
		}
		val := node.Value
		if isBenignLiteral(val) {
			return false
		}

		pos := fset.Position(node.Pos())
		findings = append(findings, analyzer.Finding{
			RuleID:   "LINT006",
			Severity: "info",
			Message:  fmt.Sprintf("magic number %s: consider extracting to a named constant", val),
			File:     path,
			Line:     pos.Line,
			Column:   pos.Column,
			Suggestion: fmt.Sprintf("const meaningfulName = %s", val),
		})
		return false
	})

	return findings
}

// isBenignLiteral returns true for numeric literals that are so common they
// should not be flagged (0, 1 are already handled; we also skip 2 and 10
// which appear ubiquitously in integer ops and base conversions).
func isBenignLiteral(val string) bool {
	benign := map[string]bool{
		"0": true, "1": true, "2": true, "10": true,
	}
	return benign[val]
}

// isExported reports whether name begins with an uppercase letter.
func isExported(name string) bool {
	if name == "" {
		return false
	}
	return unicode.IsUpper(rune(name[0]))
}

// hasProperGodoc returns true when doc is non-nil and its first comment line
// begins with name (the Go godoc convention).
func hasProperGodoc(doc *ast.CommentGroup, name string) bool {
	if doc == nil || len(doc.List) == 0 {
		return false
	}
	// The first comment text, stripped of the "//" or "/*" prefix.
	first := doc.List[0].Text
	first = strings.TrimPrefix(first, "//")
	first = strings.TrimPrefix(first, "/*")
	first = strings.TrimSpace(first)
	return strings.HasPrefix(first, name)
}

// runGoVet runs `go vet ./...` in dir and parses the output into Findings.
// go vet exits non-zero when it finds issues; that is expected and non-fatal.
func runGoVet(dir string) ([]analyzer.Finding, error) {
	cmd := exec.Command("go", "vet", "./...")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()

	// If go vet itself could not run (e.g. not on PATH), surface the error.
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("go vet failed: %w", err)
	}

	return parseGoVetOutput(dir, out), nil
}

// parseGoVetOutput converts raw go vet output lines into Findings.
// Lines have the format: <file>:<line>:<col>: <message>
// or the format produced by older go vet: #  <pkg>  <message> on the same line.
func parseGoVetOutput(dir string, out []byte) []analyzer.Finding {
	var findings []analyzer.Finding
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Skip package-summary lines like "# example.com/sample"
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		f := parseVetLine(dir, line)
		if f != nil {
			findings = append(findings, *f)
		}
	}
	return findings
}

// parseVetLine parses a single go vet output line.
// Expected format: ./path/to/file.go:10:5: some message
func parseVetLine(dir, line string) *analyzer.Finding {
	// Split off the message: last field after the third colon.
	// Format: <file>:<line>:<col>: <msg>
	// Windows paths may contain drive letters, so parse carefully.
	parts := strings.SplitN(line, ":", 4)
	if len(parts) < 4 {
		// Try 3-part (file:line: msg) as fallback.
		if len(parts) == 3 {
			parts = append(parts, "")
		} else {
			return nil
		}
	}

	filePart := strings.TrimSpace(parts[0])
	lineNum, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil
	}
	colNum, err := strconv.Atoi(strings.TrimSpace(parts[2]))
	if err != nil {
		colNum = 0
	}
	msg := strings.TrimSpace(parts[3])

	// Resolve relative paths against dir.
	if !filepath.IsAbs(filePart) {
		filePart = filepath.Join(dir, filePart)
	}

	return &analyzer.Finding{
		RuleID:     "VET001",
		Severity:   "medium",
		Message:    msg,
		File:       filePart,
		Line:       lineNum,
		Column:     colNum,
		Suggestion: "Fix the issue reported by `go vet`.",
	}
}

// runLintAnalysisWithLINT005 is the package-aware entry point used internally.
// It groups files by package directory so that LINT005 can be applied across
// all files in a package.
func runLintAnalysisWithLINT005(dir string) ([]analyzer.Finding, error) {
	// Map: directory → slice of fileEntry
	pkgFiles := make(map[string][]fileEntry)

	var findings []analyzer.Finding

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			name := d.Name()
			if name != "." && (strings.HasPrefix(name, ".") || name == "vendor" || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "lint: parsing %s: %v\n", path, err)
			return nil
		}

		isTestFile := strings.HasSuffix(path, "_test.go")
		pkgName := file.Name.Name
		isMainPkg := pkgName == "main"

		findings = append(findings, checkLINT001(fset, file, path, isTestFile)...)
		findings = append(findings, checkLINT002(fset, file, path)...)
		findings = append(findings, checkLINT003(fset, file, path, isMainPkg, isTestFile)...)
		findings = append(findings, checkLINT004(fset, file, path)...)
		findings = append(findings, checkLINT006(fset, file, path)...)

		pkgDir := filepath.Dir(path)
		pkgFiles[pkgDir] = append(pkgFiles[pkgDir], fileEntry{fset: fset, file: file, path: path})

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Apply LINT005 per package directory.
	for _, entries := range pkgFiles {
		findings = append(findings, checkLINT005Package(entries)...)
	}

	return findings, nil
}
