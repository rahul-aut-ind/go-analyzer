// Package deadcode implements the dead code analyzer for go-analyzer.
// It detects unused unexported functions, unreachable code after return/panic,
// and unused exported constants via AST-based analysis.
package deadcode

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/rahul-aut-ind/go-analyzer/internal/analyzer"
)

// deadcodeAnalyzer is the implementation of the dead code Analyzer.
type deadcodeAnalyzer struct{}

// New returns a new dead code Analyzer.
func New() analyzer.Analyzer { return &deadcodeAnalyzer{} }

// Name returns the analyzer's short identifier.
func (a *deadcodeAnalyzer) Name() string { return "deadcode" }

// Description returns a one-line summary of what this analyzer checks.
func (a *deadcodeAnalyzer) Description() string {
	return "Detects dead code: unused unexported functions, unreachable statements after return/panic, and unused exported constants"
}

// Run executes dead code detection on the Go module rooted at dir.
func (a *deadcodeAnalyzer) Run(dir string) ([]analyzer.Finding, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("deadcode: parse %s: %w", dir, err)
	}

	var findings []analyzer.Finding

	for _, pkg := range pkgs {
		findings = append(findings, checkDEAD001(fset, pkg)...)
		findings = append(findings, checkDEAD002(fset, pkg)...)
		findings = append(findings, checkDEAD003(fset, pkg)...)
	}

	toolFindings, _ := runDeadcodeTool(dir)
	findings = append(findings, toolFindings...)

	return findings, nil
}

// checkDEAD001 detects unexported functions that are never called within
// their own package. Functions named init, main, TestXxx, BenchmarkXxx,
// ExampleXxx, and methods with receivers are excluded.
func checkDEAD001(fset *token.FileSet, pkg *ast.Package) []analyzer.Finding {
	// Collect all unexported top-level function declarations (no receiver).
	type funcInfo struct {
		decl *ast.FuncDecl
		pos  token.Position
	}
	declared := map[string]funcInfo{}

	for _, file := range pkg.Files {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			name := fd.Name.Name
			// Skip exported, methods, and well-known entry-point functions.
			if fd.Recv != nil {
				continue
			}
			if isExported(name) {
				continue
			}
			if isExcludedFuncName(name) {
				continue
			}
			pos := fset.Position(fd.Pos())
			declared[name] = funcInfo{decl: fd, pos: pos}
		}
	}

	// Collect all call-expression function name identifiers across all files.
	called := map[string]bool{}
	for _, file := range pkg.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				called[fun.Name] = true
			case *ast.SelectorExpr:
				called[fun.Sel.Name] = true
			}
			return true
		})
	}

	var findings []analyzer.Finding
	for name, info := range declared {
		if called[name] {
			continue
		}
		findings = append(findings, analyzer.Finding{
			RuleID:     "DEAD001",
			Severity:   "low",
			Message:    fmt.Sprintf("unexported function %q is never called within package %q", name, pkg.Name),
			File:       info.pos.Filename,
			Line:       info.pos.Line,
			Column:     info.pos.Column,
			Suggestion: "Remove the function or call it from somewhere in the package.",
		})
	}
	return findings
}

// checkDEAD002 detects statements that are unreachable because they follow a
// return statement or a panic() call at the top level of a block.
func checkDEAD002(fset *token.FileSet, pkg *ast.Package) []analyzer.Finding {
	var findings []analyzer.Finding

	for _, file := range pkg.Files {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			findings = append(findings, unreachableInBlock(fset, fd.Body.List)...)
		}
	}
	return findings
}

// unreachableInBlock checks a flat list of statements for code after a
// return or panic call. Only the first unreachable statement is reported.
func unreachableInBlock(fset *token.FileSet, stmts []ast.Stmt) []analyzer.Finding {
	var findings []analyzer.Finding
	for i, stmt := range stmts {
		if isTerminating(stmt) && i+1 < len(stmts) {
			next := stmts[i+1]
			pos := fset.Position(next.Pos())
			findings = append(findings, analyzer.Finding{
				RuleID:     "DEAD002",
				Severity:   "medium",
				Message:    "unreachable code after return or panic statement",
				File:       pos.Filename,
				Line:       pos.Line,
				Column:     pos.Column,
				Suggestion: "Remove the unreachable code.",
			})
			// Report only the first unreachable statement per block.
			break
		}
	}
	return findings
}

// isTerminating reports whether stmt is a return statement or a panic() call.
func isTerminating(stmt ast.Stmt) bool {
	switch s := stmt.(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.ExprStmt:
		call, ok := s.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		ident, ok := call.Fun.(*ast.Ident)
		return ok && ident.Name == "panic"
	}
	return false
}

// checkDEAD003 detects exported constants that are never referenced anywhere
// in the package (excluding their own declaration). This is a heuristic.
func checkDEAD003(fset *token.FileSet, pkg *ast.Package) []analyzer.Finding {
	type constInfo struct {
		pos token.Position
	}
	declared := map[string]constInfo{}

	// Collect all exported constants.
	for _, file := range pkg.Files {
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, name := range vs.Names {
					if isExported(name.Name) {
						declared[name.Name] = constInfo{pos: fset.Position(name.Pos())}
					}
				}
			}
		}
	}

	if len(declared) == 0 {
		return nil
	}

	// Count all Ident references across all files.
	refCount := map[string]int{}
	for _, file := range pkg.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if ok {
				refCount[ident.Name]++
			}
			return true
		})
	}

	// A declared constant's name will appear at least once (its declaration).
	// If it appears exactly once it is unreferenced.
	var findings []analyzer.Finding
	for name, info := range declared {
		if refCount[name] <= 1 {
			findings = append(findings, analyzer.Finding{
				RuleID:     "DEAD003",
				Severity:   "info",
				Message:    fmt.Sprintf("exported constant %q appears to be unused (heuristic)", name),
				File:       info.pos.Filename,
				Line:       info.pos.Line,
				Column:     info.pos.Column,
				Suggestion: "Remove the constant or add a reference to suppress this warning.",
			})
		}
	}
	return findings
}

// isExported reports whether name is an exported Go identifier.
func isExported(name string) bool {
	return len(name) > 0 && name[0] >= 'A' && name[0] <= 'Z'
}

// isExcludedFuncName reports whether name is one of the well-known entry-point
// function names that should not be flagged as unused.
func isExcludedFuncName(name string) bool {
	switch name {
	case "init", "main":
		return true
	}
	return strings.HasPrefix(name, "Test") ||
		strings.HasPrefix(name, "Benchmark") ||
		strings.HasPrefix(name, "Example") ||
		strings.HasPrefix(name, "Fuzz")
}

// runDeadcodeTool optionally wraps the golang.org/x/tools/cmd/deadcode
// subprocess. If the binary is not installed, the function returns nil, nil.
func runDeadcodeTool(dir string) ([]analyzer.Finding, error) {
	cmd := exec.Command("deadcode", "./...")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		if isNotFound(err) {
			// deadcode binary not installed – skip gracefully.
			return nil, nil
		}
		// Parse whatever output was produced.
		return parseDeadcodeOutput(string(out), dir), nil
	}
	return parseDeadcodeOutput(string(out), dir), nil
}

// isNotFound reports whether err signals that the executable was not found.
func isNotFound(err error) bool {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false
	}
	return strings.Contains(err.Error(), "executable file not found") ||
		strings.Contains(err.Error(), "no such file or directory")
}

// parseDeadcodeOutput converts lines from the deadcode tool into Findings.
// Expected format: "file.go:line:col: message"
func parseDeadcodeOutput(output, dir string) []analyzer.Finding {
	var findings []analyzer.Finding
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var file string
		var lineNum, col int
		var msg string
		// Try to parse "path/to/file.go:line:col: message"
		n, err := fmt.Sscanf(line, "%s", &file)
		if n == 0 || err != nil {
			continue
		}
		// Attempt structured parse.
		parts := strings.SplitN(line, ":", 4)
		if len(parts) >= 3 {
			file = filepath.Join(dir, parts[0])
			fmt.Sscanf(parts[1], "%d", &lineNum)
			if len(parts) >= 4 {
				fmt.Sscanf(parts[2], "%d", &col)
				msg = strings.TrimSpace(parts[3])
			} else {
				msg = strings.TrimSpace(parts[2])
			}
		}
		if msg == "" {
			continue
		}
		findings = append(findings, analyzer.Finding{
			RuleID:   "DEAD001",
			Severity: "low",
			Message:  msg,
			File:     file,
			Line:     lineNum,
			Column:   col,
		})
	}
	return findings
}

func init() {
	analyzer.Register(New())
}
