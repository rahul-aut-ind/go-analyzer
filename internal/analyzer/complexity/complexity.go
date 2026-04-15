// Package complexity implements the code complexity analyzer for go-analyzer.
// It detects functions and files that exceed configurable thresholds for
// cyclomatic complexity, function body length, nesting depth, parameter count,
// and file line count — all via pure AST walking with no subprocess calls.
package complexity

import (
	"fmt"
	"go/ast"
	"go/token"

	"github.com/rahul-aut-ind/go-analyzer/internal/analyzer"
	"github.com/rahul-aut-ind/go-analyzer/internal/parser"
)

// Default thresholds for each rule.
const (
	defaultMaxCyclomaticComplexity = 10
	defaultMaxFuncBodyLines        = 50
	defaultMaxNestingDepth         = 4
	defaultMaxParams               = 5
	defaultMaxFileLines            = 500
)

// complexityAnalyzer implements analyzer.Analyzer for all complexity rules.
type complexityAnalyzer struct{}

// New returns a new complexity Analyzer ready to be run or registered.
func New() analyzer.Analyzer { return &complexityAnalyzer{} }

// Name returns the short identifier used to select this analyzer.
func (a *complexityAnalyzer) Name() string { return "complexity" }

// Description returns a one-line summary of what this analyzer checks.
func (a *complexityAnalyzer) Description() string {
	return "Detects high cyclomatic complexity, long functions, deep nesting, too many parameters, and large files"
}

// Run executes all complexity checks on the Go module rooted at dir and
// returns the aggregated list of findings.
func (a *complexityAnalyzer) Run(dir string) ([]analyzer.Finding, error) {
	pkgs, err := parser.Load(dir)
	if err != nil {
		return nil, fmt.Errorf("complexity: loading packages: %w", err)
	}

	var findings []analyzer.Finding
	for _, lp := range pkgs {
		for _, f := range lp.Files {
			findings = append(findings, checkFile(f, lp.Fset)...)
		}
	}
	return findings, nil
}

// checkFile runs all rules against a single parsed AST file.
func checkFile(f *ast.File, fset *token.FileSet) []analyzer.Finding {
	var findings []analyzer.Finding

	// CMPLX005: file line count.
	fileLineCount := fset.File(f.Pos()).LineCount()
	if fileLineCount > defaultMaxFileLines {
		findings = append(findings, analyzer.Finding{
			RuleID:   "CMPLX005",
			Severity: "info",
			Message: fmt.Sprintf("file has %d lines, exceeds maximum of %d",
				fileLineCount, defaultMaxFileLines),
			File:       fset.Position(f.Pos()).Filename,
			Line:       1,
			Column:     1,
			Suggestion: "Consider splitting this file into smaller, focused files.",
		})
	}

	// Walk top-level declarations looking for function declarations.
	for _, decl := range f.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if !ok || funcDecl.Body == nil {
			continue
		}

		pos := fset.Position(funcDecl.Pos())
		name := funcDecl.Name.Name
		filename := pos.Filename

		// CMPLX001: cyclomatic complexity.
		cc := cyclomaticComplexity(funcDecl)
		if cc > defaultMaxCyclomaticComplexity {
			findings = append(findings, analyzer.Finding{
				RuleID:   "CMPLX001",
				Severity: "medium",
				Message: fmt.Sprintf("function %s has cyclomatic complexity of %d, exceeds maximum of %d",
					name, cc, defaultMaxCyclomaticComplexity),
				File:       filename,
				Line:       pos.Line,
				Column:     pos.Column,
				Suggestion: "Break this function into smaller, single-purpose functions.",
			})
		}

		// CMPLX002: function body line count.
		bodyLines := fset.Position(funcDecl.End()).Line - fset.Position(funcDecl.Pos()).Line
		if bodyLines > defaultMaxFuncBodyLines {
			findings = append(findings, analyzer.Finding{
				RuleID:   "CMPLX002",
				Severity: "low",
				Message: fmt.Sprintf("function %s has %d lines, exceeds maximum of %d",
					name, bodyLines, defaultMaxFuncBodyLines),
				File:       filename,
				Line:       pos.Line,
				Column:     pos.Column,
				Suggestion: "Extract logic into helper functions to reduce function length.",
			})
		}

		// CMPLX003: maximum nesting depth.
		depth := maxNestingDepth(funcDecl.Body)
		if depth > defaultMaxNestingDepth {
			findings = append(findings, analyzer.Finding{
				RuleID:   "CMPLX003",
				Severity: "medium",
				Message: fmt.Sprintf("function %s has nesting depth of %d, exceeds maximum of %d",
					name, depth, defaultMaxNestingDepth),
				File:       filename,
				Line:       pos.Line,
				Column:     pos.Column,
				Suggestion: "Reduce nesting by using early returns or extracting nested logic.",
			})
		}

		// CMPLX004: number of parameters.
		paramCount := countParams(funcDecl)
		if paramCount > defaultMaxParams {
			findings = append(findings, analyzer.Finding{
				RuleID:   "CMPLX004",
				Severity: "low",
				Message: fmt.Sprintf("function %s has %d parameters, exceeds maximum of %d",
					name, paramCount, defaultMaxParams),
				File:       filename,
				Line:       pos.Line,
				Column:     pos.Column,
				Suggestion: "Group related parameters into a struct to reduce parameter count.",
			})
		}
	}

	return findings
}

// cyclomaticComplexity computes the cyclomatic complexity of a single function
// declaration. The formula starts at 1 and adds 1 for each:
//   - IfStmt (including else-if branches, which are IfStmts inside an Else)
//   - ForStmt / RangeStmt
//   - CaseClause (switch and type-switch cases; default is not counted)
//   - CommClause (select cases; default is not counted)
//   - BinaryExpr with operator && or ||
func cyclomaticComplexity(fn *ast.FuncDecl) int {
	complexity := 1
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt:
			complexity++
		case *ast.ForStmt:
			complexity++
		case *ast.RangeStmt:
			complexity++
		case *ast.CaseClause:
			// default clause has nil List; only count non-default cases.
			if node.List != nil {
				complexity++
			}
		case *ast.CommClause:
			// default select clause has nil Comm; only count non-default.
			if node.Comm != nil {
				complexity++
			}
		case *ast.BinaryExpr:
			if node.Op == token.LAND || node.Op == token.LOR {
				complexity++
			}
		}
		return true
	})
	return complexity
}

// maxNestingDepth returns the maximum nesting depth reached inside the given
// block statement. The depth increments by 1 for each IfStmt, ForStmt,
// RangeStmt, SwitchStmt, TypeSwitchStmt, and SelectStmt encountered.
func maxNestingDepth(body *ast.BlockStmt) int {
	if body == nil {
		return 0
	}
	max := 0
	walkDepth(body, 0, &max)
	return max
}

// walkDepth recursively walks AST nodes tracking nesting depth.
func walkDepth(node ast.Node, current int, max *int) {
	if current > *max {
		*max = current
	}

	switch n := node.(type) {
	case *ast.IfStmt:
		next := current + 1
		if next > *max {
			*max = next
		}
		walkDepth(n.Body, next, max)
		if n.Else != nil {
			// An else-if block should not add another depth level for the else
			// itself; the inner IfStmt will add its own +1.
			switch el := n.Else.(type) {
			case *ast.BlockStmt:
				walkDepth(el, next, max)
			case *ast.IfStmt:
				walkDepth(el, current, max)
			}
		}

	case *ast.ForStmt:
		next := current + 1
		if next > *max {
			*max = next
		}
		walkDepth(n.Body, next, max)

	case *ast.RangeStmt:
		next := current + 1
		if next > *max {
			*max = next
		}
		walkDepth(n.Body, next, max)

	case *ast.SwitchStmt:
		next := current + 1
		if next > *max {
			*max = next
		}
		walkDepth(n.Body, next, max)

	case *ast.TypeSwitchStmt:
		next := current + 1
		if next > *max {
			*max = next
		}
		walkDepth(n.Body, next, max)

	case *ast.SelectStmt:
		next := current + 1
		if next > *max {
			*max = next
		}
		walkDepth(n.Body, next, max)

	case *ast.BlockStmt:
		if n != nil {
			for _, stmt := range n.List {
				walkDepth(stmt, current, max)
			}
		}

	case *ast.CaseClause:
		for _, stmt := range n.Body {
			walkDepth(stmt, current, max)
		}

	case *ast.CommClause:
		for _, stmt := range n.Body {
			walkDepth(stmt, current, max)
		}
	}
}

// countParams returns the total number of named parameters in a function
// declaration. Each field in the parameter list may declare multiple names
// (e.g. "a, b int" counts as 2), so we sum len(field.Names) for each field.
// An unnamed parameter (e.g. a type-only param) contributes 1.
func countParams(fn *ast.FuncDecl) int {
	if fn.Type == nil || fn.Type.Params == nil {
		return 0
	}
	count := 0
	for _, field := range fn.Type.Params.List {
		if len(field.Names) == 0 {
			// Type-only parameter (e.g. in an interface method signature).
			count++
		} else {
			count += len(field.Names)
		}
	}
	return count
}

func init() {
	analyzer.Register(New())
}
