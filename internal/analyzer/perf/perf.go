// Package perf implements the performance analyzer for go-analyzer.
// It detects common Go performance anti-patterns via pure AST inspection
// using go/ast, go/token, and go/parser — no subprocess calls are made.
//
// Rules detected:
//
//	PERF001 – string concatenation with + inside a loop body
//	PERF002 – regexp.MustCompile / regexp.Compile called inside a function body
//	PERF003 – defer statement inside a for loop
//	PERF004 – append() inside a loop without a prior make() with capacity
//	PERF005 – large struct (>5 fields) passed by value to a function
//	PERF006 – fmt.Sprintf used for single-variable type conversion
package perf

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"github.com/rahul-aut-ind/go-analyzer/internal/analyzer"
)

// perfAnalyzer is the concrete type that implements the performance analyzer.
type perfAnalyzer struct{}

// New returns a new performance Analyzer ready for registration.
func New() analyzer.Analyzer { return &perfAnalyzer{} }

// Name returns the short identifier used for this analyzer in the registry.
func (a *perfAnalyzer) Name() string { return "perf" }

// Description returns a one-line summary of the checks performed.
func (a *perfAnalyzer) Description() string {
	return "Detects performance anti-patterns: string concat in loops, regexp inside functions, defer in loops, append without pre-allocation, large struct pass-by-value, and redundant fmt.Sprintf"
}

// Run executes the performance analysis on every .go file found under dir,
// skipping vendor/ and testdata/ directories. It returns all findings
// collected across all files, or an error if the directory cannot be walked.
func (a *perfAnalyzer) Run(dir string) ([]analyzer.Finding, error) {
	var findings []analyzer.Finding

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories that are conventionally excluded from analysis.
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
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			// Skip files that cannot be parsed (e.g. cgo files with unsupported directives).
			return nil
		}

		findings = append(findings, analyzeFile(fset, file, path)...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking directory %s: %w", dir, err)
	}

	return findings, nil
}

// analyzeFile runs all rule checks against a single parsed AST file and
// returns the combined list of findings.
func analyzeFile(fset *token.FileSet, file *ast.File, path string) []analyzer.Finding {
	var findings []analyzer.Finding

	findings = append(findings, checkPERF002(fset, file, path)...)
	findings = append(findings, checkPERF005(fset, file, path)...)
	findings = append(findings, checkPERF006(fset, file, path)...)

	// Rules PERF001, PERF003, PERF004 are checked inside each FuncDecl.
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		findings = append(findings, checkLoopRules(fset, fn, path)...)
	}

	return findings
}

// ── PERF001 ─────────────────────────────────────────────────────────────────

// checkLoopRules walks every for/range loop inside fn and applies
// PERF001 (string concatenation), PERF003 (defer in loop), and
// PERF004 (append without pre-allocation).
func checkLoopRules(fset *token.FileSet, fn *ast.FuncDecl, path string) []analyzer.Finding {
	var findings []analyzer.Finding

	// Collect all make() call positions in the function so PERF004 can
	// determine whether a capacity hint was provided before the loop.
	makePositions := collectMakeWithCap(fn.Body)

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		var loopBody *ast.BlockStmt
		var loopPos token.Pos

		switch stmt := n.(type) {
		case *ast.ForStmt:
			loopBody = stmt.Body
			loopPos = stmt.For
		case *ast.RangeStmt:
			loopBody = stmt.Body
			loopPos = stmt.For
		default:
			return true
		}

		if loopBody == nil {
			return true
		}

		findings = append(findings, checkPERF001InLoop(fset, loopBody, path)...)
		findings = append(findings, checkPERF003InLoop(fset, loopBody, path)...)
		findings = append(findings, checkPERF004InLoop(fset, loopBody, path, loopPos, makePositions)...)

		// Do not descend further — nested loops will be visited by the outer
		// ast.Inspect call when it reaches them.
		return true
	})

	return findings
}

// checkPERF001InLoop looks for string concatenation (= x + y or += y where
// the result involves a string) inside the direct statements of a loop body.
func checkPERF001InLoop(fset *token.FileSet, body *ast.BlockStmt, path string) []analyzer.Finding {
	var findings []analyzer.Finding

	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}

		switch assign.Tok {
		case token.ADD_ASSIGN: // result += item
			// Any += on a string variable is a concatenation.
			// We conservatively flag all += inside loops; type info would be
			// needed for perfect precision, but pure-AST heuristics suffice.
			pos := fset.Position(assign.TokPos)
			findings = append(findings, analyzer.Finding{
				RuleID:     "PERF001",
				Severity:   "medium",
				Message:    "string concatenation with += inside a loop; consider using strings.Builder",
				File:       path,
				Line:       pos.Line,
				Column:     pos.Column,
				Suggestion: "Replace += loop with strings.Builder.WriteString for O(1) amortised allocation",
			})

		case token.ASSIGN: // result = result + item
			for _, rhs := range assign.Rhs {
				if isStringAddBinaryExpr(rhs) {
					pos := fset.Position(assign.TokPos)
					findings = append(findings, analyzer.Finding{
						RuleID:     "PERF001",
						Severity:   "medium",
						Message:    "string concatenation with + inside a loop; consider using strings.Builder",
						File:       path,
						Line:       pos.Line,
						Column:     pos.Column,
						Suggestion: "Replace + loop with strings.Builder.WriteString for O(1) amortised allocation",
					})
				}
			}
		}

		return true
	})

	return findings
}

// isStringAddBinaryExpr returns true if expr is a BinaryExpr with Op == ADD.
// We cannot resolve types without go/types, so we accept any ADD expression
// inside a loop body as a potential string concatenation.
func isStringAddBinaryExpr(expr ast.Expr) bool {
	bin, ok := expr.(*ast.BinaryExpr)
	return ok && bin.Op == token.ADD
}

// ── PERF002 ─────────────────────────────────────────────────────────────────

// checkPERF002 detects calls to regexp.MustCompile or regexp.Compile that
// appear inside a function body (as opposed to package-level var initialisers).
func checkPERF002(fset *token.FileSet, file *ast.File, path string) []analyzer.Finding {
	var findings []analyzer.Finding

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			if isRegexpCompileCall(call) {
				pos := fset.Position(call.Pos())
				findings = append(findings, analyzer.Finding{
					RuleID:     "PERF002",
					Severity:   "medium",
					Message:    "regexp compiled inside a function body; move to a package-level var",
					File:       path,
					Line:       pos.Line,
					Column:     pos.Column,
					Suggestion: "Declare `var re = regexp.MustCompile(...)` at package level to compile once",
				})
			}
			return true
		})
	}

	return findings
}

// isRegexpCompileCall returns true if call is regexp.MustCompile(…) or
// regexp.Compile(…).
func isRegexpCompileCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "regexp" &&
		(sel.Sel.Name == "MustCompile" || sel.Sel.Name == "Compile")
}

// ── PERF003 ─────────────────────────────────────────────────────────────────

// checkPERF003InLoop looks for DeferStmt nodes directly inside a loop body.
func checkPERF003InLoop(fset *token.FileSet, body *ast.BlockStmt, path string) []analyzer.Finding {
	var findings []analyzer.Finding

	ast.Inspect(body, func(n ast.Node) bool {
		d, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}
		pos := fset.Position(d.Defer)
		findings = append(findings, analyzer.Finding{
			RuleID:     "PERF003",
			Severity:   "low",
			Message:    "defer inside a for loop; deferred calls execute only when the surrounding function returns, not each iteration",
			File:       path,
			Line:       pos.Line,
			Column:     pos.Column,
			Suggestion: "Move defer out of the loop, or extract the loop body into a helper function",
		})
		return true
	})

	return findings
}

// ── PERF004 ─────────────────────────────────────────────────────────────────

// collectMakeWithCap returns the token.Pos of every make() call that includes
// a capacity argument (i.e. make(T, len, cap) or make([]T, 0, cap)).
func collectMakeWithCap(body *ast.BlockStmt) map[token.Pos]struct{} {
	positions := make(map[token.Pos]struct{})
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn, ok := call.Fun.(*ast.Ident)
		if !ok || fn.Name != "make" {
			return true
		}
		// make(T, len, cap) has 3 args; make([]T, 0) has 2 (no pre-alloc cap).
		if len(call.Args) >= 3 {
			positions[call.Pos()] = struct{}{}
		}
		return true
	})
	return positions
}

// checkPERF004InLoop flags append() calls inside a loop when there is no
// preceding make() with a capacity argument in the enclosing function body.
func checkPERF004InLoop(fset *token.FileSet, body *ast.BlockStmt, path string, loopPos token.Pos, makePositions map[token.Pos]struct{}) []analyzer.Finding {
	var findings []analyzer.Finding

	// Determine whether any make-with-cap appears before this loop.
	hasMakeBefore := false
	for pos := range makePositions {
		if pos < loopPos {
			hasMakeBefore = true
			break
		}
	}

	if hasMakeBefore {
		return findings
	}

	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn, ok := call.Fun.(*ast.Ident)
		if !ok || fn.Name != "append" {
			return true
		}
		pos := fset.Position(call.Pos())
		findings = append(findings, analyzer.Finding{
			RuleID:     "PERF004",
			Severity:   "low",
			Message:    "append() inside a loop without prior make() with capacity; consider pre-allocating the slice",
			File:       path,
			Line:       pos.Line,
			Column:     pos.Column,
			Suggestion: "Use make([]T, 0, expectedLen) before the loop to avoid repeated slice reallocations",
		})
		return true
	})

	return findings
}

// ── PERF005 ─────────────────────────────────────────────────────────────────

// checkPERF005 flags function parameters whose type is a struct literal with
// more than 5 fields when the parameter is passed by value (not a pointer).
func checkPERF005(fset *token.FileSet, file *ast.File, path string) []analyzer.Finding {
	var findings []analyzer.Finding

	// Build a map from struct type name → field count for all TypeSpecs in
	// this file so we can look up named types used in function signatures.
	structFieldCounts := collectStructFieldCounts(file)

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Type == nil || fn.Type.Params == nil {
			continue
		}

		for _, field := range fn.Type.Params.List {
			fieldCount := 0

			switch t := field.Type.(type) {
			case *ast.StructType:
				// Inline anonymous struct type — sum names across field entries.
				if t.Fields != nil {
					for _, sf := range t.Fields.List {
						if len(sf.Names) == 0 {
							fieldCount++ // embedded field
						} else {
							fieldCount += len(sf.Names)
						}
					}
				}
			case *ast.Ident:
				// Named type — look up the struct definition.
				fieldCount = structFieldCounts[t.Name]
			case *ast.StarExpr:
				// Pointer — already indirect, skip.
				continue
			}

			if fieldCount > 5 {
				pos := fset.Position(field.Pos())
				// Determine a readable name for the parameter.
				paramName := ""
				if len(field.Names) > 0 {
					paramName = field.Names[0].Name + " "
				}
				typeName := typeExprName(field.Type)
				findings = append(findings, analyzer.Finding{
					RuleID:   "PERF005",
					Severity: "low",
					Message: fmt.Sprintf(
						"parameter %s(%s) is a struct with %d fields passed by value; consider using a pointer",
						paramName, typeName, fieldCount,
					),
					File:       path,
					Line:       pos.Line,
					Column:     pos.Column,
					Suggestion: "Pass large structs by pointer (*T) to avoid copying all fields on each call",
				})
			}
		}
	}

	return findings
}

// collectStructFieldCounts returns a map of struct type name → number of
// fields for every struct TypeSpec declared in file.
//
// Note: a single *ast.Field entry may declare multiple names (e.g.
// "A, B, C int" is one Field with three Names), so we must sum
// len(field.Names) across all entries rather than using len(Fields.List).
// Embedded (anonymous) fields have no Names, so they count as 1.
func collectStructFieldCounts(file *ast.File) map[string]int {
	counts := make(map[string]int)
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range genDecl.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || st.Fields == nil {
				continue
			}
			count := 0
			for _, f := range st.Fields.List {
				if len(f.Names) == 0 {
					// Embedded (anonymous) field counts as one.
					count++
				} else {
					count += len(f.Names)
				}
			}
			counts[ts.Name.Name] = count
		}
	}
	return counts
}

// typeExprName returns a short string representation of a type expression,
// used for human-readable messages in PERF005 findings.
func typeExprName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StructType:
		return "struct{...}"
	case *ast.StarExpr:
		return "*" + typeExprName(t.X)
	case *ast.SelectorExpr:
		return typeExprName(t.X) + "." + t.Sel.Name
	default:
		return "?"
	}
}

// ── PERF006 ─────────────────────────────────────────────────────────────────

// singleVerbFormats lists format verbs whose only purpose is converting a
// single value to a string. Using fmt.Sprintf with these verbs when a simpler
// conversion is available (strconv, fmt.Sprint, etc.) is wasteful.
var singleVerbFormats = map[string]bool{
	"%v": true,
	"%s": true,
	"%d": true,
	"%f": true,
	"%g": true,
	"%e": true,
	"%t": true,
	"%b": true,
	"%o": true,
	"%x": true,
	"%X": true,
	"%q": true,
}

// checkPERF006 flags calls to fmt.Sprintf(verb, singleArg) where the format
// string is a plain single conversion verb.
func checkPERF006(fset *token.FileSet, file *ast.File, path string) []analyzer.Finding {
	var findings []analyzer.Finding

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		if !isFmtSprintfCall(call) {
			return true
		}

		// fmt.Sprintf must have at least 2 args: format + one value.
		if len(call.Args) != 2 {
			return true
		}

		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}

		// Strip the surrounding quotes from the string literal.
		raw := lit.Value
		if len(raw) >= 2 {
			raw = raw[1 : len(raw)-1]
		}

		if singleVerbFormats[raw] {
			pos := fset.Position(call.Pos())
			findings = append(findings, analyzer.Finding{
				RuleID:     "PERF006",
				Severity:   "info",
				Message:    fmt.Sprintf("fmt.Sprintf(%q, x) used for single-value conversion; use a type-specific conversion instead", raw),
				File:       path,
				Line:       pos.Line,
				Column:     pos.Column,
				Suggestion: "Use strconv.Itoa / strconv.FormatFloat / fmt.Sprint(x) / string(x) as appropriate",
			})
		}

		return true
	})

	return findings
}

// isFmtSprintfCall returns true if call is fmt.Sprintf(…).
func isFmtSprintfCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "fmt" && sel.Sel.Name == "Sprintf"
}

// ── Registration ─────────────────────────────────────────────────────────────

func init() {
	analyzer.Register(New())
}
