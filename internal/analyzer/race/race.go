// Package race implements the race condition analyzer for go-analyzer.
// It detects common concurrency bugs via AST inspection and optionally
// wraps `go test -race` for additional data-race detection.
package race

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rahul-aut-ind/go-analyzer/internal/analyzer"
)

// raceAnalyzer detects race conditions in Go source code.
type raceAnalyzer struct{}

// New returns a new race condition Analyzer.
func New() analyzer.Analyzer { return &raceAnalyzer{} }

// Name returns the analyzer's short identifier.
func (a *raceAnalyzer) Name() string { return "race" }

// Description returns a one-line summary of what this analyzer checks.
func (a *raceAnalyzer) Description() string {
	return "Detects race conditions: loop variable capture, unguarded map writes, non-atomic increments, and WaitGroup misuse"
}

// Run executes race condition detection on the Go module at dir.
func (a *raceAnalyzer) Run(dir string) ([]analyzer.Finding, error) {
	return runRaceAnalysis(dir)
}

func init() {
	analyzer.Register(New())
}

// runRaceAnalysis is the top-level analysis entry point.
// It walks all .go files under dir, inspects the AST for concurrency patterns,
// then optionally runs `go test -race ./...` and merges the results.
func runRaceAnalysis(dir string) ([]analyzer.Finding, error) {
	goFiles, err := collectGoFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("collecting go files: %w", err)
	}
	if len(goFiles) == 0 {
		return nil, nil
	}

	fset := token.NewFileSet()
	var astFindings []analyzer.Finding

	for _, path := range goFiles {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			// Skip files that do not parse (generated, cgo, etc.).
			continue
		}
		astFindings = append(astFindings, inspectFile(fset, f, path)...)
	}

	raceFindings := runGoTestRace(dir)

	merged := mergeFindings(astFindings, raceFindings)
	return merged, nil
}

// collectGoFiles returns every .go file (excluding _test.go) under dir.
func collectGoFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			// Skip hidden dirs and vendor.
			name := d.Name()
			if name == "vendor" || (len(name) > 0 && name[0] == '.') {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// inspectFile walks the AST of a single parsed file and returns findings.
func inspectFile(fset *token.FileSet, f *ast.File, filePath string) []analyzer.Finding {
	var findings []analyzer.Finding

	ast.Inspect(f, func(n ast.Node) bool {
		goStmt, ok := n.(*ast.GoStmt)
		if !ok {
			return true
		}

		// Extract the function literal that is the goroutine body.
		fn := extractFuncLit(goStmt.Call)
		if fn == nil {
			return true
		}

		// Determine what variables are passed as arguments (not captured).
		argVars := collectArgVarNames(goStmt.Call)

		// Walk enclosing context for RACE001: loop variable capture.
		findings = append(findings, checkLoopCapture(fset, f, goStmt, fn, filePath, argVars)...)

		// Walk goroutine body for RACE002: map write without mutex.
		findings = append(findings, checkMapWrite(fset, fn, filePath)...)

		// Walk goroutine body for RACE003: non-atomic increment/decrement.
		findings = append(findings, checkNonAtomicIncDec(fset, fn, filePath)...)

		// Walk goroutine body for RACE004: WaitGroup.Add inside goroutine.
		findings = append(findings, checkWaitGroupAdd(fset, fn, filePath)...)

		return true
	})

	return findings
}

// extractFuncLit returns the *ast.FuncLit from a call expression if the
// function being called is an inline literal, e.g. `go func() { ... }()`.
func extractFuncLit(call *ast.CallExpr) *ast.FuncLit {
	if call == nil {
		return nil
	}
	fl, ok := call.Fun.(*ast.FuncLit)
	if !ok {
		return nil
	}
	return fl
}

// collectArgVarNames returns a set of identifier names that are passed as
// arguments to the goroutine call, i.e. variables that are NOT closured.
func collectArgVarNames(call *ast.CallExpr) map[string]bool {
	args := make(map[string]bool)
	for _, arg := range call.Args {
		if id, ok := arg.(*ast.Ident); ok {
			args[id.Name] = true
		}
	}
	return args
}

// ---- RACE001 ---------------------------------------------------------------

// loopVarInfo holds information about a range/for loop and its iteration
// variables so we can detect closure capture.
type loopVarInfo struct {
	vars    []string
	forStmt ast.Node // *ast.RangeStmt or *ast.ForStmt
}

// checkLoopCapture detects RACE001: a goroutine closure that captures a loop
// variable by reference instead of shadowing/passing it as an argument.
func checkLoopCapture(
	fset *token.FileSet,
	f *ast.File,
	goStmt *ast.GoStmt,
	fn *ast.FuncLit,
	filePath string,
	argVars map[string]bool,
) []analyzer.Finding {
	// Find all loop variables declared in for/range statements that are
	// ancestors of this goStmt in the file AST.
	loopVars := collectEnclosingLoopVars(f, goStmt)
	if len(loopVars) == 0 {
		return nil
	}

	// Collect variables referenced inside the goroutine body.
	referenced := collectReferencedIdents(fn.Body)

	var findings []analyzer.Finding
	for _, lv := range loopVars {
		for _, varName := range lv.vars {
			if referenced[varName] && !argVars[varName] {
				pos := fset.Position(goStmt.Pos())
				findings = append(findings, analyzer.Finding{
					RuleID:   "RACE001",
					Severity: "high",
					Message:  fmt.Sprintf("goroutine closure captures loop variable %q by reference", varName),
					File:     filePath,
					Line:     pos.Line,
					Column:   pos.Column,
					Suggestion: fmt.Sprintf(
						"shadow the variable before the goroutine: `%s := %s` or pass it as a parameter",
						varName, varName,
					),
				})
				break // one finding per goroutine is enough
			}
		}
	}
	return findings
}

// collectEnclosingLoopVars walks the file AST and returns all loop variable
// sets whose for/range statement is an ancestor of target.
func collectEnclosingLoopVars(f *ast.File, target ast.Node) []loopVarInfo {
	// Build an ancestor set: walk and record the path to target.
	path := findPath(f, target)
	if len(path) == 0 {
		return nil
	}

	ancestorSet := make(map[ast.Node]bool, len(path))
	for _, n := range path {
		ancestorSet[n] = true
	}

	var result []loopVarInfo
	for _, ancestor := range path {
		switch stmt := ancestor.(type) {
		case *ast.RangeStmt:
			var vars []string
			if stmt.Key != nil {
				if id, ok := stmt.Key.(*ast.Ident); ok && id.Name != "_" {
					vars = append(vars, id.Name)
				}
			}
			if stmt.Value != nil {
				if id, ok := stmt.Value.(*ast.Ident); ok && id.Name != "_" {
					vars = append(vars, id.Name)
				}
			}
			if len(vars) > 0 {
				result = append(result, loopVarInfo{vars: vars, forStmt: stmt})
			}
		case *ast.ForStmt:
			// Classic for with init; look for short-var-decl in Init.
			if stmt.Init != nil {
				if assign, ok := stmt.Init.(*ast.AssignStmt); ok && assign.Tok == token.DEFINE {
					var vars []string
					for _, lhs := range assign.Lhs {
						if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" {
							vars = append(vars, id.Name)
						}
					}
					if len(vars) > 0 {
						result = append(result, loopVarInfo{vars: vars, forStmt: stmt})
					}
				}
			}
		}
	}
	return result
}

// findPath returns the list of AST nodes from root down to target (inclusive),
// or nil if target is not found.
func findPath(root ast.Node, target ast.Node) []ast.Node {
	var path []ast.Node
	var found bool

	var walk func(n ast.Node) bool
	walk = func(n ast.Node) bool {
		if n == nil {
			return false
		}
		path = append(path, n)
		if n == target {
			found = true
			return false // stop walking children
		}
		ast.Inspect(n, func(child ast.Node) bool {
			if child == nil || child == n {
				return true
			}
			return walk(child)
		})
		if !found {
			path = path[:len(path)-1]
		}
		return !found
	}

	// We use a manual DFS because ast.Inspect doesn't track paths.
	walkFile(root, target, &path, &found)
	if found {
		return path
	}
	return nil
}

// walkFile is a path-tracking DFS over any AST node.
func walkFile(n ast.Node, target ast.Node, path *[]ast.Node, found *bool) {
	if n == nil || *found {
		return
	}
	*path = append(*path, n)
	if n == target {
		*found = true
		return
	}
	ast.Inspect(n, func(child ast.Node) bool {
		if *found {
			return false
		}
		if child == nil || child == n {
			return true
		}
		walkFile(child, target, path, found)
		return false // we handle recursion ourselves
	})
	if !*found {
		*path = (*path)[:len(*path)-1]
	}
}

// collectReferencedIdents returns a set of all identifier names used inside
// the given block statement.
func collectReferencedIdents(block *ast.BlockStmt) map[string]bool {
	refs := make(map[string]bool)
	ast.Inspect(block, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if ok {
			refs[id.Name] = true
		}
		return true
	})
	return refs
}

// ---- RACE002 ---------------------------------------------------------------

// checkMapWrite detects RACE002: a map assignment inside a goroutine body
// with no surrounding mutex lock.
func checkMapWrite(fset *token.FileSet, fn *ast.FuncLit, filePath string) []analyzer.Finding {
	var findings []analyzer.Finding

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		// Any of the LHS targets that are index expressions indicate a map/slice write.
		for _, lhs := range assign.Lhs {
			if _, ok := lhs.(*ast.IndexExpr); ok {
				pos := fset.Position(assign.Pos())
				findings = append(findings, analyzer.Finding{
					RuleID:   "RACE002",
					Severity: "high",
					Message:  "map or slice write in goroutine without mutex protection",
					File:     filePath,
					Line:     pos.Line,
					Column:   pos.Column,
					Suggestion: "protect the map/slice access with a sync.Mutex or use sync.Map for concurrent writes",
				})
				break
			}
		}
		return true
	})

	return findings
}

// ---- RACE003 ---------------------------------------------------------------

// checkNonAtomicIncDec detects RACE003: use of ++ or -- on a shared variable
// inside a goroutine without atomic operations.
func checkNonAtomicIncDec(fset *token.FileSet, fn *ast.FuncLit, filePath string) []analyzer.Finding {
	var findings []analyzer.Finding

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		inc, ok := n.(*ast.IncDecStmt)
		if !ok {
			return true
		}
		// We flag any ++ or -- inside a goroutine.
		varName := exprName(inc.X)
		op := "++"
		if inc.Tok == token.DEC {
			op = "--"
		}
		msg := fmt.Sprintf("non-atomic %s of variable %q in goroutine; data race possible", op, varName)
		pos := fset.Position(inc.Pos())
		findings = append(findings, analyzer.Finding{
			RuleID:   "RACE003",
			Severity: "high",
			Message:  msg,
			File:     filePath,
			Line:     pos.Line,
			Column:   pos.Column,
			Suggestion: "use sync/atomic operations (e.g., atomic.AddInt64) or protect with a sync.Mutex",
		})
		return true
	})

	return findings
}

// exprName returns a best-effort string representation of an expression for use
// in diagnostic messages.
func exprName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprName(e.X) + "." + e.Sel.Name
	case *ast.IndexExpr:
		return exprName(e.X) + "[...]"
	default:
		return "<expr>"
	}
}

// ---- RACE004 ---------------------------------------------------------------

// checkWaitGroupAdd detects RACE004: a call to (*sync.WaitGroup).Add inside
// the goroutine body itself (it should be called before launching the goroutine).
func checkWaitGroupAdd(fset *token.FileSet, fn *ast.FuncLit, filePath string) []analyzer.Finding {
	var findings []analyzer.Finding

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name == "Add" {
			// Check whether the receiver looks like a WaitGroup.
			// We use a heuristic: the type name or variable name contains "wg" or "WaitGroup".
			receiver := exprName(sel.X)
			lowerReceiver := strings.ToLower(receiver)
			if strings.Contains(lowerReceiver, "wg") || strings.Contains(lowerReceiver, "waitgroup") {
				pos := fset.Position(call.Pos())
				findings = append(findings, analyzer.Finding{
					RuleID:   "RACE004",
					Severity: "medium",
					Message:  fmt.Sprintf("sync.WaitGroup.Add called inside goroutine on %q; may cause WaitGroup reuse race", receiver),
					File:     filePath,
					Line:     pos.Line,
					Column:   pos.Column,
					Suggestion: "call wg.Add(1) before the `go` statement, not inside the goroutine body",
				})
			}
		}
		return true
	})

	return findings
}

// ---- go test -race subprocess -----------------------------------------------

// raceOutputRe matches lines of the form:
//
//	    /path/to/file.go:42 +0x...
//
// in the output of `go test -race`.
var raceOutputRe = regexp.MustCompile(`^\s+(.+\.go):(\d+)`)

// runGoTestRace executes `go test -race ./...` in dir and parses its stderr
// for data race reports. It returns findings for each unique file:line pair
// reported. Errors (missing go.mod, no test files, etc.) are silently ignored
// so the subprocess step is always best-effort.
func runGoTestRace(dir string) []analyzer.Finding {
	// Verify the directory has a go.mod so we don't waste time.
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	//nolint:gosec // dir is validated above; this is an analysis tool
	cmd := exec.CommandContext(ctx, "go", "test", "-race", "./...")
	cmd.Dir = dir

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// Ignore the exit code; non-zero just means tests failed or races found.
	_ = cmd.Run()

	return parseRaceOutput(stderr.String(), dir)
}

// parseRaceOutput parses the text output of `go test -race` and converts data
// race reports into Finding values.
func parseRaceOutput(output, dir string) []analyzer.Finding {
	var findings []analyzer.Finding
	seen := make(map[string]bool)

	inRaceReport := false
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		// Detect beginning of a DATA RACE block.
		if strings.Contains(line, "DATA RACE") {
			inRaceReport = true
			continue
		}
		// A blank line ends the race report block.
		if inRaceReport && strings.TrimSpace(line) == "" {
			inRaceReport = false
			continue
		}

		if !inRaceReport {
			continue
		}

		m := raceOutputRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		filePath := m[1]
		lineNo, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}

		// Make the path absolute if it is not already.
		if !filepath.IsAbs(filePath) {
			filePath = filepath.Join(dir, filePath)
		}

		key := fmt.Sprintf("%s:%d", filePath, lineNo)
		if seen[key] {
			continue
		}
		seen[key] = true

		findings = append(findings, analyzer.Finding{
			RuleID:     "RACE000",
			Severity:   "high",
			Message:    "data race detected by go test -race",
			File:       filePath,
			Line:       lineNo,
			Column:     1,
			Suggestion: "use synchronization primitives (sync.Mutex, channels, sync/atomic) to protect shared state",
		})
	}

	return findings
}

// ---- deduplication ----------------------------------------------------------

// dedupKey is the unique identity of a finding for deduplication purposes.
type dedupKey struct {
	file   string
	line   int
	ruleID string
}

// mergeFindings combines AST-based findings with those from `go test -race`,
// deduplicating entries that share the same file, line, and rule ID.
func mergeFindings(astFindings, raceFindings []analyzer.Finding) []analyzer.Finding {
	seen := make(map[dedupKey]bool)
	var out []analyzer.Finding

	for _, f := range append(astFindings, raceFindings...) {
		k := dedupKey{file: f.File, line: f.Line, ruleID: f.RuleID}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}
