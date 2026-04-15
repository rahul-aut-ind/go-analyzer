// Package coverage implements a test-coverage analyzer for go-analyzer.
// It runs `go test -coverprofile` on the target module, parses the resulting
// profile, flags exported functions with zero coverage and packages below the
// configured minimum, and persists a history file so that delta/trend
// information is included in subsequent run findings.
package coverage

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rahul-aut-ind/go-analyzer/internal/analyzer"
)

// CoverageMinimum is the package-level coverage percentage below which a
// COV002 finding is emitted. It defaults to 80 and may be overridden by
// tests or callers.
var CoverageMinimum = 80.0

// historyDir is the sub-directory (relative to the analysed module root) in
// which history snapshots are stored.
const historyDir = ".goanalyzer/history"

// coverageAnalyzer is the concrete implementation of analyzer.Analyzer.
type coverageAnalyzer struct{}

// New returns a new coverage Analyzer ready for use.
func New() analyzer.Analyzer { return &coverageAnalyzer{} }

// Name returns the short identifier for this analyzer.
func (a *coverageAnalyzer) Name() string { return "coverage" }

// Description returns a one-line summary of what this analyzer checks.
func (a *coverageAnalyzer) Description() string {
	return "Runs go test -coverprofile and flags exported functions with 0% coverage and packages below the coverage minimum"
}

// Run executes coverage analysis on the Go module rooted at dir.
func (a *coverageAnalyzer) Run(dir string) ([]analyzer.Finding, error) {
	return runCoverageAnalysis(dir)
}

func init() { analyzer.Register(New()) }

// coverBlock represents a single statement range from the coverprofile.
type coverBlock struct {
	File      string
	StartLine int
	EndLine   int
	NumStmts  int
	Count     int // 0 = not covered
}

// fileLineKey is the composite key used to look up coverage by (file, line).
type fileLineKey struct {
	file string
	line int
}

// funcInfo holds metadata about a parsed Go function declaration.
type funcInfo struct {
	Name      string
	StartLine int
	EndLine   int
	Exported  bool
}

// packageCoverage holds the aggregate coverage data for a Go package.
type packageCoverage struct {
	// TotalStmts is the total number of statements in the package.
	TotalStmts int
	// CoveredStmts is the number of statements executed at least once.
	CoveredStmts int
}

// Pct returns the coverage percentage (0–100).
func (p packageCoverage) Pct() float64 {
	if p.TotalStmts == 0 {
		return 100.0
	}
	return float64(p.CoveredStmts) / float64(p.TotalStmts) * 100.0
}

// HistoryEntry is the JSON schema for a single history snapshot.
type HistoryEntry struct {
	// Timestamp is the RFC3339 timestamp of the run.
	Timestamp string `json:"timestamp"`
	// PackageCoverage maps package import paths to coverage percentages.
	PackageCoverage map[string]float64 `json:"package_coverage"`
}

// runCoverageAnalysis is the top-level entry point.
func runCoverageAnalysis(dir string) ([]analyzer.Finding, error) {
	profilePath, cleanup, err := runGoTest(dir)
	if err != nil {
		// go test itself failed (compilation error, no .go files, etc.)
		// Return empty findings with a warning.
		return []analyzer.Finding{
			{
				RuleID:     "COV000",
				Severity:   "info",
				Message:    fmt.Sprintf("coverage analysis skipped: %v", err),
				File:       ".",
				Suggestion: "ensure the module compiles and has at least one test file",
			},
		}, nil
	}
	defer cleanup()

	blocks, err := parseCoverProfile(profilePath)
	if err != nil {
		return nil, fmt.Errorf("parsing coverprofile: %w", err)
	}

	pkgCoverage, err := computePackageCoverage(blocks, dir)
	if err != nil {
		return nil, fmt.Errorf("computing package coverage: %w", err)
	}

	// Load previous history to compute deltas.
	prev, _ := loadLastHistory(dir) // ignore error; no history is fine

	// Persist current run.
	if saveErr := saveHistory(dir, pkgCoverage); saveErr != nil {
		// Non-fatal: just continue without history persistence.
		_ = saveErr
	}

	var findings []analyzer.Finding

	// COV001: exported functions with 0% coverage.
	cov001, err := findUncoveredExports(blocks, dir)
	if err != nil {
		// Non-fatal; best-effort.
		_ = err
	}
	findings = append(findings, cov001...)

	// COV002: packages below minimum.
	for pkg, cov := range pkgCoverage {
		pct := cov.Pct()
		if pct < CoverageMinimum {
			msg := fmt.Sprintf("package %s has %.1f%% coverage (below %.0f%% minimum)", pkg, pct, CoverageMinimum)

			// Append trend if history is available.
			if prev != nil {
				if prevPct, ok := prev.PackageCoverage[pkg]; ok {
					delta := pct - prevPct
					switch {
					case delta > 0:
						msg += fmt.Sprintf(" [trend: +%.1f%% since last run]", delta)
					case delta < 0:
						msg += fmt.Sprintf(" [trend: %.1f%% since last run]", delta)
					default:
						msg += " [trend: no change since last run]"
					}
				}
			}

			findings = append(findings, analyzer.Finding{
				RuleID:     "COV002",
				Severity:   "high",
				Message:    msg,
				File:       pkg,
				Suggestion: fmt.Sprintf("add tests to bring %s coverage above %.0f%%", pkg, CoverageMinimum),
			})
		}
	}

	return findings, nil
}

// runGoTest executes `go test -coverprofile=<tmp> ./...` in dir and returns
// the path to the profile file, a cleanup function, and any error.
// On failure it still returns a cleanup that is safe to call.
func runGoTest(dir string) (profilePath string, cleanup func(), err error) {
	tmp, err := os.CreateTemp("", "goanalyzer-cover-*.out")
	if err != nil {
		return "", func() {}, fmt.Errorf("creating temp file: %w", err)
	}
	tmp.Close()
	profilePath = tmp.Name()
	cleanup = func() { _ = os.Remove(profilePath) }

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	//nolint:gosec // dir is validated by the caller; this is an analysis tool
	cmd := exec.CommandContext(ctx, "go", "test", "-coverprofile="+profilePath, "./...")
	cmd.Dir = dir

	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		// Check whether the profile contains real coverage blocks (beyond the
		// mode header). A file with only "mode: set\n" (no actual data) means
		// go test didn't process any packages, so treat it as a full failure.
		hasBlocks := profileHasCoverageBlocks(profilePath)
		if !hasBlocks {
			return profilePath, cleanup, fmt.Errorf("go test failed: %w\n%s", runErr, out)
		}
	}
	return profilePath, cleanup, nil
}

// profileHasCoverageBlocks returns true if the coverage profile at path
// contains at least one data line (beyond the "mode: ..." header).
func profileHasCoverageBlocks(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	lines := 0
	for sc.Scan() {
		lines++
		if lines > 1 { // first line is the mode header
			return true
		}
	}
	return false
}

// parseCoverProfile reads the Go coverage profile file and returns all coverage
// blocks. The first line (mode: ...) is skipped.
//
// Each subsequent line has the format:
//
//	<file>:<startline>.<startcol>,<endline>.<endcol> <numstmts> <count>
func parseCoverProfile(path string) ([]coverBlock, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening coverprofile: %w", err)
	}
	defer f.Close()

	var blocks []coverBlock
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || lineNum == 1 {
			// Skip empty lines and the "mode: ..." header.
			continue
		}
		b, err := parseCoverLine(line)
		if err != nil {
			// Skip malformed lines.
			continue
		}
		blocks = append(blocks, b)
	}
	return blocks, scanner.Err()
}

// parseCoverLine parses a single coverprofile data line.
func parseCoverLine(line string) (coverBlock, error) {
	// Format: <file>:<startline>.<startcol>,<endline>.<endcol> <numstmts> <count>
	// Split on space first.
	parts := strings.Fields(line)
	if len(parts) != 3 {
		return coverBlock{}, fmt.Errorf("unexpected field count: %d", len(parts))
	}

	numStmts, err := strconv.Atoi(parts[1])
	if err != nil {
		return coverBlock{}, fmt.Errorf("parsing numstmts: %w", err)
	}
	count, err := strconv.Atoi(parts[2])
	if err != nil {
		return coverBlock{}, fmt.Errorf("parsing count: %w", err)
	}

	// parts[0] is <file>:<startline>.<startcol>,<endline>.<endcol>
	// Split on the last colon to separate file from positions.
	lastColon := strings.LastIndex(parts[0], ":")
	if lastColon < 0 {
		return coverBlock{}, fmt.Errorf("no colon in position field")
	}
	filePart := parts[0][:lastColon]
	posPart := parts[0][lastColon+1:]

	// posPart is <startline>.<startcol>,<endline>.<endcol>
	posHalves := strings.Split(posPart, ",")
	if len(posHalves) != 2 {
		return coverBlock{}, fmt.Errorf("unexpected position format: %s", posPart)
	}

	startLine, err := parseLineCol(posHalves[0])
	if err != nil {
		return coverBlock{}, err
	}
	endLine, err := parseLineCol(posHalves[1])
	if err != nil {
		return coverBlock{}, err
	}

	return coverBlock{
		File:      filePart,
		StartLine: startLine,
		EndLine:   endLine,
		NumStmts:  numStmts,
		Count:     count,
	}, nil
}

// parseLineCol extracts the line number from a "<line>.<col>" string.
func parseLineCol(s string) (int, error) {
	parts := strings.SplitN(s, ".", 2)
	if len(parts) < 1 {
		return 0, fmt.Errorf("empty line.col: %s", s)
	}
	return strconv.Atoi(parts[0])
}

// computePackageCoverage aggregates coverage blocks per package.
// It returns a map from package import path to packageCoverage.
func computePackageCoverage(blocks []coverBlock, dir string) (map[string]packageCoverage, error) {
	pkgMap := make(map[string]packageCoverage)

	for _, b := range blocks {
		// The file in the coverprofile is a module-relative path like
		// "github.com/foo/bar/pkg/file.go". We derive the package by stripping
		// the filename.
		pkg := coverFileToPackage(b.File)
		cov := pkgMap[pkg]
		cov.TotalStmts += b.NumStmts
		if b.Count > 0 {
			cov.CoveredStmts += b.NumStmts
		}
		pkgMap[pkg] = cov
	}
	return pkgMap, nil
}

// coverFileToPackage extracts the package import path from a coverprofile file
// entry (which looks like "module/path/to/pkg/file.go").
func coverFileToPackage(file string) string {
	// Strip the trailing "/filename.go".
	idx := strings.LastIndex(file, "/")
	if idx < 0 {
		return file
	}
	return file[:idx]
}

// findUncoveredExports returns COV001 findings for every exported function that
// has zero statement coverage in the profile.
func findUncoveredExports(blocks []coverBlock, dir string) ([]analyzer.Finding, error) {
	// Build a map from (file, line) -> covered for quick lookup.
	// A line is considered covered if any block that spans it has Count > 0.
	lineCovered := make(map[fileLineKey]bool)
	for _, b := range blocks {
		for l := b.StartLine; l <= b.EndLine; l++ {
			key := fileLineKey{file: b.File, line: l}
			if b.Count > 0 {
				lineCovered[key] = true
			} else if !lineCovered[key] {
				lineCovered[key] = false
			}
		}
	}

	// Collect unique file paths from the profile.
	fileSet := make(map[string]bool)
	for _, b := range blocks {
		fileSet[b.File] = true
	}

	var findings []analyzer.Finding

	for coverFile := range fileSet {
		// Resolve the actual filesystem path.
		absPath, err := resolveFile(coverFile, dir)
		if err != nil {
			continue
		}

		fns, err := parseFunctions(absPath)
		if err != nil {
			continue
		}

		for _, fn := range fns {
			if !fn.Exported {
				continue
			}
			if isFunctionCovered(fn, coverFile, lineCovered) {
				continue
			}
			findings = append(findings, analyzer.Finding{
				RuleID:   "COV001",
				Severity: "medium",
				Message:  fmt.Sprintf("exported function %s has 0%% test coverage", fn.Name),
				File:     absPath,
				Line:     fn.StartLine,
				Suggestion: fmt.Sprintf(
					"add a test for %s to improve coverage", fn.Name,
				),
			})
		}
	}

	return findings, nil
}

// isFunctionCovered returns true if any line within fn's body has coverage > 0.
func isFunctionCovered(fn funcInfo, coverFile string, lineCovered map[fileLineKey]bool) bool {
	for l := fn.StartLine; l <= fn.EndLine; l++ {
		if covered, ok := lineCovered[fileLineKey{file: coverFile, line: l}]; ok && covered {
			return true
		}
	}
	return false
}

// resolveFile attempts to find the real filesystem path for a coverprofile
// file entry. The entry is typically a module-relative import path like
// "github.com/foo/bar/pkg/file.go". We walk up from dir looking for a match.
func resolveFile(coverFile, dir string) (string, error) {
	// Strip the module prefix: the coverprofile path starts with the module
	// path. We need to strip that and resolve relative to dir.
	// Strategy: try progressively shorter prefixes until we find a file that
	// exists under dir.
	parts := strings.Split(coverFile, "/")
	for i := range parts {
		rel := strings.Join(parts[i:], string(filepath.Separator))
		candidate := filepath.Join(dir, rel)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("cannot resolve %s under %s", coverFile, dir)
}

// parseFunctions uses go/parser to extract all function declarations from a
// Go source file, returning name, line range, and whether they are exported.
func parseFunctions(path string) ([]funcInfo, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	var fns []funcInfo
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		startPos := fset.Position(fd.Pos())
		endPos := fset.Position(fd.End())
		fns = append(fns, funcInfo{
			Name:      fd.Name.Name,
			StartLine: startPos.Line,
			EndLine:   endPos.Line,
			Exported:  ast.IsExported(fd.Name.Name),
		})
	}
	return fns, nil
}

// ---- history ----------------------------------------------------------------

// loadLastHistory returns the most recent HistoryEntry from the history
// directory, or nil if no history exists.
func loadLastHistory(dir string) (*HistoryEntry, error) {
	hDir := filepath.Join(dir, historyDir)
	entries, err := os.ReadDir(hDir)
	if err != nil {
		return nil, err
	}
	// Filter for JSON files and sort ascending; take the last one.
	var jsonFiles []fs.DirEntry
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			jsonFiles = append(jsonFiles, e)
		}
	}
	if len(jsonFiles) == 0 {
		return nil, nil
	}
	sort.Slice(jsonFiles, func(i, j int) bool {
		return jsonFiles[i].Name() < jsonFiles[j].Name()
	})
	last := jsonFiles[len(jsonFiles)-1]
	data, err := os.ReadFile(filepath.Join(hDir, last.Name()))
	if err != nil {
		return nil, err
	}
	var entry HistoryEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// saveHistory writes the current coverage results to a timestamped JSON file
// in .goanalyzer/history/ under dir.
func saveHistory(dir string, pkgCoverage map[string]packageCoverage) error {
	hDir := filepath.Join(dir, historyDir)
	if err := os.MkdirAll(hDir, 0o755); err != nil {
		return fmt.Errorf("creating history dir: %w", err)
	}

	pctMap := make(map[string]float64, len(pkgCoverage))
	for pkg, cov := range pkgCoverage {
		pctMap[pkg] = cov.Pct()
	}

	entry := HistoryEntry{
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		PackageCoverage: pctMap,
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling history: %w", err)
	}

	ts := time.Now().UTC().Format("20060102T150405Z")
	fname := filepath.Join(hDir, ts+".json")
	if err := os.WriteFile(fname, data, 0o644); err != nil {
		return fmt.Errorf("writing history file: %w", err)
	}
	return nil
}
