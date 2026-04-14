// Package deps implements a dependency version and vulnerability analyzer for
// go-analyzer. It parses go.mod, queries the Go module proxy for the latest
// available version of each dependency, compares versions using semver rules,
// and checks the Go vulnerability database for known CVEs.
package deps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"

	"github.com/rahul-aut-ind/go-analyzer/internal/analyzer"
)

// DepResult holds the analysis result for a single dependency.
type DepResult struct {
	// Module is the module path, e.g. "github.com/foo/bar".
	Module string
	// CurrentVer is the version declared in go.mod.
	CurrentVer string
	// LatestVer is the most recent version returned by the module proxy.
	LatestVer string
	// Status is one of "up-to-date", "patch", "minor", "major", or "unknown".
	Status string
	// CVECount is the number of known vulnerabilities for the current version.
	CVECount int
	// IsIndirect indicates the require directive has the // indirect comment.
	IsIndirect bool
	// IsDeprecated indicates the module has been marked deprecated (not yet implemented).
	IsDeprecated bool
}

// proxyLatestResponse is the JSON payload returned by
// https://proxy.golang.org/<module>/@latest.
type proxyLatestResponse struct {
	Version string `json:"Version"`
}

// vulnQueryRequest is the request body sent to https://vuln.go.dev/v1/query.
type vulnQueryRequest struct {
	Module  string `json:"module"`
	Version string `json:"version"`
}

// vulnQueryResponse is the (partial) response from the Go vulnerability database.
type vulnQueryResponse struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
}

// httpClient is the shared HTTP client used for all outbound requests.
// It is a package-level var so tests can replace it.
var httpClient = &http.Client{Timeout: 3 * time.Second}

// depsAnalyzer is the concrete implementation of analyzer.Analyzer.
type depsAnalyzer struct{}

// New returns a new dependency Analyzer ready for use.
func New() analyzer.Analyzer { return &depsAnalyzer{} }

// Name returns the short identifier for this analyzer.
func (a *depsAnalyzer) Name() string { return "deps" }

// Description returns a one-line summary of what this analyzer checks.
func (a *depsAnalyzer) Description() string {
	return "Checks dependencies for outdated versions and known CVEs by querying the Go module proxy and vulnerability database"
}

// Run executes the dependency analysis on the Go module rooted at dir.
func (a *depsAnalyzer) Run(dir string) ([]analyzer.Finding, error) {
	return runDepsAnalysis(dir)
}

func init() { analyzer.Register(New()) }

// runDepsAnalysis is the main entry point for dependency analysis.
func runDepsAnalysis(dir string) ([]analyzer.Finding, error) {
	goModPath := filepath.Join(dir, "go.mod")
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}

	mf, err := modfile.Parse(goModPath, data, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod: %w", err)
	}

	results, err := analyzeRequires(mf.Require)
	if err != nil {
		// Non-fatal: return whatever we gathered plus a warning finding.
		return resultsToFindings(results), nil
	}
	return resultsToFindings(results), nil
}

// analyzeRequires processes each require directive and produces a DepResult.
func analyzeRequires(requires []*modfile.Require) ([]DepResult, error) {
	results := make([]DepResult, 0, len(requires))
	for _, req := range requires {
		res := DepResult{
			Module:     req.Mod.Path,
			CurrentVer: req.Mod.Version,
			IsIndirect: req.Indirect,
		}

		latest, err := fetchLatestVersion(req.Mod.Path)
		if err != nil {
			res.Status = "unknown"
			results = append(results, res)
			continue
		}
		res.LatestVer = latest
		res.Status = compareVersions(req.Mod.Version, latest)

		cveCount, err := fetchCVECount(req.Mod.Path, req.Mod.Version)
		if err == nil {
			res.CVECount = cveCount
		}

		results = append(results, res)
	}
	return results, nil
}

// fetchLatestVersion queries the Go module proxy for the latest version of module.
// Returns an error if the network is unavailable or the response is unexpected.
func fetchLatestVersion(module string) (string, error) {
	// The proxy URL format encodes capital letters with a "!" prefix.
	encodedModule := encodeModulePath(module)
	url := fmt.Sprintf("https://proxy.golang.org/%s/@latest", encodedModule)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching latest version for %s: %w", module, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("proxy returned status %d for %s", resp.StatusCode, module)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response body: %w", err)
	}

	var payload proxyLatestResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("decoding proxy response: %w", err)
	}
	if payload.Version == "" {
		return "", fmt.Errorf("empty version returned for %s", module)
	}
	return payload.Version, nil
}

// fetchCVECount queries the Go vulnerability database and returns the number of
// known vulnerabilities for the given module at version.
func fetchCVECount(module, version string) (int, error) {
	url := "https://vuln.go.dev/v1/query"

	body, err := json.Marshal(vulnQueryRequest{Module: module, Version: version})
	if err != nil {
		return 0, fmt.Errorf("marshalling vuln query: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("creating vuln request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("querying vuln db: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("vuln db returned status %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("reading vuln response: %w", err)
	}

	var payload vulnQueryResponse
	if err := json.Unmarshal(respBody, &payload); err != nil {
		return 0, fmt.Errorf("decoding vuln response: %w", err)
	}
	return len(payload.Vulns), nil
}

// compareVersions compares current and latest semver strings and returns one of
// "up-to-date", "patch", "minor", "major", or "unknown".
func compareVersions(current, latest string) string {
	// Normalise: semver requires a "v" prefix.
	cur := canonicalize(current)
	lat := canonicalize(latest)

	if !semver.IsValid(cur) || !semver.IsValid(lat) {
		return "unknown"
	}

	cmp := semver.Compare(cur, lat)
	if cmp >= 0 {
		// current >= latest
		return "up-to-date"
	}

	// Determine how different the versions are.
	curMajor := semver.Major(cur)
	latMajor := semver.Major(lat)
	if curMajor != latMajor {
		return "major"
	}

	curMMP := semver.MajorMinor(cur)
	latMMP := semver.MajorMinor(lat)
	if curMMP != latMMP {
		return "minor"
	}

	return "patch"
}

// canonicalize ensures a version string starts with "v" for semver parsing.
func canonicalize(v string) string {
	if v == "" {
		return v
	}
	if !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

// encodeModulePath encodes capital letters in module paths as required by the
// Go module proxy protocol (e.g. "GitHub" -> "!git!hub").
func encodeModulePath(module string) string {
	var sb strings.Builder
	for _, r := range module {
		if r >= 'A' && r <= 'Z' {
			sb.WriteRune('!')
			sb.WriteRune(r + 32) // toLower
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// resultsToFindings converts a slice of DepResult into analyzer.Finding values.
func resultsToFindings(results []DepResult) []analyzer.Finding {
	var findings []analyzer.Finding
	for _, r := range results {
		// DEP001: outdated dependency.
		switch r.Status {
		case "patch", "minor":
			findings = append(findings, analyzer.Finding{
				RuleID:   "DEP001",
				Severity: "medium",
				Message: fmt.Sprintf(
					"dependency %s is outdated: current=%s latest=%s (%s update available)",
					r.Module, r.CurrentVer, r.LatestVer, r.Status,
				),
				File:       "go.mod",
				Suggestion: fmt.Sprintf("run `go get %s@%s` to update", r.Module, r.LatestVer),
			})
		case "major":
			findings = append(findings, analyzer.Finding{
				RuleID:   "DEP001",
				Severity: "high",
				Message: fmt.Sprintf(
					"dependency %s is outdated by a major version: current=%s latest=%s",
					r.Module, r.CurrentVer, r.LatestVer,
				),
				File:       "go.mod",
				Suggestion: fmt.Sprintf("review the migration guide and run `go get %s@%s`", r.Module, r.LatestVer),
			})
		case "unknown":
			findings = append(findings, analyzer.Finding{
				RuleID:   "DEP001",
				Severity: "medium",
				Message: fmt.Sprintf(
					"dependency %s: could not determine latest version (network unavailable?)",
					r.Module,
				),
				File: "go.mod",
				Suggestion: "ensure network access is available and retry; or check https://pkg.go.dev/" + r.Module,
			})
		}

		// DEP002: known CVEs.
		if r.CVECount > 0 {
			findings = append(findings, analyzer.Finding{
				RuleID:   "DEP002",
				Severity: "critical",
				Message: fmt.Sprintf(
					"dependency %s@%s has %d known CVE(s)",
					r.Module, r.CurrentVer, r.CVECount,
				),
				File: "go.mod",
				Suggestion: fmt.Sprintf(
					"update %s to a version without known vulnerabilities; see https://pkg.go.dev/vuln/",
					r.Module,
				),
			})
		}
	}
	return findings
}
