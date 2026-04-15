// Package engine orchestrates the concurrent execution of all registered
// analysis modules and aggregates their findings into a single RunResult.
package engine

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/rahul-aut-ind/go-analyzer/internal/analyzer"
	"github.com/rahul-aut-ind/go-analyzer/internal/config"
)

// RunOptions controls which analyzers run and how results are handled.
type RunOptions struct {
	// Dir is the root directory of the Go module to analyze.
	Dir string
	// Only is a whitelist of analyzer names to run; empty means run all.
	Only []string
	// Skip is a list of analyzer names to exclude.
	Skip []string
	// Config holds user-supplied configuration and thresholds.
	Config *config.Config
	// FailOn is the minimum severity that causes a non-zero exit code.
	FailOn string
	// NoNetwork skips analyzers that require network access (e.g., deps).
	NoNetwork bool
	// Diff instructs the engine to compare results against the previous run
	// and return only newly introduced findings.
	Diff bool
}

// RunResult aggregates findings and metadata from a full analysis run.
type RunResult struct {
	// Findings is the sorted list of all diagnostics produced.
	Findings []analyzer.Finding
	// Duration is the wall-clock time taken by the full run.
	Duration time.Duration
	// Errors maps analyzer name → error for any analyzer that failed.
	Errors map[string]error
	// TargetDir is the directory that was analyzed.
	TargetDir string
}

// severityOrder defines the sort key for each severity level
// (higher number = higher severity).
var severityOrder = map[string]int{
	"info":     0,
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// Run executes all applicable analyzers concurrently and returns an aggregated
// RunResult. Individual analyzer failures are captured in RunResult.Errors
// rather than aborting the entire run.
func Run(opts RunOptions) (*RunResult, error) {
	if opts.Config == nil {
		var err error
		opts.Config, err = config.Load("")
		if err != nil {
			return nil, fmt.Errorf("loading default config: %w", err)
		}
	}

	analyzers := selectAnalyzers(opts)
	if len(analyzers) == 0 {
		return &RunResult{TargetDir: opts.Dir, Errors: map[string]error{}}, nil
	}

	type result struct {
		name     string
		findings []analyzer.Finding
		err      error
	}

	ch := make(chan result, len(analyzers))
	var wg sync.WaitGroup

	start := time.Now()

	for _, a := range analyzers {
		wg.Add(1)
		go func(a analyzer.Analyzer) {
			defer wg.Done()
			findings, err := a.Run(opts.Dir)
			ch <- result{name: a.Name(), findings: findings, err: err}
		}(a)
	}

	// Close channel once all goroutines finish.
	go func() {
		wg.Wait()
		close(ch)
	}()

	rr := &RunResult{
		TargetDir: opts.Dir,
		Errors:    make(map[string]error),
	}

	for r := range ch {
		if r.err != nil {
			rr.Errors[r.name] = r.err
		} else {
			rr.Findings = append(rr.Findings, r.findings...)
		}
	}

	rr.Duration = time.Since(start)

	// Sort: severity desc → file asc → line asc.
	sort.Slice(rr.Findings, func(i, j int) bool {
		si := severityOrder[rr.Findings[i].Severity]
		sj := severityOrder[rr.Findings[j].Severity]
		if si != sj {
			return si > sj
		}
		if rr.Findings[i].File != rr.Findings[j].File {
			return rr.Findings[i].File < rr.Findings[j].File
		}
		return rr.Findings[i].Line < rr.Findings[j].Line
	})

	return rr, nil
}

// selectAnalyzers filters the global registry using the Only and Skip lists
// from RunOptions.
func selectAnalyzers(opts RunOptions) []analyzer.Analyzer {
	all := analyzer.All()

	onlySet := make(map[string]bool, len(opts.Only))
	for _, n := range opts.Only {
		onlySet[n] = true
	}
	skipSet := make(map[string]bool, len(opts.Skip))
	for _, n := range opts.Skip {
		skipSet[n] = true
	}

	var selected []analyzer.Analyzer
	for _, a := range all {
		if len(onlySet) > 0 && !onlySet[a.Name()] {
			continue
		}
		if skipSet[a.Name()] {
			continue
		}
		selected = append(selected, a)
	}
	return selected
}
