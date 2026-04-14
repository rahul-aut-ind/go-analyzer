// Package analyzer defines the shared Analyzer interface and global registry
// used by all go-analyzer analysis modules.
package analyzer

import "sync"

// Finding represents a single diagnostic result produced by an analyzer.
type Finding struct {
	// RuleID is the unique rule identifier, e.g. "RACE001".
	RuleID string
	// Severity is one of "critical", "high", "medium", "low", "info".
	Severity string
	// Message is a human-readable description of the finding.
	Message string
	// File is the path to the source file containing the finding.
	File string
	// Line is the 1-based line number of the finding.
	Line int
	// Column is the 1-based column number of the finding.
	Column int
	// Suggestion is an optional hint for how to fix the issue.
	Suggestion string
}

// Analyzer is the contract every analysis module must implement.
type Analyzer interface {
	// Name returns the short identifier for this analyzer, e.g. "race".
	Name() string
	// Description returns a one-line summary of what this analyzer checks.
	Description() string
	// Run executes the analysis on the Go module rooted at dir and returns
	// the list of findings (possibly empty) or an error if analysis could not
	// be completed at all.
	Run(dir string) ([]Finding, error)
}

var (
	mu       sync.RWMutex
	registry []Analyzer
)

// Register adds a to the global analyzer registry. It is typically called from
// the init() function of each analyzer sub-package.
func Register(a Analyzer) {
	mu.Lock()
	defer mu.Unlock()
	registry = append(registry, a)
}

// All returns a snapshot of all registered analyzers.
func All() []Analyzer {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Analyzer, len(registry))
	copy(out, registry)
	return out
}

// Get returns the analyzer with the given name and true, or nil and false if
// no analyzer with that name exists in the registry.
func Get(name string) (Analyzer, bool) {
	mu.RLock()
	defer mu.RUnlock()
	for _, a := range registry {
		if a.Name() == name {
			return a, true
		}
	}
	return nil, false
}
