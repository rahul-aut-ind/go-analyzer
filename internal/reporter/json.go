package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rahul-aut-ind/go-analyzer/internal/analyzer"
	"github.com/rahul-aut-ind/go-analyzer/internal/engine"
)

// JSONReporter writes analysis results as a JSON file.
type JSONReporter struct {
	// TargetDir is the Go module directory that was analyzed (stored in output).
	TargetDir string
}

// jsonReport is the top-level structure serialised to JSON.
type jsonReport struct {
	GeneratedAt string              `json:"generated_at"`
	TargetDir   string              `json:"target_dir"`
	Summary     jsonSummary         `json:"summary"`
	Findings    []analyzer.Finding  `json:"findings"`
	Errors      map[string]string   `json:"errors,omitempty"`
}

type jsonSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Write serialises result to <outputDir>/report-<timestamp>.json and returns
// the absolute path of the created file.
func (r *JSONReporter) Write(result *engine.RunResult, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", fmt.Errorf("creating output dir %s: %w", outputDir, err)
	}

	summary := jsonSummary{Total: len(result.Findings)}
	for _, f := range result.Findings {
		switch f.Severity {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		case "info":
			summary.Info++
		}
	}

	errStrs := make(map[string]string, len(result.Errors))
	for k, v := range result.Errors {
		errStrs[k] = v.Error()
	}

	report := jsonReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		TargetDir:   r.TargetDir,
		Summary:     summary,
		Findings:    result.Findings,
		Errors:      errStrs,
	}
	if report.Findings == nil {
		report.Findings = []analyzer.Finding{}
	}

	ts := time.Now().UTC().Format("20060102-150405")
	outPath := filepath.Join(outputDir, fmt.Sprintf("report-%s.json", ts))

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshalling JSON report: %w", err)
	}

	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		return "", fmt.Errorf("writing JSON report: %w", err)
	}

	return outPath, nil
}
