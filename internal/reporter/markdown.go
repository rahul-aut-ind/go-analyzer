package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rahul-aut-ind/go-analyzer/internal/engine"
)

// MarkdownReporter writes analysis results as a GitHub-flavored Markdown file.
type MarkdownReporter struct {
	// TargetDir is the Go module directory that was analyzed.
	TargetDir string
}

// Write serialises result to <outputDir>/report-<timestamp>.md and returns
// the absolute path of the created file.
func (r *MarkdownReporter) Write(result *engine.RunResult, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", fmt.Errorf("creating output dir %s: %w", outputDir, err)
	}

	var sb strings.Builder

	// Header
	sb.WriteString("# go-analyzer Report\n\n")
	sb.WriteString(fmt.Sprintf("**Generated:** %s  \n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**Target:** `%s`  \n", r.TargetDir))
	sb.WriteString(fmt.Sprintf("**Duration:** %s  \n\n", result.Duration))

	// Executive summary table
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range result.Findings {
		counts[f.Severity]++
	}
	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		sb.WriteString(fmt.Sprintf("| %s | %d |\n", sev, counts[sev]))
	}
	sb.WriteString(fmt.Sprintf("| **Total** | **%d** |\n\n", len(result.Findings)))

	// Findings grouped by severity
	severities := []string{"critical", "high", "medium", "low", "info"}
	for _, sev := range severities {
		var group []string
		for _, f := range result.Findings {
			if f.Severity == sev {
				suggestion := f.Suggestion
				if suggestion == "" {
					suggestion = "-"
				}
				group = append(group, fmt.Sprintf("| `%s` | `%s:%d` | %s | %s |",
					f.RuleID, f.File, f.Line, escapeMarkdown(f.Message), escapeMarkdown(suggestion)))
			}
		}
		if len(group) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("## %s\n\n", strings.ToUpper(sev[:1])+sev[1:]))
		sb.WriteString("| Rule ID | Location | Message | Suggestion |\n")
		sb.WriteString("|---------|----------|---------|------------|\n")
		for _, line := range group {
			sb.WriteString(line + "\n")
		}
		sb.WriteString("\n")
	}

	// Errors section
	if len(result.Errors) > 0 {
		sb.WriteString("## Analyzer Errors\n\n")
		sb.WriteString("| Analyzer | Error |\n")
		sb.WriteString("|----------|-------|\n")
		for name, err := range result.Errors {
			sb.WriteString(fmt.Sprintf("| %s | %s |\n", name, err.Error()))
		}
	}

	ts := time.Now().UTC().Format("20060102-150405")
	outPath := filepath.Join(outputDir, fmt.Sprintf("report-%s.md", ts))

	if err := os.WriteFile(outPath, []byte(sb.String()), 0o644); err != nil {
		return "", fmt.Errorf("writing Markdown report: %w", err)
	}

	return outPath, nil
}

// escapeMarkdown escapes pipe characters that would break Markdown tables.
func escapeMarkdown(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
