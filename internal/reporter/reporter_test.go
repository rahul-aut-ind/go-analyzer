package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rahul-aut-ind/go-analyzer/internal/analyzer"
	"github.com/rahul-aut-ind/go-analyzer/internal/engine"
)

func makeTestResult() *engine.RunResult {
	return &engine.RunResult{
		Findings: []analyzer.Finding{
			{RuleID: "TEST001", Severity: "critical", Message: "critical issue", File: "main.go", Line: 10, Suggestion: "fix it"},
			{RuleID: "TEST002", Severity: "high", Message: "high issue", File: "util.go", Line: 20},
			{RuleID: "TEST003", Severity: "low", Message: "low issue", File: "other.go", Line: 5},
		},
		Duration:  100 * time.Millisecond,
		Errors:    map[string]error{},
		TargetDir: "/test/dir",
	}
}

func TestJSONReporter(t *testing.T) {
	dir := t.TempDir()
	r := &JSONReporter{TargetDir: "/test/dir"}
	result := makeTestResult()

	path, err := r.Write(result, dir)
	if err != nil {
		t.Fatalf("JSONReporter.Write() error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading JSON report: %v", err)
	}

	// Must be valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("JSON report is not valid JSON: %v", err)
	}

	// Check required top-level keys
	for _, key := range []string{"generated_at", "target_dir", "summary", "findings"} {
		if _, ok := parsed[key]; !ok {
			t.Errorf("JSON report missing key %q", key)
		}
	}

	// Check summary counts
	summary := parsed["summary"].(map[string]interface{})
	if total := summary["total"].(float64); total != 3 {
		t.Errorf("summary.total: want 3, got %v", total)
	}
}

func TestMarkdownReporter(t *testing.T) {
	dir := t.TempDir()
	r := &MarkdownReporter{TargetDir: "/test/dir"}
	result := makeTestResult()

	path, err := r.Write(result, dir)
	if err != nil {
		t.Fatalf("MarkdownReporter.Write() error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading Markdown report: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "# go-analyzer Report") {
		t.Error("Markdown report missing heading")
	}
	if !strings.Contains(content, "TEST001") {
		t.Error("Markdown report missing TEST001 finding")
	}
	if !strings.Contains(content, "critical") {
		t.Error("Markdown report missing severity")
	}
}

func TestHTMLReporter(t *testing.T) {
	dir := t.TempDir()
	r := &HTMLReporter{TargetDir: "/test/dir"}
	result := makeTestResult()

	path, err := r.Write(result, dir)
	if err != nil {
		t.Fatalf("HTMLReporter.Write() error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading HTML report: %v", err)
	}

	content := string(data)
	if !strings.HasPrefix(strings.TrimSpace(content), "<!DOCTYPE html>") {
		t.Error("HTML report does not start with DOCTYPE")
	}
	if !strings.Contains(content, "TEST001") {
		t.Error("HTML report missing TEST001 finding")
	}
	if !strings.Contains(content, "filter") {
		t.Error("HTML report missing JS filter function")
	}
}

func TestForFormats(t *testing.T) {
	reporters := ForFormats([]string{"json", "markdown", "html"}, ".")
	if len(reporters) != 3 {
		t.Errorf("ForFormats returned %d reporters, want 3", len(reporters))
	}
}

func TestForFormats_Unknown(t *testing.T) {
	reporters := ForFormats([]string{"json", "unknown-format"}, ".")
	if len(reporters) != 1 {
		t.Errorf("ForFormats returned %d reporters for unknown format, want 1", len(reporters))
	}
}

func TestReporter_OutputDir_Created(t *testing.T) {
	base := t.TempDir()
	subDir := filepath.Join(base, "nested", "reports")

	r := &JSONReporter{TargetDir: "."}
	_, err := r.Write(makeTestResult(), subDir)
	if err != nil {
		t.Fatalf("Write() should create nested output dir: %v", err)
	}
	if _, err := os.Stat(subDir); os.IsNotExist(err) {
		t.Error("output dir was not created")
	}
}
