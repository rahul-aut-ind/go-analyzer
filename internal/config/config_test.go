package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	// Load with no config file — all values should be defaults.
	cfg, err := Load("/nonexistent/path/that/does/not/exist.yaml")
	if err != nil {
		t.Fatalf("Load() error with missing file: %v", err)
	}

	if cfg.Thresholds.CyclomaticComplexity != 10 {
		t.Errorf("CyclomaticComplexity default: want 10, got %d", cfg.Thresholds.CyclomaticComplexity)
	}
	if cfg.Thresholds.FunctionLength != 50 {
		t.Errorf("FunctionLength default: want 50, got %d", cfg.Thresholds.FunctionLength)
	}
	if cfg.Thresholds.CoverageMinimum != 80.0 {
		t.Errorf("CoverageMinimum default: want 80.0, got %f", cfg.Thresholds.CoverageMinimum)
	}
	if cfg.Report.OutputDir != ".goanalyzer/reports" {
		t.Errorf("OutputDir default: want .goanalyzer/reports, got %s", cfg.Report.OutputDir)
	}
	if cfg.Report.HistoryLimit != 5 {
		t.Errorf("HistoryLimit default: want 5, got %d", cfg.Report.HistoryLimit)
	}
	if len(cfg.Report.Formats) != 2 {
		t.Errorf("Formats default: want 2 entries, got %d", len(cfg.Report.Formats))
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".goanalyzer.yaml")

	yaml := `
thresholds:
  cyclomaticComplexity: 20
  functionLength: 100
  coverageMinimum: 60.0
report:
  outputDir: custom/reports
  formats:
    - html
  historyLimit: 7
rules:
  disable:
    - RACE001
scan:
  exclude:
    - vendor/
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Thresholds.CyclomaticComplexity != 20 {
		t.Errorf("CyclomaticComplexity: want 20, got %d", cfg.Thresholds.CyclomaticComplexity)
	}
	if cfg.Thresholds.FunctionLength != 100 {
		t.Errorf("FunctionLength: want 100, got %d", cfg.Thresholds.FunctionLength)
	}
	if cfg.Thresholds.CoverageMinimum != 60.0 {
		t.Errorf("CoverageMinimum: want 60.0, got %f", cfg.Thresholds.CoverageMinimum)
	}
	if cfg.Report.OutputDir != "custom/reports" {
		t.Errorf("OutputDir: want custom/reports, got %s", cfg.Report.OutputDir)
	}
	if cfg.Report.HistoryLimit != 7 {
		t.Errorf("HistoryLimit: want 7, got %d", cfg.Report.HistoryLimit)
	}
	if len(cfg.Report.Formats) != 1 || cfg.Report.Formats[0] != "html" {
		t.Errorf("Formats: want [html], got %v", cfg.Report.Formats)
	}
	if len(cfg.Rules.Disable) != 1 || cfg.Rules.Disable[0] != "RACE001" {
		t.Errorf("Rules.Disable: want [RACE001], got %v", cfg.Rules.Disable)
	}
	if len(cfg.Scan.Exclude) != 1 || cfg.Scan.Exclude[0] != "vendor/" {
		t.Errorf("Scan.Exclude: want [vendor/], got %v", cfg.Scan.Exclude)
	}
}

func TestWriteDefault(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, ".goanalyzer.yaml")

	if err := WriteDefault(dest); err != nil {
		t.Fatalf("WriteDefault() error: %v", err)
	}

	if _, err := os.Stat(dest); os.IsNotExist(err) {
		t.Fatal("WriteDefault() did not create file")
	}

	// Calling again should fail (file exists).
	if err := WriteDefault(dest); err == nil {
		t.Error("WriteDefault() should fail when file exists")
	}

	// The written file should be loadable.
	cfg, err := Load(dest)
	if err != nil {
		t.Fatalf("Load(default yaml) error: %v", err)
	}
	if cfg.Thresholds.CyclomaticComplexity != 10 {
		t.Errorf("written default CyclomaticComplexity: want 10, got %d", cfg.Thresholds.CyclomaticComplexity)
	}
}
