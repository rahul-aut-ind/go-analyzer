// Package cmd wires together all cobra commands for the go-analyzer CLI tool
// and delegates analysis to internal packages.
// The actual entry point is the root main.go which calls Execute().
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	// Register all analyzers
	_ "github.com/rahul-aut-ind/go-analyzer/internal/analyzer/complexity"
	_ "github.com/rahul-aut-ind/go-analyzer/internal/analyzer/coverage"
	_ "github.com/rahul-aut-ind/go-analyzer/internal/analyzer/deadcode"
	_ "github.com/rahul-aut-ind/go-analyzer/internal/analyzer/deps"
	_ "github.com/rahul-aut-ind/go-analyzer/internal/analyzer/lint"
	_ "github.com/rahul-aut-ind/go-analyzer/internal/analyzer/perf"
	_ "github.com/rahul-aut-ind/go-analyzer/internal/analyzer/race"
	_ "github.com/rahul-aut-ind/go-analyzer/internal/analyzer/security"

	"strings"

	"github.com/rahul-aut-ind/go-analyzer/internal/analyzer"
	"github.com/rahul-aut-ind/go-analyzer/internal/config"
	"github.com/rahul-aut-ind/go-analyzer/internal/engine"
	"github.com/rahul-aut-ind/go-analyzer/internal/reporter"
)

// Build-time variables injected via ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Execute is the entry point called by the root main package.
// It runs the cobra root command and exits with code 1 on error.
func Execute() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "go-analyzer",
		Short: "go-analyzer — static analysis tool for Go codebases",
		Long: `go-analyzer analyzes any Go codebase and produces reports on race conditions,
performance issues, security vulnerabilities, outdated dependencies, test coverage,
code complexity, lint issues, and dead code.`,
	}

	root.AddCommand(
		newScanCmd(),
		newRulesCmd(),
		newInitCmd(),
		newVersionCmd(),
	)

	return root
}

// newScanCmd creates the `scan` subcommand.
func newScanCmd() *cobra.Command {
	var (
		onlyFlag      string
		skipFlag      string
		formatFlag    string
		outputFlag    string
		failOnFlag    string
		configFlag    string
		noNetworkFlag bool
		diffFlag      bool
	)

	cmd := &cobra.Command{
		Use:   "scan [dir]",
		Short: "Scan a Go codebase for issues",
		Long: `Scan analyzes a Go project directory for race conditions, performance issues,
security vulnerabilities, dependency health, test coverage, code complexity,
lint issues, and dead code.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) == 1 {
				dir = args[0]
			}

			// Load config
			cfg, err := config.Load(configFlag)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			// Override output dir from flag
			if outputFlag != "" {
				cfg.Report.OutputDir = outputFlag
			}

			// Build run options
			opts := engine.RunOptions{
				Dir:       dir,
				Config:    cfg,
				FailOn:    failOnFlag,
				NoNetwork: noNetworkFlag,
				Diff:      diffFlag,
			}

			if onlyFlag != "" {
				opts.Only = strings.Split(onlyFlag, ",")
			}
			if skipFlag != "" {
				opts.Skip = strings.Split(skipFlag, ",")
			}

			// Determine formats
			formats := cfg.Report.Formats
			if formatFlag != "" {
				formats = strings.Split(formatFlag, ",")
			}

			// Run analysis
			result, err := engine.Run(opts)
			if err != nil {
				return fmt.Errorf("analysis failed: %w", err)
			}

			// Write reports
			reporters := reporter.ForFormats(formats, dir)
			for _, r := range reporters {
				path, werr := r.Write(result, cfg.Report.OutputDir)
				if werr != nil {
					fmt.Fprintf(os.Stderr, "warning: reporter failed: %v\n", werr)
					continue
				}
				fmt.Printf("Report written: %s\n", path)
			}

			// Summary to stdout
			printSummary(result)

			// Exit code based on --fail-on
			if failOnFlag != "" {
				if hasFindings(result, failOnFlag) {
					os.Exit(1)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&onlyFlag, "only", "", "Comma-separated list of analyzers to run")
	cmd.Flags().StringVar(&skipFlag, "skip", "", "Comma-separated list of analyzers to skip")
	cmd.Flags().StringVar(&formatFlag, "format", "", "Output formats: json,markdown,html (default: json,markdown)")
	cmd.Flags().StringVar(&outputFlag, "output", "", "Output directory (default: .goanalyzer/reports)")
	cmd.Flags().StringVar(&failOnFlag, "fail-on", "", "Exit 1 if findings at this severity exist (critical|high|medium|low)")
	cmd.Flags().StringVar(&configFlag, "config", "", "Path to .goanalyzer.yaml (default: auto-detect)")
	cmd.Flags().BoolVar(&noNetworkFlag, "no-network", false, "Skip all checks requiring internet access")
	cmd.Flags().BoolVar(&diffFlag, "diff", false, "Compare with last run and show only new findings")

	return cmd
}

// newRulesCmd creates the `rules` subcommand with list and describe sub-subcommands.
func newRulesCmd() *cobra.Command {
	rules := &cobra.Command{
		Use:   "rules",
		Short: "Manage and inspect analysis rules",
	}

	rules.AddCommand(newRulesListCmd(), newRulesDescribeCmd())
	return rules
}

func newRulesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all rule IDs, severity, and description",
		Run: func(cmd *cobra.Command, args []string) {
			catalog := getRuleCatalog()
			fmt.Printf("%-12s %-10s %-12s %s\n", "RULE ID", "SEVERITY", "ANALYZER", "DESCRIPTION")
			fmt.Println(strings.Repeat("-", 80))
			for _, r := range catalog {
				fmt.Printf("%-12s %-10s %-12s %s\n", r.id, r.severity, r.analyzer, r.description)
			}
		},
	}
}

func newRulesDescribeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "describe <RULE_ID>",
		Short: "Show full description, example code, and suggested fix for a rule",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ruleID := strings.ToUpper(args[0])
			for _, r := range getRuleCatalog() {
				if r.id == ruleID {
					fmt.Printf("Rule:        %s\n", r.id)
					fmt.Printf("Analyzer:    %s\n", r.analyzer)
					fmt.Printf("Severity:    %s\n", r.severity)
					fmt.Printf("Description: %s\n", r.description)
					fmt.Printf("\nExample (bad code):\n%s\n", r.example)
					fmt.Printf("\nSuggested fix:\n%s\n", r.fix)
					return
				}
			}
			fmt.Fprintf(os.Stderr, "unknown rule ID: %s\n", ruleID)
			os.Exit(1)
		},
	}
}

// newInitCmd creates the `init` subcommand.
func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create a .goanalyzer.yaml with all defaults in the current directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			return config.WriteDefault(".goanalyzer.yaml")
		},
	}
}

// newVersionCmd creates the `version` subcommand.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit hash, and build date",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("go-analyzer version %s\ncommit:  %s\nbuilt:   %s\n", version, commit, date)
		},
	}
}

// ruleEntry holds metadata for one rule used in `rules list` / `rules describe`.
type ruleEntry struct {
	id          string
	severity    string
	analyzer    string
	description string
	example     string
	fix         string
}

// getRuleCatalog returns the full catalog of rules.
func getRuleCatalog() []ruleEntry {
	return []ruleEntry{
		// Race
		{"RACE001", "high", "race", "Loop variable captured by goroutine closure", "for _, v := range s { go func() { use(v) }() }", "Pass v as argument: go func(v T) { use(v) }(v)"},
		{"RACE002", "high", "race", "Map written in goroutine without mutex", "go func() { m[key] = val }()", "Protect map writes with sync.Mutex or use sync.Map"},
		{"RACE003", "high", "race", "Non-atomic increment of shared int in goroutine", "go func() { counter++ }()", "Use sync/atomic or sync.Mutex"},
		{"RACE004", "medium", "race", "sync.WaitGroup.Add called inside goroutine", "go func() { wg.Add(1); ... }()", "Call wg.Add before launching the goroutine"},
		// Perf
		{"PERF001", "medium", "perf", "String concatenation with + inside loop", "for ... { s = s + str }", "Use strings.Builder or bytes.Buffer"},
		{"PERF002", "medium", "perf", "regexp.Compile/MustCompile inside function body", "func f() { re := regexp.MustCompile(p) }", "Define regexp as package-level variable"},
		{"PERF003", "low", "perf", "defer statement inside for loop", "for ... { defer f() }", "Move defer outside loop or call f() directly"},
		{"PERF004", "low", "perf", "append in loop without pre-allocation", "for ... { s = append(s, v) }", "Pre-allocate with make([]T, 0, n)"},
		{"PERF005", "low", "perf", "Large struct passed by value", "func f(s BigStruct) {}", "Pass pointer: func f(s *BigStruct) {}"},
		{"PERF006", "info", "perf", "fmt.Sprintf used for single variable to string", `fmt.Sprintf("%v", x)`, "Use strconv or fmt.Sprint(x)"},
		// Security
		{"SEC001", "critical", "security", "tls.Config with InsecureSkipVerify: true", "tls.Config{InsecureSkipVerify: true}", "Remove InsecureSkipVerify or set to false"},
		{"SEC002", "high", "security", "Use of weak hash algorithm (md5/sha1)", `import "crypto/md5"`, "Use crypto/sha256 or stronger"},
		{"SEC003", "high", "security", "exec.Command with variable argument", "exec.Command(userInput)", "Validate and sanitize input; use fixed command"},
		{"SEC004", "critical", "security", "Hardcoded secret literal in assignment", `password = "abc123"`, "Use environment variables or a secret manager"},
		{"SEC005", "high", "security", "SQL string built with + containing variable", `"SELECT * FROM t WHERE id="+id`, "Use parameterized queries / prepared statements"},
		{"SEC006", "medium", "security", "math/rand used for security-sensitive context", `import "math/rand"`, "Use crypto/rand for security-sensitive randomness"},
		// Deps
		{"DEP001", "medium", "deps", "Dependency is behind latest version", "", "Run go get -u <module>"},
		{"DEP002", "critical", "deps", "Dependency has known CVE", "", "Upgrade to a patched version"},
		// Coverage
		{"COV001", "medium", "coverage", "Exported function has 0% test coverage", "", "Add tests for the exported function"},
		{"COV002", "high", "coverage", "Package coverage below configured minimum", "", "Add tests to reach minimum coverage threshold"},
		// Complexity
		{"CMPLX001", "medium", "complexity", "Cyclomatic complexity > 10", "", "Extract helper functions to reduce branches"},
		{"CMPLX002", "low", "complexity", "Function body > 50 lines", "", "Split into smaller functions"},
		{"CMPLX003", "medium", "complexity", "Nesting depth > 4", "", "Extract inner logic into helper functions"},
		{"CMPLX004", "low", "complexity", "Function has > 5 parameters", "", "Group parameters into a struct"},
		{"CMPLX005", "info", "complexity", "File > 500 lines", "", "Consider splitting into multiple files"},
		// Lint
		{"LINT001", "low", "lint", "Exported symbol missing godoc comment", "", "Add a godoc comment above the declaration"},
		{"LINT002", "medium", "lint", "Error return value explicitly ignored with _", "_, err := f(); _ = err", "Handle the error explicitly"},
		{"LINT003", "high", "lint", "panic() in non-main, non-test package", "panic(msg)", "Return an error instead"},
		{"LINT004", "info", "lint", "init() function present", "func init() {}", "Consider explicit initialization instead"},
		{"LINT005", "low", "lint", "Inconsistent receiver names on same type", "", "Use the same receiver name on all methods"},
		{"LINT006", "info", "lint", "Magic number literal used outside const block", "x := 42", "Define as a named constant"},
		{"VET001", "medium", "lint", "go vet diagnostic", "", "See go vet output for details"},
		// Dead code
		{"DEAD001", "low", "deadcode", "Unexported function never called in package", "", "Remove if unused, or export if needed"},
		{"DEAD002", "medium", "deadcode", "Unreachable code after return/panic", "", "Remove unreachable statements"},
		{"DEAD003", "info", "deadcode", "Unused exported constant", "", "Remove or document why it is kept"},
	}
}

// printSummary writes a brief findings summary to stdout.
func printSummary(result *engine.RunResult) {
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range result.Findings {
		counts[f.Severity]++
	}
	total := len(result.Findings)
	fmt.Printf("\n=== go-analyzer summary ===\n")
	fmt.Printf("Total findings: %d  (critical:%d  high:%d  medium:%d  low:%d  info:%d)\n",
		total, counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"])
	fmt.Printf("Analysis duration: %s\n", result.Duration)
	if len(result.Errors) > 0 {
		fmt.Printf("Analyzer errors: %d\n", len(result.Errors))
		for name, err := range result.Errors {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", name, err)
		}
	}
}

// hasFindings returns true if the result contains findings at or above the specified severity.
func hasFindings(result *engine.RunResult, failOn string) bool {
	order := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	threshold, ok := order[strings.ToLower(failOn)]
	if !ok {
		return false
	}
	for _, f := range result.Findings {
		if order[strings.ToLower(f.Severity)] >= threshold {
			return true
		}
	}
	return false
}

// Ensure analyzer package is used (registry is populated via init() in each sub-package).
var _ = analyzer.All
