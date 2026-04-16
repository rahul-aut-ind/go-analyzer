// go-analyzer is a static analysis CLI for Go codebases.
// It scans any Go module in a single command and produces findings across eight
// categories: race conditions, performance, security, dependencies, test coverage,
// code complexity, lint issues, and dead code.
//
// # Installation
//
//	go install github.com/rahul-aut-ind/go-analyzer@latest
//
// # Quick start
//
//	go-analyzer scan .                      # scan current directory, write reports
//	go-analyzer scan ./myproject            # scan a specific directory
//	go-analyzer scan --format=html .        # HTML report only
//	go-analyzer scan --only=security,race . # run a subset of analyzers
//	go-analyzer scan --fail-on=high .       # exit 1 if high/critical findings exist
//
// # Commands
//
//	scan [dir]                 Analyze a Go project directory
//	rules list                 List all rule IDs, severities, and descriptions
//	rules describe <RULE_ID>   Show full detail and suggested fix for a rule
//	init                       Write a .goanalyzer.yaml config with all defaults
//	version                    Print version and build information
//
// # Analysis categories
//
// go-analyzer covers 30+ rules across eight built-in analyzers:
//
//   - Race (RACE001–004): loop variable capture by goroutine closures,
//     unsynchronized map writes, non-atomic counter increments,
//     WaitGroup.Add inside goroutines.
//
//   - Performance (PERF001–006): string concatenation with + in loops,
//     regexp.Compile inside function bodies, defer in loops,
//     append without pre-allocation, large struct passed by value,
//     fmt.Sprintf for single-variable conversion.
//
//   - Security (SEC001–006): TLS InsecureSkipVerify, weak hash algorithms
//     (md5/sha1), exec.Command with variable arguments, hardcoded secrets,
//     SQL strings built with concatenation, math/rand for security contexts.
//
//   - Dependencies (DEP001–002): modules behind latest version, known CVEs.
//
//   - Coverage (COV001–002): exported functions with 0% coverage,
//     packages below the configured minimum threshold.
//
//   - Complexity (CMPLX001–005): cyclomatic complexity above threshold,
//     functions exceeding line limit, nesting depth above limit,
//     functions with too many parameters, files exceeding line limit.
//
//   - Lint (LINT001–006, VET001): missing godoc on exported symbols,
//     explicitly ignored errors, panic in non-main packages,
//     init() usage, inconsistent receiver names, magic numbers,
//     and all go vet diagnostics.
//
//   - Dead code (DEAD001–003): unexported functions never called,
//     unreachable code after return/panic, unused exported constants.
//
// # Configuration
//
// Run `go-analyzer init` to generate a .goanalyzer.yaml in the current
// directory. The config file controls:
//
//   - Excluded path patterns (scan.exclude)
//   - Cyclomatic complexity and function length thresholds
//   - Minimum test coverage percentage
//   - Disabled rule IDs (rules.disable)
//   - Report output directory and formats
//
// # Report formats
//
// Reports are written to .goanalyzer/reports/ by default.
// Three formats are supported and can be combined with --format=json,markdown,html:
//
//   - json: machine-readable, suitable for CI pipelines and integrations
//   - markdown: human-readable summary with a findings table
//   - html: self-contained file with inline CSS, interactive severity filtering,
//     collapsible finding groups, and no external dependencies
//
// Source: https://github.com/rahul-aut-ind/go-analyzer
package main
