// Package reporter provides output formatting for go-analyzer run results.
// It defines the Reporter interface and a factory for creating reporters by
// format name.
package reporter

import (
	"fmt"

	"github.com/rahul-aut-ind/go-analyzer/internal/engine"
)

// Reporter writes an analysis RunResult to an output directory in a specific
// format and returns the path of the created file.
type Reporter interface {
	// Write serialises result into outputDir and returns the file path.
	Write(result *engine.RunResult, outputDir string) (string, error)
}

// ForFormats returns one Reporter for each format name in formats. Unknown
// format names are silently skipped and a warning is printed to stderr.
func ForFormats(formats []string, targetDir string) []Reporter {
	var reporters []Reporter
	for _, f := range formats {
		switch f {
		case "json":
			reporters = append(reporters, &JSONReporter{TargetDir: targetDir})
		case "markdown", "md":
			reporters = append(reporters, &MarkdownReporter{TargetDir: targetDir})
		case "html":
			reporters = append(reporters, &HTMLReporter{TargetDir: targetDir})
		default:
			fmt.Printf("warning: unknown report format %q — skipping\n", f)
		}
	}
	return reporters
}
