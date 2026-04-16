package reporter

import (
	"fmt"
	"time"
)

// formatDuration formats a duration to 3 decimal seconds or milliseconds.
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.3fs", d.Seconds())
}
