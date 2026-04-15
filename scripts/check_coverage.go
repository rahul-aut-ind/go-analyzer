package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	file, err := os.Open("coverfunc.txt")
	if err != nil {
		fmt.Fprintln(os.Stderr, "open coverfunc.txt:", err)
		os.Exit(1)
	}
	defer file.Close()

	var totalLine string
	s := bufio.NewScanner(file)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "total:") {
			totalLine = line
		}
	}
	if err := s.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "scan coverfunc.txt:", err)
		os.Exit(1)
	}
	if totalLine == "" {
		fmt.Fprintln(os.Stderr, "could not find total coverage line in coverfunc.txt")
		os.Exit(1)
	}

	// total: (statements) 78.9%
	fields := strings.Fields(totalLine)
	pctStr := strings.TrimSuffix(fields[len(fields)-1], "%")

	cov, err := strconv.ParseFloat(pctStr, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse coverage from %q (pct=%q): %v\n", totalLine, pctStr, err)
		os.Exit(1)
	}

	fmt.Printf("Total coverage: %.2f%%\n", cov)
	if cov < 70.0 {
		fmt.Printf("Coverage %.2f%% is below 70%% minimum\n", cov)
		os.Exit(1)
	}
}
