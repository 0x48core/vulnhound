// Package report renders scan results.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/0x48core/vulnhound/pkg/types"
)

// Formats lists the supported output formats.
var Formats = []string{"table", "json"}

// Options controls rendering.
type Options struct {
	Color bool // ANSI colors in table output
}

// Write renders r in the given format.
func Write(w io.Writer, format string, r *types.Report, opts Options) error {
	switch format {
	case "table":
		return writeTable(w, r, opts)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	return fmt.Errorf("unknown format %q (supported: %s)", format, strings.Join(Formats, ", "))
}

// Every color code is exactly 5 bytes so tabwriter, which counts bytes,
// pads all severity cells (including the header) by the same amount.
const reset = "\x1b[0m"

var severityColor = map[types.Severity]string{
	types.SeverityCritical: "\x1b[91m", // bright red
	types.SeverityHigh:     "\x1b[31m", // red
	types.SeverityMedium:   "\x1b[33m", // yellow
	types.SeverityLow:      "\x1b[36m", // cyan
	types.SeverityUnknown:  "\x1b[90m", // grey
}

const boldColor = "\x1b[01m"

func writeTable(w io.Writer, r *types.Report, opts Options) error {
	paint := func(code, s string) string {
		if !opts.Color {
			return s
		}
		return code + s + reset
	}

	fmt.Fprintf(w, "Target: %s (%s)\n", r.Target, r.TargetType)
	fmt.Fprintf(w, "Packages: %d   Vulnerabilities: %d%s\n", len(r.Packages), len(r.Findings), countSummary(r.Findings))
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "\nNo known vulnerabilities found.")
		return nil
	}
	fmt.Fprintln(w)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "PACKAGE\tVERSION\tECOSYSTEM\tID\t%s\tFIXED IN\tLOCATION\tSUMMARY\n", paint(boldColor, "SEVERITY"))
	for _, f := range r.Findings {
		fixed := f.FixedIn
		if fixed == "" {
			fixed = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			f.Package.Name,
			f.Package.Version,
			f.Package.Ecosystem,
			f.VulnID,
			paint(severityColor[f.Severity], f.Severity.String()),
			fixed,
			location(f.Package),
			truncate(f.Summary, 60),
		)
	}
	return tw.Flush()
}

func countSummary(fs []types.Finding) string {
	if len(fs) == 0 {
		return ""
	}
	counts := make(map[types.Severity]int)
	for _, f := range fs {
		counts[f.Severity]++
	}
	var parts []string
	for s := types.SeverityCritical; s >= types.SeverityUnknown; s-- {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func location(p types.Package) string {
	switch len(p.Locations) {
	case 0:
		return "-"
	case 1:
		return p.Locations[0]
	}
	return fmt.Sprintf("%s (+%d)", p.Locations[0], len(p.Locations)-1)
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
