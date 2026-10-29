package main

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/0x48core/vulnhound/internal/analyzer"
	"github.com/0x48core/vulnhound/internal/matcher"
	"github.com/0x48core/vulnhound/internal/report"
	"github.com/0x48core/vulnhound/internal/scan"
	"github.com/0x48core/vulnhound/internal/source"
	"github.com/0x48core/vulnhound/pkg/types"
)

type scanFlags struct {
	format  string
	output  string
	failOn  string
	skipDev bool
	noColor bool
	osvURL  string
}

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a target for vulnerabilities",
	}
	cmd.AddCommand(newScanDirCmd())
	return cmd
}

func newScanDirCmd() *cobra.Command {
	var f scanFlags
	cmd := &cobra.Command{
		Use:   "dir [path]",
		Short: "Scan a local directory",
		Example: `  vulnhound scan dir .
  vulnhound scan dir ./myapp --format json --output report.json
  vulnhound scan dir . --fail-on high`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			return runScan(cmd, source.Dir{Path: path}, f)
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&f.format, "format", "f", "table", "output format: "+strings.Join(report.Formats, ", "))
	fl.StringVarP(&f.output, "output", "o", "", "write the report to a file instead of stdout")
	fl.StringVar(&f.failOn, "fail-on", "", "exit with code 1 if any finding is at or above this severity (low, medium, high, critical)")
	fl.BoolVar(&f.skipDev, "skip-dev", false, "ignore development-only dependencies")
	fl.BoolVar(&f.noColor, "no-color", false, "disable colored output")
	fl.StringVar(&f.osvURL, "osv-url", matcher.DefaultOSVURL, "OSV API base URL")
	_ = fl.MarkHidden("osv-url")
	return cmd
}

func runScan(cmd *cobra.Command, src source.Source, f scanFlags) error {
	// Validate flags before doing any work.
	if !slices.Contains(report.Formats, f.format) {
		return fmt.Errorf("unknown format %q (supported: %s)", f.format, strings.Join(report.Formats, ", "))
	}
	var threshold types.Severity
	if f.failOn != "" {
		var err error
		threshold, err = types.ParseSeverity(f.failOn)
		if err != nil || threshold == types.SeverityUnknown {
			return fmt.Errorf("invalid --fail-on %q: want low, medium, high, or critical", f.failOn)
		}
	}

	osv := matcher.NewOSV("vulnhound/" + buildVersion())
	osv.BaseURL = f.osvURL
	r, err := scan.Run(cmd.Context(), scan.Options{
		Source:    src,
		Analyzers: analyzer.Default(),
		Matcher:   osv,
		SkipDev:   f.skipDev,
	})
	if err != nil {
		return err
	}

	if err := writeReport(cmd.OutOrStdout(), r, f); err != nil {
		return err
	}

	if f.failOn != "" {
		for _, finding := range r.Findings {
			if finding.Severity >= threshold {
				return errFindings
			}
		}
	}
	return nil
}

func writeReport(stdout io.Writer, r *types.Report, f scanFlags) (err error) {
	w := stdout
	color := !f.noColor && os.Getenv("NO_COLOR") == "" && isTerminal(w)
	if f.output != "" {
		file, err := os.Create(f.output)
		if err != nil {
			return err
		}
		defer func() {
			if cerr := file.Close(); err == nil {
				err = cerr
			}
		}()
		w, color = file, false
	}
	return report.Write(w, f.format, r, report.Options{Color: color})
}

func isTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
