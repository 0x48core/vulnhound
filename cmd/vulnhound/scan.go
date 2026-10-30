package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/0x48core/vulnhound/internal/analyzer"
	"github.com/0x48core/vulnhound/internal/ignore"
	"github.com/0x48core/vulnhound/internal/matcher"
	"github.com/0x48core/vulnhound/internal/report"
	"github.com/0x48core/vulnhound/internal/scan"
	"github.com/0x48core/vulnhound/internal/source"
	"github.com/0x48core/vulnhound/internal/source/image"
	"github.com/0x48core/vulnhound/pkg/types"
)

type scanFlags struct {
	format  string
	output  string
	failOn  string
	skipDev bool
	color   string
	noColor bool // deprecated alias for --color never
	osvURL  string

	exclude     []string
	ignoreFile  string
	sarifOutput string
	offline     bool
}

var colorModes = []string{"auto", "always", "never"}

// colorsEnv holds theme overrides, e.g. "critical=1;31:upgrade=1;32".
const colorsEnv = "VULNHOUND_COLORS"

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a target for vulnerabilities",
	}
	cmd.AddCommand(newScanDirCmd(), newScanImageCmd())
	return cmd
}

func newScanDirCmd() *cobra.Command {
	var f scanFlags
	cmd := &cobra.Command{
		Use:   "dir [path]",
		Short: "Scan a local directory",
		Example: `  vulnhound scan dir .
  vulnhound scan dir ./myapp --format json --output report.json
  vulnhound scan dir . --fail-on high
  vulnhound scan dir . --exclude testdata --format sarif -o vulnhound.sarif`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			return runScan(cmd, source.Dir{Path: path}, analyzer.Default(), f)
		},
	}
	addScanFlags(cmd, &f)
	return cmd
}

func newScanImageCmd() *cobra.Command {
	var (
		f        scanFlags
		input    string
		platform string
	)
	cmd := &cobra.Command{
		Use:   "image [REF]",
		Short: "Scan a container image from a registry or an image archive",
		Long: `Scan a container image for vulnerable OS packages (Debian, Ubuntu, Alpine),
Go binaries, and application lockfiles. No container runtime is needed:
images are pulled from the registry directly, or read from a file saved
with 'docker save' or an OCI layout tarball (--input).

Registry credentials are read from the Docker config file
(~/.docker/config.json or $DOCKER_CONFIG); credential helpers are not
supported yet.`,
		Example: `  vulnhound scan image nginx:1.25
  vulnhound scan image ghcr.io/org/app:v1.2.0 --platform linux/arm64
  docker save myapp:dev -o myapp.tar && vulnhound scan image --input myapp.tar
  vulnhound scan image alpine:3.19 --fail-on critical --format sarif -o image.sarif`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if (len(args) == 1) == (input != "") {
				return fmt.Errorf("give an image reference or --input FILE, not both")
			}
			plat := image.DefaultPlatform()
			if platform != "" {
				var err error
				if plat, err = image.ParsePlatform(platform); err != nil {
					return err
				}
			}
			analyzers := analyzer.ForImage()
			want := image.WantFunc(analyzer.Selector(analyzers))
			var src source.Source = image.Archive{Path: input, Platform: plat, Want: want}
			if len(args) == 1 {
				src = image.Remote{Ref: args[0], Platform: plat, Want: want}
			}
			// The ignore file belongs to the project, not the image.
			if f.ignoreFile == "" {
				if _, err := os.Stat(ignore.DefaultFile); err == nil {
					f.ignoreFile = ignore.DefaultFile
				}
			}
			return runScan(cmd, src, analyzers, f)
		},
	}
	addScanFlags(cmd, &f)
	cmd.Flags().StringVar(&input, "input", "", "read the image from a 'docker save' or OCI layout tarball instead of a registry")
	cmd.Flags().StringVar(&platform, "platform", "", "platform to scan in a multi-platform image, e.g. linux/arm64 (default linux/<host CPU>)")
	return cmd
}

// addScanFlags registers the flags every scan target shares.
func addScanFlags(cmd *cobra.Command, f *scanFlags) {
	fl := cmd.Flags()
	fl.StringVarP(&f.format, "format", "f", "table", "output format: "+strings.Join(report.Formats, ", "))
	fl.StringVarP(&f.output, "output", "o", "", "write the report to a file instead of stdout")
	fl.StringVar(&f.sarifOutput, "sarif-output", "", "also write a SARIF report to this file, for GitHub code scanning")
	fl.BoolVar(&f.offline, "offline", false, "match against the local database from `vulnhound db update` instead of the OSV API")
	fl.StringVar(&f.failOn, "fail-on", "", "exit with code 1 if any finding is at or above this severity (low, medium, high, critical)")
	fl.BoolVar(&f.skipDev, "skip-dev", false, "ignore development-only dependencies")
	fl.StringSliceVar(&f.exclude, "exclude", nil, "skip files and directories matching a pattern (repeatable); a pattern without / matches a name at any depth")
	fl.StringVar(&f.ignoreFile, "ignore-file", "", "file of accepted vulnerability IDs (default: "+ignore.DefaultFile+" in the scanned directory, if present)")
	fl.StringVar(&f.color, "color", "auto", "colorize table output: auto (when stdout is a terminal), always, never; customize with $"+colorsEnv)
	fl.BoolVar(&f.noColor, "no-color", false, "same as --color never")
	fl.StringVar(&f.osvURL, "osv-url", matcher.DefaultOSVURL, "OSV API base URL")
	_ = fl.MarkHidden("osv-url")
	_ = fl.MarkHidden("no-color")
}

func runScan(cmd *cobra.Command, src source.Source, analyzers []analyzer.Analyzer, f scanFlags) error {
	// Validate flags before doing any work.
	if !slices.Contains(report.Formats, f.format) {
		return fmt.Errorf("unknown format %q (supported: %s)", f.format, strings.Join(report.Formats, ", "))
	}
	if !slices.Contains(colorModes, f.color) {
		return fmt.Errorf("invalid --color %q: want %s", f.color, strings.Join(colorModes, ", "))
	}
	if f.noColor {
		f.color = "never"
	}
	if err := analyzer.ValidateExclude(f.exclude); err != nil {
		return err
	}
	var threshold types.Severity
	if f.failOn != "" {
		var err error
		threshold, err = types.ParseSeverity(f.failOn)
		if err != nil || threshold == types.SeverityUnknown {
			return fmt.Errorf("invalid --fail-on %q: want low, medium, high, or critical", f.failOn)
		}
	}

	var m matcher.Matcher
	if f.offline {
		db, err := openDB()
		if err != nil {
			return err
		}
		defer func() { _ = db.Close() }()
		m = &matcher.Offline{DB: db}
	} else {
		osv := matcher.NewOSV("vulnhound/" + buildVersion())
		osv.BaseURL = f.osvURL
		m = osv
	}
	r, err := scan.Run(cmd.Context(), scan.Options{
		Source:    src,
		Analyzers: analyzers,
		Matcher:   m,
		SkipDev:   f.skipDev,
		Exclude:   f.exclude,

		IgnoreFile: f.ignoreFile,
	})
	if err != nil {
		return err
	}

	if err := writeReport(cmd.OutOrStdout(), r, f); err != nil {
		return err
	}
	if f.sarifOutput != "" {
		sarif := f
		sarif.format, sarif.output = "sarif", f.sarifOutput
		if err := writeReport(io.Discard, r, sarif); err != nil {
			return err
		}
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
		w = file
	}
	opts := renderOptions(w, f.color)
	opts.ToolVersion = buildVersion()
	opts.PathPrefix = sarifPathPrefix(r.Target)
	return report.Write(w, f.format, r, opts)
}

// sarifPathPrefix makes SARIF locations relative to the working directory,
// which is the repository root in CI, so code scanning can find the files
// even when a subdirectory was scanned. Targets outside the working
// directory keep paths relative to the target.
func sarifPathPrefix(target string) string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	rel, err := filepath.Rel(cwd, target)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ""
	}
	return filepath.ToSlash(rel)
}

// renderOptions decides colors, hyperlinks, and width for w.
//
// "auto" colors only a terminal, and respects NO_COLOR (https://no-color.org)
// and TERM=dumb. "always" colors anything, for CI logs or `less -R`.
// Hyperlinks and summary truncation apply only to a real terminal, since
// files and pipes have no width and may not understand OSC 8 links.
func renderOptions(w io.Writer, mode string) report.Options {
	fd, tty := terminalFd(w)
	var opts report.Options
	switch mode {
	case "always":
		opts.Color = true
	case "auto":
		opts.Color = tty && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
	}
	if tty {
		opts.Hyperlinks = opts.Color
		if width, _, err := term.GetSize(fd); err == nil {
			opts.Width = width
		}
	}
	if opts.Color {
		theme, errs := report.ParseTheme(os.Getenv(colorsEnv))
		for _, err := range errs {
			slog.Warn("ignoring invalid "+colorsEnv+" entry", "err", err)
		}
		opts.Theme = theme
	}
	return opts
}

func terminalFd(w io.Writer) (int, bool) {
	file, ok := w.(*os.File)
	if !ok {
		return 0, false
	}
	fd := int(file.Fd())
	return fd, term.IsTerminal(fd)
}
