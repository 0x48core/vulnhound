// Package scan wires the pipeline together:
// Source -> Analyzers -> Packages -> Matcher -> Report.
package scan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"time"

	"github.com/0x48core/vulnhound/internal/analyzer"
	"github.com/0x48core/vulnhound/internal/ignore"
	"github.com/0x48core/vulnhound/internal/matcher"
	"github.com/0x48core/vulnhound/internal/source"
	"github.com/0x48core/vulnhound/pkg/types"
)

// Options configures a scan.
type Options struct {
	Source    source.Source
	Analyzers []analyzer.Analyzer
	Matcher   matcher.Matcher
	SkipDev   bool     // drop development-only dependencies before matching
	Exclude   []string // path patterns to skip; see analyzer.Options.Exclude

	// IgnoreFile is a local ignore file. When empty, ignore.DefaultFile is
	// read from the scan root if it exists.
	IgnoreFile string
	Now        func() time.Time // for ignore expiry; defaults to time.Now
}

// Run executes a scan and returns its report.
func Run(ctx context.Context, opts Options) (*types.Report, error) {
	target, err := opts.Source.Open(ctx)
	if err != nil {
		return nil, fmt.Errorf("open target: %w", err)
	}
	defer func() {
		if err := target.Close(); err != nil {
			slog.Warn("close target", "err", err)
		}
	}()

	// Read ignore rules before the slow steps, so a bad file fails fast.
	rules, ignoreFile, err := loadIgnore(target.FS, opts.IgnoreFile)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	pkgs, err := analyzer.Catalog(ctx, target.FS, opts.Analyzers, analyzer.Options{Exclude: opts.Exclude})
	if err != nil {
		return nil, fmt.Errorf("catalog packages: %w", err)
	}
	if opts.SkipDev {
		kept := pkgs[:0]
		for _, p := range pkgs {
			if !p.Dev {
				kept = append(kept, p)
			}
		}
		pkgs = kept
	}
	slog.Info("cataloged packages", "count", len(pkgs), "took", time.Since(start).Round(time.Millisecond))

	findings := []types.Finding{}
	if len(pkgs) > 0 {
		start = time.Now()
		if findings, err = opts.Matcher.Match(ctx, pkgs); err != nil {
			return nil, fmt.Errorf("match vulnerabilities: %w", err)
		}
		slog.Info("matched vulnerabilities", "count", len(findings), "took", time.Since(start).Round(time.Millisecond))
	}

	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	var ignored []types.IgnoredFinding
	if len(rules) > 0 {
		findings, ignored = ignore.Apply(rules, findings, now())
	}

	// Empty slices, not nil, so JSON output has [] rather than null.
	if pkgs == nil {
		pkgs = []types.Package{}
	}
	if findings == nil {
		findings = []types.Finding{}
	}
	r := &types.Report{
		Target:      target.Name,
		TargetType:  target.Type,
		GeneratedAt: now().UTC(),
		Packages:    pkgs,
		Findings:    findings,
		Ignored:     ignored,
	}
	if len(ignored) > 0 {
		r.IgnoreFile = ignoreFile
	}
	return r, nil
}

// loadIgnore reads the explicit ignore file from disk, or else the default
// file from the scan root. A missing default file is not an error.
func loadIgnore(fsys fs.FS, explicit string) ([]ignore.Rule, string, error) {
	var (
		data []byte
		err  error
		name = explicit
	)
	if explicit != "" {
		data, err = os.ReadFile(explicit)
	} else {
		name = ignore.DefaultFile
		data, err = fs.ReadFile(fsys, ignore.DefaultFile)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, "", nil
		}
	}
	if err != nil {
		return nil, "", fmt.Errorf("read ignore file: %w", err)
	}
	rules, err := ignore.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", name, err)
	}
	slog.Debug("loaded ignore rules", "file", name, "rules", len(rules))
	return rules, name, nil
}
