// Package scan wires the pipeline together:
// Source -> Analyzers -> Packages -> Matcher -> Report.
package scan

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/0x48core/vulnhound/internal/analyzer"
	"github.com/0x48core/vulnhound/internal/matcher"
	"github.com/0x48core/vulnhound/internal/source"
	"github.com/0x48core/vulnhound/pkg/types"
)

// Options configures a scan.
type Options struct {
	Source    source.Source
	Analyzers []analyzer.Analyzer
	Matcher   matcher.Matcher
	SkipDev   bool // drop development-only dependencies before matching
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

	start := time.Now()
	pkgs, err := analyzer.Catalog(ctx, target.FS, opts.Analyzers, analyzer.Options{})
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

	// Empty slices, not nil, so JSON output has [] rather than null.
	if pkgs == nil {
		pkgs = []types.Package{}
	}
	if findings == nil {
		findings = []types.Finding{}
	}
	return &types.Report{
		Target:      target.Name,
		TargetType:  target.Type,
		GeneratedAt: time.Now().UTC(),
		Packages:    pkgs,
		Findings:    findings,
	}, nil
}
