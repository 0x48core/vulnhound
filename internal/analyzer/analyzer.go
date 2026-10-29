// Package analyzer detects packages in a filesystem. Each ecosystem has its
// own Analyzer; Catalog walks the filesystem and runs every matching
// analyzer concurrently.
package analyzer

import (
	"context"
	"io/fs"
	"log/slog"
	"runtime"
	"slices"
	"sort"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/0x48core/vulnhound/pkg/types"
)

// Analyzer extracts packages from files it recognises.
type Analyzer interface {
	// Name identifies the analyzer in logs.
	Name() string
	// Match reports whether the file at path (slash-separated, relative to
	// the filesystem root) belongs to this analyzer.
	Match(path string) bool
	// Analyze parses the file at path. It receives the whole filesystem so
	// analyzers that need sibling files can read them.
	Analyze(ctx context.Context, fsys fs.FS, path string) ([]types.Package, error)
}

// Default returns all built-in analyzers.
func Default() []Analyzer {
	return []Analyzer{GoMod{}, NpmLock{}}
}

// skipDirs are never descended into: they hold installed copies of
// dependencies already described by a lockfile, or VCS metadata.
var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
}

// Options controls a Catalog run.
type Options struct {
	Concurrency int // defaults to GOMAXPROCS
}

// Catalog walks fsys, runs every matching analyzer, and returns the
// deduplicated packages sorted by ecosystem, name, and version. A failing
// analyzer is logged and skipped so one malformed file cannot abort a scan.
func Catalog(ctx context.Context, fsys fs.FS, analyzers []Analyzer, opts Options) ([]types.Package, error) {
	type job struct {
		a    Analyzer
		path string
	}
	var jobs []job
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			slog.Warn("walk", "path", p, "err", err)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if p != "." && skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		for _, a := range analyzers {
			if a.Match(p) {
				jobs = append(jobs, job{a, p})
			}
		}
		return ctx.Err()
	})
	if err != nil {
		return nil, err
	}

	limit := opts.Concurrency
	if limit <= 0 {
		limit = runtime.GOMAXPROCS(0)
	}
	var (
		mu    sync.Mutex
		found []types.Package
	)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(limit)
	for _, j := range jobs {
		g.Go(func() error {
			pkgs, err := j.a.Analyze(gctx, fsys, j.path)
			if err != nil {
				slog.Warn("analyze", "analyzer", j.a.Name(), "path", j.path, "err", err)
				return gctx.Err()
			}
			slog.Debug("analyzed", "analyzer", j.a.Name(), "path", j.path, "packages", len(pkgs))
			mu.Lock()
			found = append(found, pkgs...)
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return dedupe(found), nil
}

// dedupe merges packages with the same key, unioning their locations. A
// package is direct if it is direct anywhere, and dev only if it is dev
// everywhere.
func dedupe(pkgs []types.Package) []types.Package {
	byKey := make(map[string]*types.Package, len(pkgs))
	var order []string
	for _, p := range pkgs {
		existing, ok := byKey[p.Key()]
		if !ok {
			cp := p
			cp.Locations = append([]string(nil), p.Locations...)
			byKey[p.Key()] = &cp
			order = append(order, p.Key())
			continue
		}
		existing.Locations = appendUnique(existing.Locations, p.Locations...)
		existing.Direct = existing.Direct || p.Direct
		existing.Dev = existing.Dev && p.Dev
	}
	out := make([]types.Package, 0, len(order))
	for _, k := range order {
		p := byKey[k]
		sort.Strings(p.Locations)
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	return out
}

func appendUnique(dst []string, src ...string) []string {
	for _, s := range src {
		if !slices.Contains(dst, s) {
			dst = append(dst, s)
		}
	}
	return dst
}
