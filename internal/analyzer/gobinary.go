package analyzer

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"io"
	"io/fs"
	"log/slog"
	"strings"

	"github.com/0x48core/vulnhound/internal/purl"
	"github.com/0x48core/vulnhound/pkg/types"
)

// FileMatcher is implemented by analyzers that select files by type rather
// than by name. Catalog calls it for every regular file, in addition to
// Match.
type FileMatcher interface {
	MatchFile(path string, mode fs.FileMode, size int64) bool
}

// GoBinary reads the module versions embedded in compiled Go executables
// (what `go version -m` prints), including the Go version, which is
// reported as the "stdlib" module. This finds vulnerable dependencies in
// images that ship only a binary, such as distroless and scratch images.
type GoBinary struct{}

const (
	minGoBinarySize = 64 << 10  // smaller files cannot be Go binaries
	maxGoBinarySize = 512 << 20 // skip absurdly large files
)

func (GoBinary) Name() string { return "gobinary" }

func (GoBinary) Match(string) bool { return false }

func (GoBinary) MatchFile(_ string, mode fs.FileMode, size int64) bool {
	return mode.IsRegular() && mode.Perm()&0o111 != 0 && size >= minGoBinarySize && size <= maxGoBinarySize
}

func (GoBinary) Analyze(_ context.Context, fsys fs.FS, p string) ([]types.Package, error) {
	f, err := fsys.Open(p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	ra, ok := f.(io.ReaderAt)
	if !ok {
		data, err := io.ReadAll(io.LimitReader(f, maxGoBinarySize))
		if err != nil {
			return nil, err
		}
		ra = bytes.NewReader(data)
	}
	info, err := buildinfo.Read(ra)
	if err != nil {
		// Most executables are not Go programs; that is not a failure.
		slog.Debug("not a Go binary", "path", p, "err", err)
		return nil, nil
	}

	loc := []types.Location{{Path: p}}
	var pkgs []types.Package
	add := func(name, version string, direct bool) {
		if name == "" || version == "" || version == "(devel)" {
			return
		}
		pkgs = append(pkgs, types.Package{
			Name:      name,
			Version:   version,
			Ecosystem: types.EcosystemGo,
			PURL:      purl.Build("golang", name, version),
			Locations: loc,
			Direct:    direct,
		})
	}

	// "go1.22.3", or "go1.22.3 X:boringcrypto"; development toolchains
	// ("devel go1.23-abc") have no comparable version.
	if v, ok := strings.CutPrefix(strings.Fields(info.GoVersion + " ")[0], "go"); ok {
		add("stdlib", v, true)
	}
	add(info.Main.Path, info.Main.Version, true)
	for _, d := range info.Deps {
		if d.Replace != nil {
			if d.Replace.Version == "" {
				continue // replaced by a local directory
			}
			d = d.Replace
		}
		add(d.Path, d.Version, false)
	}
	return pkgs, nil
}
