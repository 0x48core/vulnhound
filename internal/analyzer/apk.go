package analyzer

import (
	"bufio"
	"bytes"
	"context"
	"io/fs"
	"strings"

	"github.com/0x48core/vulnhound/internal/purl"
	"github.com/0x48core/vulnhound/pkg/types"
)

// Apk reads the Alpine package database, /lib/apk/db/installed. Each
// package is a block of "X:value" lines; P is the name, V the version,
// and o the origin (source package) that advisories are published for.
// See https://wiki.alpinelinux.org/wiki/Apk_spec#Index_Format.
type Apk struct{}

func (Apk) Name() string { return "apk" }

func (Apk) Match(p string) bool { return p == "lib/apk/db/installed" }

func (Apk) Analyze(_ context.Context, fsys fs.FS, p string) ([]types.Package, error) {
	rel, err := readOSRelease(fsys)
	if err != nil {
		return nil, err
	}
	eco, err := rel.osvEcosystem()
	if err != nil {
		return nil, err
	}
	data, err := fs.ReadFile(fsys, p)
	if err != nil {
		return nil, err
	}

	var (
		pkgs                  []types.Package
		name, version, origin string
		line                  int
	)
	flush := func() {
		if name != "" && version != "" {
			if origin == "" {
				origin = name
			}
			pkgs = append(pkgs, types.Package{
				Name:       name,
				Version:    version,
				Ecosystem:  eco,
				PURL:       purl.Build("apk", "alpine/"+name, version),
				Locations:  []types.Location{{Path: p, Line: line}},
				SourceName: origin,
			})
		}
		name, version, origin, line = "", "", "", 0
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for n := 1; sc.Scan(); n++ {
		text := sc.Text()
		if strings.TrimSpace(text) == "" {
			flush()
			continue
		}
		key, value, ok := strings.Cut(text, ":")
		if !ok || len(key) != 1 {
			continue
		}
		switch key {
		case "P":
			name, line = value, n
		case "V":
			version = value
		case "o":
			origin = value
		}
	}
	flush()
	return pkgs, nil
}
