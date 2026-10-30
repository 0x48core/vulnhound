package analyzer

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/0x48core/vulnhound/internal/purl"
	"github.com/0x48core/vulnhound/pkg/types"
)

// Dpkg reads the package database of Debian and Ubuntu images:
// /var/lib/dpkg/status, and the per-package files in
// /var/lib/dpkg/status.d/ that distroless images use instead.
type Dpkg struct{}

func (Dpkg) Name() string { return "dpkg" }

func (Dpkg) Match(p string) bool {
	if p == "var/lib/dpkg/status" {
		return true
	}
	return path.Dir(p) == "var/lib/dpkg/status.d" && !strings.HasSuffix(p, ".md5sums")
}

func (Dpkg) Analyze(_ context.Context, fsys fs.FS, p string) ([]types.Package, error) {
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

	var pkgs []types.Package
	for _, para := range controlParagraphs(data) {
		name, version := para.fields["Package"], para.fields["Version"]
		if name == "" || version == "" {
			continue
		}
		// Deinstalled packages keep a paragraph with a different status.
		// status.d files have no Status field and are always installed.
		if status, ok := para.fields["Status"]; ok && !strings.HasSuffix(status, " installed") {
			continue
		}
		srcName, srcVersion := name, version
		if src := para.fields["Source"]; src != "" {
			// "Source: openssl" or "Source: openssl (3.0.11-1)" when the
			// source version differs from the binary version.
			srcName = src
			if n, v, ok := strings.Cut(src, " ("); ok {
				srcName, srcVersion = n, strings.TrimSuffix(v, ")")
			}
		}
		pkgs = append(pkgs, types.Package{
			Name:          name,
			Version:       version,
			Ecosystem:     eco,
			PURL:          purl.Build("deb", rel.ID+"/"+name, version),
			Locations:     []types.Location{{Path: p, Line: para.line}},
			SourceName:    srcName,
			SourceVersion: srcVersion,
		})
	}
	if len(pkgs) == 0 && p == "var/lib/dpkg/status" {
		return nil, fmt.Errorf("no installed packages found")
	}
	return pkgs, nil
}

// controlParagraph is one stanza of a Debian control file.
type controlParagraph struct {
	fields map[string]string
	line   int // line of the first field
}

// controlParagraphs splits a Debian control file (deb822) into stanzas.
// Continuation lines (starting with a space) are ignored: none of the
// fields vulnhound reads span lines.
func controlParagraphs(data []byte) []controlParagraph {
	var (
		out []controlParagraph
		cur controlParagraph
	)
	flush := func() {
		if len(cur.fields) > 0 {
			out = append(out, cur)
		}
		cur = controlParagraph{}
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if cur.fields == nil {
			cur.fields, cur.line = make(map[string]string), n
		}
		cur.fields[key] = strings.TrimSpace(value)
	}
	flush()
	return out
}
