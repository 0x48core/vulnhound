package image

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// WantFunc reports whether a file in the image is needed for analysis.
// Only wanted files are extracted, so a multi-gigabyte image costs only
// the size of its package databases and binaries.
type WantFunc func(path string, mode fs.FileMode, size int64) bool

// flattener applies image layers in order to produce the final filesystem,
// extracting wanted regular files under root. See
// https://github.com/opencontainers/image-spec/blob/main/layer.md for
// whiteouts and opaque directories.
//
// Symlinks and hard links are never created on disk. They are recorded and
// resolved inside the image when all layers are applied, and the target's
// content is copied, so nothing can point outside the image root.
type flattener struct {
	root  string
	want  WantFunc
	owner map[string]int  // extracted path -> layer that wrote it
	links map[string]link // link path -> link
}

type link struct {
	target string // image-root-relative path the link points to
	layer  int
}

const maxLinkHops = 16

func newFlattener(root string, want WantFunc) *flattener {
	return &flattener{root: root, want: want, owner: map[string]int{}, links: map[string]link{}}
}

// apply reads one uncompressed layer tar.
func (f *flattener) apply(layer int, r io.Reader) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("layer %d: %w", layer, err)
		}
		name, ok := cleanPath(hdr.Name)
		if !ok {
			continue // empty, root, or escapes the root: ignore
		}
		dir, base := path.Dir(name), path.Base(name)

		if base == ".wh..wh..opq" {
			f.removeBelow(dir, layer, false)
			continue
		}
		if hidden, ok := strings.CutPrefix(base, ".wh."); ok {
			f.removeBelow(path.Join(dir, hidden), layer, true)
			continue
		}

		// Any new entry replaces what lower layers had at this path.
		f.remove(name)

		mode := hdr.FileInfo().Mode()
		switch hdr.Typeflag {
		case tar.TypeReg:
			if f.want(name, mode, hdr.Size) {
				if err := f.extract(name, mode.Perm(), tr); err != nil {
					return fmt.Errorf("layer %d: %s: %w", layer, name, err)
				}
				f.owner[name] = layer
			}
		case tar.TypeSymlink:
			if f.want(name, mode, 0) {
				target := hdr.Linkname
				if !path.IsAbs(target) {
					target = path.Join(dir, target)
				}
				if t, ok := cleanPath(target); ok {
					f.links[name] = link{t, layer}
				}
			}
		case tar.TypeLink:
			// Hard link names are relative to the archive root.
			if t, ok := cleanPath(hdr.Linkname); ok && f.want(name, mode, 0) {
				f.links[name] = link{t, layer}
			}
		}
	}
}

// finish resolves links to extracted files by copying their content.
func (f *flattener) finish() error {
	names := make([]string, 0, len(f.links))
	for n := range f.links {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		target, ok := f.resolve(name)
		if !ok {
			continue
		}
		src, err := os.Open(f.diskPath(target))
		if err != nil {
			return err
		}
		info, err := src.Stat()
		if err == nil {
			err = f.extract(name, info.Mode().Perm(), src)
		}
		_ = src.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// resolve follows a chain of links to an extracted file.
func (f *flattener) resolve(name string) (string, bool) {
	for range maxLinkHops {
		l, ok := f.links[name]
		if !ok {
			_, extracted := f.owner[name]
			return name, extracted
		}
		name = l.target
	}
	return "", false // a loop
}

func (f *flattener) extract(name string, perm fs.FileMode, r io.Reader) error {
	p := f.diskPath(name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	// Owner read/write so analysis and cleanup always work; keep the
	// executable bits, which the Go binary analyzer selects on.
	out, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm|0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, r); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// remove deletes whatever was recorded at exactly this path.
func (f *flattener) remove(name string) {
	if _, ok := f.owner[name]; ok {
		_ = os.Remove(f.diskPath(name))
		delete(f.owner, name)
	}
	delete(f.links, name)
}

// removeBelow applies a whiteout from layer: everything lower layers put
// under dir is deleted, and, when self is true, dir itself as well.
func (f *flattener) removeBelow(dir string, layer int, self bool) {
	under := func(p string) bool {
		return (self && p == dir) || strings.HasPrefix(p, dir+"/") || dir == "."
	}
	for p, l := range f.owner {
		if l < layer && under(p) {
			_ = os.Remove(f.diskPath(p))
			delete(f.owner, p)
		}
	}
	for p, l := range f.links {
		if l.layer < layer && under(p) {
			delete(f.links, p)
		}
	}
}

func (f *flattener) diskPath(name string) string {
	return filepath.Join(f.root, filepath.FromSlash(name))
}

// cleanPath turns a tar entry name into a clean, root-relative,
// slash-separated path. Cleaning it as an absolute path drops any ".."
// that would climb above the root, so the result can never escape it.
func cleanPath(name string) (string, bool) {
	p := strings.TrimPrefix(path.Clean("/"+strings.ReplaceAll(name, "\\", "/")), "/")
	return p, p != ""
}
