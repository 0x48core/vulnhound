// Package source fetches scan targets and exposes them as an fs.FS, so
// analyzers never need to know whether files came from a local directory,
// a Git clone, or a container image.
package source

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Target is an opened scan target.
type Target struct {
	Name string // human-readable identifier, e.g. an absolute path or image ref
	Type string // "dir", "repo", "image", ...
	FS   fs.FS

	closer func() error
}

// Close releases any resources held by the target (temp dirs, layer files).
func (t *Target) Close() error {
	if t.closer == nil {
		return nil
	}
	return t.closer()
}

// Source opens a target for scanning.
type Source interface {
	Open(ctx context.Context) (*Target, error)
}

// Dir is a local directory source.
type Dir struct {
	Path string
}

func (d Dir) Open(_ context.Context) (*Target, error) {
	abs, err := filepath.Abs(d.Path)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", abs)
	}
	return &Target{Name: abs, Type: "dir", FS: os.DirFS(abs)}, nil
}
