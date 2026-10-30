// Package image opens container images as scan targets, from a registry or
// from an image archive, without needing a container runtime.
package image

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/0x48core/vulnhound/internal/source"
)

// Remote pulls an image from a registry.
type Remote struct {
	Ref      string
	Platform Platform
	Want     WantFunc
}

// Archive reads an image saved with `docker save` or an OCI layout tarball.
type Archive struct {
	Path     string
	Platform Platform
	Want     WantFunc
}

func (s Remote) Open(ctx context.Context) (*source.Target, error) {
	ref, err := ParseReference(s.Ref)
	if err != nil {
		return nil, err
	}
	reg := newRegistry(ref)

	start := time.Now()
	m, digest, err := reg.manifest(ctx, ref.manifestRef())
	if err != nil {
		return nil, err
	}
	if m.isIndex(m.MediaType) {
		desc, err := selectPlatform(m, s.Platform)
		if err != nil {
			return nil, err
		}
		if m, digest, err = reg.manifest(ctx, desc.Digest); err != nil {
			return nil, err
		}
	}
	slog.Info("resolved image", "ref", ref.String(), "digest", digest, "layers", len(m.Layers))

	return flattenLayers(ctx, fmt.Sprintf("%s@%s", ref, digest), s.Want, len(m.Layers),
		func(i int) (io.ReadCloser, string, error) {
			rc, err := reg.blob(ctx, m.Layers[i].Digest)
			return rc, m.Layers[i].MediaType, err
		}, start)
}

func (s Archive) Open(ctx context.Context) (*source.Target, error) {
	a, err := openArchive(s.Path)
	if err != nil {
		return nil, err
	}
	defer a.close()
	layers, name, err := a.layers(s.Platform)
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = filepath.Base(s.Path)
	}
	return flattenLayers(ctx, name, s.Want, len(layers),
		func(i int) (io.ReadCloser, string, error) {
			r, err := a.open(layers[i].name)
			return io.NopCloser(r), layers[i].mediaType, err
		}, time.Now())
}

// flattenLayers applies every layer into a temporary directory, which the
// returned target removes on Close.
func flattenLayers(ctx context.Context, name string, want WantFunc, n int,
	open func(int) (io.ReadCloser, string, error), start time.Time) (*source.Target, error) {
	root, err := os.MkdirTemp("", "vulnhound-image-*")
	if err != nil {
		return nil, err
	}
	cleanup := func() error { return os.RemoveAll(root) }

	f := newFlattener(root, want)
	for i := range n {
		if err := ctx.Err(); err != nil {
			_ = cleanup()
			return nil, err
		}
		if err := applyLayer(f, i, open); err != nil {
			_ = cleanup()
			return nil, err
		}
	}
	if err := f.finish(); err != nil {
		_ = cleanup()
		return nil, err
	}
	slog.Info("flattened image", "image", name, "layers", n, "files", len(f.owner), "took", time.Since(start).Round(time.Millisecond))
	return source.NewTarget(name, "image", os.DirFS(root), cleanup), nil
}

func applyLayer(f *flattener, i int, open func(int) (io.ReadCloser, string, error)) error {
	rc, mediaType, err := open(i)
	if err != nil {
		return fmt.Errorf("layer %d: %w", i, err)
	}
	defer func() { _ = rc.Close() }()
	if mediaType == mediaDockerForeign {
		return nil // Windows base layers are not distributable or Linux
	}
	tr, closeLayer, err := layerReader(mediaType, rc)
	if err != nil {
		return fmt.Errorf("layer %d: %w", i, err)
	}
	defer func() { _ = closeLayer() }()
	if err := f.apply(i, tr); err != nil {
		return err
	}
	// Read to the end so the blob digest is verified even though the tar
	// stream may stop before the compressed data does.
	if _, err := io.Copy(io.Discard, tr); err != nil {
		return fmt.Errorf("layer %d: %w", i, err)
	}
	if _, err := io.Copy(io.Discard, rc); err != nil {
		return fmt.Errorf("layer %d: %w", i, err)
	}
	return nil
}
