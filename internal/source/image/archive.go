package image

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

// archive is an image tarball: the output of `docker save` (manifest.json)
// or an OCI image layout (index.json and blobs/). Entries are located once
// and then read in place, so layers are never copied out of the file.
type archive struct {
	f       *os.File
	entries map[string]archiveEntry
	cleanup func()
}

type archiveEntry struct{ offset, size int64 }

func openArchive(p string) (*archive, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	a := &archive{f: f, entries: map[string]archiveEntry{}, cleanup: func() {}}

	// A gzipped tarball cannot be read in place: decompress it to a
	// temporary file first.
	var magic [2]byte
	if _, err := io.ReadFull(f, magic[:]); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		tmp, err := decompressToTemp(f)
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		a.f, a.cleanup = tmp, func() { _ = os.Remove(tmp.Name()) }
	}
	if _, err := a.f.Seek(0, io.SeekStart); err != nil {
		a.close()
		return nil, err
	}

	cr := &countingReader{r: a.f}
	tr := tar.NewReader(cr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			a.close()
			return nil, fmt.Errorf("read image archive %s: %w", p, err)
		}
		if hdr.Typeflag == tar.TypeReg {
			name, _ := cleanPath(hdr.Name)
			a.entries[name] = archiveEntry{offset: cr.n, size: hdr.Size}
		}
	}
	return a, nil
}

func (a *archive) close() {
	_ = a.f.Close()
	a.cleanup()
}

func (a *archive) open(name string) (*io.SectionReader, error) {
	name, _ = cleanPath(name)
	e, ok := a.entries[name]
	if !ok {
		return nil, fmt.Errorf("image archive has no %s", name)
	}
	return io.NewSectionReader(a.f, e.offset, e.size), nil
}

func (a *archive) readJSON(name string, v any) error {
	r, err := a.open(name)
	if err != nil {
		return err
	}
	return json.NewDecoder(io.LimitReader(r, maxManifestSize)).Decode(v)
}

// archiveLayer is a layer's location inside the archive.
type archiveLayer struct {
	name      string
	mediaType string
}

// layers lists the image's layers, bottom first, and a display name.
func (a *archive) layers(platform Platform) ([]archiveLayer, string, error) {
	if _, ok := a.entries["manifest.json"]; ok {
		return a.dockerLayers()
	}
	if _, ok := a.entries["index.json"]; ok {
		return a.ociLayers(platform)
	}
	return nil, "", errors.New("not an image archive: no manifest.json (docker save) or index.json (OCI layout)")
}

func (a *archive) dockerLayers() ([]archiveLayer, string, error) {
	var images []struct {
		RepoTags []string
		Layers   []string
	}
	if err := a.readJSON("manifest.json", &images); err != nil {
		return nil, "", fmt.Errorf("manifest.json: %w", err)
	}
	if len(images) == 0 {
		return nil, "", errors.New("manifest.json lists no images")
	}
	img := images[0]
	name := ""
	if len(img.RepoTags) > 0 {
		name = img.RepoTags[0]
	}
	layers := make([]archiveLayer, len(img.Layers))
	for i, l := range img.Layers {
		layers[i] = archiveLayer{name: l}
	}
	return layers, name, nil
}

func (a *archive) ociLayers(platform Platform) ([]archiveLayer, string, error) {
	var index manifest
	if err := a.readJSON("index.json", &index); err != nil {
		return nil, "", fmt.Errorf("index.json: %w", err)
	}
	// Follow nested indexes (an index of a multi-platform index) down to
	// one image manifest.
	for range 4 {
		if len(index.Manifests) == 0 {
			return nil, "", errors.New("OCI index lists no manifests")
		}
		desc := index.Manifests[0]
		if len(index.Manifests) > 1 {
			var err error
			if desc, err = selectPlatform(index, platform); err != nil {
				return nil, "", err
			}
		}
		var m manifest
		if err := a.readJSON(blobPath(desc.Digest), &m); err != nil {
			return nil, "", err
		}
		if m.isIndex(desc.MediaType) {
			index = m
			continue
		}
		layers := make([]archiveLayer, len(m.Layers))
		for i, l := range m.Layers {
			layers[i] = archiveLayer{name: blobPath(l.Digest), mediaType: l.MediaType}
		}
		return layers, "", nil
	}
	return nil, "", errors.New("OCI index nesting is too deep")
}

func blobPath(digest string) string {
	algo, hex, _ := strings.Cut(digest, ":")
	return path.Join("blobs", algo, hex)
}

func decompressToTemp(f *os.File) (*os.File, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer func() { _ = gz.Close() }()
	tmp, err := os.CreateTemp("", "vulnhound-archive-*.tar")
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(tmp, gz); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return nil, err
	}
	return tmp, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
