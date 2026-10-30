package image

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"
)

// Media types for manifests, indexes, and layers in both the OCI and the
// Docker v2 formats.
const (
	mediaOCIIndex      = "application/vnd.oci.image.index.v1+json"
	mediaOCIManifest   = "application/vnd.oci.image.manifest.v1+json"
	mediaDockerList    = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaDockerV2      = "application/vnd.docker.distribution.manifest.v2+json"
	mediaOCILayerGzip  = "application/vnd.oci.image.layer.v1.tar+gzip"
	mediaOCILayer      = "application/vnd.oci.image.layer.v1.tar"
	mediaOCILayerZstd  = "application/vnd.oci.image.layer.v1.tar+zstd"
	mediaDockerLayer   = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	mediaDockerForeign = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
)

var manifestAccept = strings.Join([]string{mediaOCIIndex, mediaDockerList, mediaOCIManifest, mediaDockerV2}, ", ")

type descriptor struct {
	MediaType string    `json:"mediaType"`
	Digest    string    `json:"digest"`
	Size      int64     `json:"size"`
	Platform  *Platform `json:"platform,omitempty"`
}

// manifest is an image manifest or an index (manifest list); which one is
// told by MediaType or by which list is set.
type manifest struct {
	MediaType string       `json:"mediaType"`
	Manifests []descriptor `json:"manifests"` // index
	Layers    []descriptor `json:"layers"`    // image manifest
}

func (m manifest) isIndex(contentType string) bool {
	switch m.MediaType {
	case mediaOCIIndex, mediaDockerList:
		return true
	case mediaOCIManifest, mediaDockerV2:
		return false
	}
	return contentType == mediaOCIIndex || contentType == mediaDockerList || (len(m.Manifests) > 0 && len(m.Layers) == 0)
}

func parseManifest(data []byte) (manifest, error) {
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("parse manifest: %w", err)
	}
	return m, nil
}

// Platform selects one image from a multi-platform index.
type Platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

// DefaultPlatform is linux on the host's CPU architecture.
func DefaultPlatform() Platform {
	return Platform{OS: "linux", Architecture: runtime.GOARCH}
}

// ParsePlatform parses "os/arch" or "os/arch/variant", e.g. "linux/arm64".
func ParsePlatform(s string) (Platform, error) {
	parts := strings.Split(s, "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" {
		return Platform{}, fmt.Errorf("invalid platform %q: want os/arch[/variant], e.g. linux/amd64", s)
	}
	p := Platform{OS: parts[0], Architecture: parts[1]}
	if len(parts) == 3 {
		p.Variant = parts[2]
	}
	return p, nil
}

func (p Platform) String() string {
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

// selectPlatform picks the index entry for want. A variant is only
// compared when want has one, so "linux/arm64" matches "linux/arm64/v8".
func selectPlatform(index manifest, want Platform) (descriptor, error) {
	var available []string
	for _, d := range index.Manifests {
		if d.Platform == nil {
			continue
		}
		p := *d.Platform
		if p.OS == want.OS && p.Architecture == want.Architecture && (want.Variant == "" || p.Variant == want.Variant) {
			return d, nil
		}
		if p.OS != "unknown" { // attestation manifests
			available = append(available, p.String())
		}
	}
	return descriptor{}, fmt.Errorf("no image for platform %s (available: %s); choose one with --platform", want, strings.Join(available, ", "))
}

// layerReader returns an uncompressed tar stream for a layer, detecting
// the compression from the content rather than trusting the media type.
func layerReader(mediaType string, r io.Reader) (io.Reader, func() error, error) {
	if mediaType == mediaOCILayerZstd || strings.HasSuffix(mediaType, "+zstd") {
		return nil, nil, fmt.Errorf("zstd-compressed layers are not supported yet")
	}
	br := newPeekReader(r)
	magic, _ := br.peek(4)
	switch {
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, nil, err
		}
		return gz, gz.Close, nil
	case len(magic) == 4 && magic[0] == 0x28 && magic[1] == 0xb5 && magic[2] == 0x2f && magic[3] == 0xfd:
		return nil, nil, fmt.Errorf("zstd-compressed layers are not supported yet")
	}
	return br, func() error { return nil }, nil
}

// peekReader lets layerReader inspect magic bytes without losing them.
type peekReader struct {
	r   io.Reader
	buf []byte
}

func newPeekReader(r io.Reader) *peekReader { return &peekReader{r: r} }

func (p *peekReader) peek(n int) ([]byte, error) {
	for len(p.buf) < n {
		chunk := make([]byte, n-len(p.buf))
		m, err := p.r.Read(chunk)
		p.buf = append(p.buf, chunk[:m]...)
		if err != nil {
			return p.buf, err
		}
	}
	return p.buf[:n], nil
}

func (p *peekReader) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	return p.r.Read(b)
}
