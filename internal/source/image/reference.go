package image

import (
	"fmt"
	"regexp"
	"strings"
)

// Reference is a parsed image reference such as "nginx:1.25",
// "ghcr.io/org/app@sha256:...", or "localhost:5000/app:dev".
type Reference struct {
	Registry   string // as written, e.g. "docker.io", "ghcr.io"
	Repository string // e.g. "library/nginx"
	Tag        string // empty when Digest is set and no tag was given
	Digest     string // "sha256:..." or empty
}

const dockerHub = "docker.io"

var (
	repoPattern   = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)
	tagPattern    = regexp.MustCompile(`^[\w][\w.-]{0,127}$`)
	digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

// ParseReference parses a reference using Docker's defaults: registry
// docker.io, the library/ namespace for single-name Docker Hub images, and
// tag latest.
func ParseReference(s string) (Reference, error) {
	var r Reference
	rest := s
	if name, digest, ok := strings.Cut(rest, "@"); ok {
		if !digestPattern.MatchString(digest) {
			return r, fmt.Errorf("invalid image reference %q: bad digest %q", s, digest)
		}
		r.Digest, rest = digest, name
	}
	// A tag is a ':' after the last '/' (a ':' before it is a registry port).
	if i := strings.LastIndexByte(rest, ':'); i > strings.LastIndexByte(rest, '/') {
		r.Tag, rest = rest[i+1:], rest[:i]
		if !tagPattern.MatchString(r.Tag) {
			return r, fmt.Errorf("invalid image reference %q: bad tag %q", s, r.Tag)
		}
	}
	if first, remainder, ok := strings.Cut(rest, "/"); ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		r.Registry, rest = first, remainder
	} else {
		r.Registry = dockerHub
	}
	if r.Registry == dockerHub && !strings.Contains(rest, "/") {
		rest = "library/" + rest
	}
	if !repoPattern.MatchString(rest) {
		return r, fmt.Errorf("invalid image reference %q: bad repository %q", s, rest)
	}
	r.Repository = rest
	if r.Tag == "" && r.Digest == "" {
		r.Tag = "latest"
	}
	return r, nil
}

// apiHost is the host serving the registry API.
func (r Reference) apiHost() string {
	if r.Registry == dockerHub {
		return "registry-1.docker.io"
	}
	return r.Registry
}

// manifestRef is the tag or digest used to request the manifest.
func (r Reference) manifestRef() string {
	if r.Digest != "" {
		return r.Digest
	}
	return r.Tag
}

func (r Reference) String() string {
	s := r.Registry + "/" + r.Repository
	if r.Tag != "" {
		s += ":" + r.Tag
	}
	if r.Digest != "" {
		s += "@" + r.Digest
	}
	return s
}
