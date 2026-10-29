// Package purl builds Package URLs (https://github.com/package-url/purl-spec).
package purl

import (
	"net/url"
	"strings"
)

// Build returns pkg:<typ>/<name>@<version>. Each slash-separated segment of
// name is percent-encoded, so "@scope/pkg" becomes "%40scope/pkg".
func Build(typ, name, version string) string {
	segs := strings.Split(name, "/")
	for i, s := range segs {
		segs[i] = escape(s)
	}
	s := "pkg:" + typ + "/" + strings.Join(segs, "/")
	if version != "" {
		s += "@" + escape(version)
	}
	return s
}

func escape(s string) string {
	// PathEscape leaves '@' alone; the purl spec requires it encoded.
	return strings.ReplaceAll(url.PathEscape(s), "@", "%40")
}
