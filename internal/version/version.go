// Package version compares package versions per ecosystem.
package version

import (
	"strings"

	"golang.org/x/mod/semver"

	"github.com/0x48core/vulnhound/pkg/types"
)

// Compare returns -1, 0, or +1 as a is older than, equal to, or newer than
// b. ok is false when the ecosystem is unsupported or either version
// cannot be parsed.
func Compare(eco, a, b string) (cmp int, ok bool) {
	switch family(eco) {
	case familySemver:
		ca, okA := canonicalSemver(a)
		cb, okB := canonicalSemver(b)
		if !okA || !okB {
			return 0, false
		}
		return semver.Compare(ca, cb), true
	case familyDebian:
		va, okA := parseDebian(a)
		vb, okB := parseDebian(b)
		if !okA || !okB {
			return 0, false
		}
		return compareDebian(va, vb), true
	case familyAlpine:
		va, okA := parseAlpine(a)
		vb, okB := parseAlpine(b)
		if !okA || !okB {
			return 0, false
		}
		return compareAlpine(va, vb), true
	}
	return 0, false
}

// Comparable reports whether v can be compared in this ecosystem.
func Comparable(eco, v string) bool {
	switch family(eco) {
	case familySemver:
		_, ok := canonicalSemver(v)
		return ok
	case familyDebian:
		_, ok := parseDebian(v)
		return ok
	case familyAlpine:
		_, ok := parseAlpine(v)
		return ok
	}
	return false
}

type versionFamily int

const (
	familyUnknown versionFamily = iota
	familySemver
	familyDebian
	familyAlpine
)

// family maps an OSV ecosystem, including release-qualified ones such as
// "Debian:12" or "Alpine:v3.19", to its version scheme.
func family(eco string) versionFamily {
	base, _, _ := strings.Cut(eco, ":")
	switch base {
	case types.EcosystemGo, types.EcosystemNpm:
		return familySemver
	case "Debian", "Ubuntu":
		return familyDebian
	case "Alpine":
		return familyAlpine
	}
	return familyUnknown
}

// canonicalSemver converts a version to the "vMAJOR.MINOR.PATCH" form
// understood by golang.org/x/mod/semver.
func canonicalSemver(v string) (string, bool) {
	c := "v" + strings.TrimPrefix(v, "v")
	return c, semver.IsValid(c)
}
