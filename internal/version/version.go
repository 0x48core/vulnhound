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
	ca, okA := canonical(eco, a)
	cb, okB := canonical(eco, b)
	if !okA || !okB {
		return 0, false
	}
	return semver.Compare(ca, cb), true
}

// Comparable reports whether v can be compared in this ecosystem.
func Comparable(eco, v string) bool {
	_, ok := canonical(eco, v)
	return ok
}

// canonical converts a version to the "vMAJOR.MINOR.PATCH" form understood
// by golang.org/x/mod/semver. Go and npm both use semantic versioning;
// other ecosystems will need their own comparators.
func canonical(eco, v string) (string, bool) {
	switch eco {
	case types.EcosystemGo, types.EcosystemNpm:
		c := "v" + strings.TrimPrefix(v, "v")
		return c, semver.IsValid(c)
	}
	return "", false
}
