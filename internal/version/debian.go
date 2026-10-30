package version

import (
	"strconv"
	"strings"
)

// debianVersion is [epoch:]upstream[-revision], as defined in
// https://www.debian.org/doc/debian-policy/ch-controlfields.html#version.
// Ubuntu uses the same scheme.
type debianVersion struct {
	epoch    int
	upstream string
	revision string
}

func parseDebian(s string) (debianVersion, bool) {
	s = strings.TrimSpace(s)
	var v debianVersion
	if e, rest, ok := strings.Cut(s, ":"); ok {
		n, err := strconv.Atoi(e)
		if err != nil || n < 0 {
			return v, false
		}
		v.epoch, s = n, rest
	}
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		v.upstream, v.revision = s[:i], s[i+1:]
	} else {
		v.upstream = s
	}
	if v.upstream == "" || !isDigit(v.upstream[0]) {
		return v, false
	}
	return v, true
}

func compareDebian(a, b debianVersion) int {
	if a.epoch != b.epoch {
		return sign(a.epoch - b.epoch)
	}
	if c := verrevcmp(a.upstream, b.upstream); c != 0 {
		return c
	}
	return verrevcmp(a.revision, b.revision)
}

// verrevcmp is dpkg's comparison (lib/dpkg/version.c): alternating
// non-digit runs, compared by a custom character order where "~" sorts
// before everything (even the end of the string), and digit runs, compared
// numerically.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := 0, 0
			if i < len(a) {
				ac = debOrder(a[i])
			}
			if j < len(b) {
				bc = debOrder(b[j])
			}
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		firstDiff := 0
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

func debOrder(c byte) int {
	switch {
	case isDigit(c):
		return 0
	case isLetter(c):
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
