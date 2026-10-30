package version

import (
	"strconv"
	"strings"
)

// alpineVersion follows apk's version format:
//
//	number{.number}...{letter}{_suffix{number}}...{~hash}{-r#}
//
// See https://wiki.alpinelinux.org/wiki/APKBUILD_Reference#pkgver.
type alpineVersion struct {
	numbers  []int
	letter   byte // 0 when absent
	suffixes []alpineSuffix
	revision int
}

type alpineSuffix struct {
	order  int
	number int
}

// Pre-release suffixes sort before the bare version, post-release after.
var alpineSuffixOrder = map[string]int{
	"alpha": -4, "beta": -3, "pre": -2, "rc": -1,
	"cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5,
}

func parseAlpine(s string) (alpineVersion, bool) {
	var v alpineVersion
	s = strings.TrimSpace(s)
	if main, rev, ok := strings.Cut(s, "-r"); ok {
		n, err := strconv.Atoi(rev)
		if err != nil {
			return v, false
		}
		v.revision, s = n, main
	}
	s, _, _ = strings.Cut(s, "~") // commit hash: not ordered

	// Leading dotted numbers.
	for {
		end := 0
		for end < len(s) && isDigit(s[end]) {
			end++
		}
		if end == 0 {
			return v, false
		}
		n, err := strconv.Atoi(s[:end])
		if err != nil {
			return v, false
		}
		v.numbers = append(v.numbers, n)
		s = s[end:]
		if !strings.HasPrefix(s, ".") {
			break
		}
		s = s[1:]
	}
	if len(s) > 0 && s[0] >= 'a' && s[0] <= 'z' {
		v.letter, s = s[0], s[1:]
	}
	for s != "" {
		if s[0] != '_' {
			return v, false
		}
		s = s[1:]
		end := 0
		for end < len(s) && isLetter(s[end]) {
			end++
		}
		name := s[:end]
		order, ok := alpineSuffixOrder[name]
		if !ok {
			return v, false
		}
		s = s[end:]
		numEnd := 0
		for numEnd < len(s) && isDigit(s[numEnd]) {
			numEnd++
		}
		num := 0
		if numEnd > 0 {
			num, _ = strconv.Atoi(s[:numEnd])
		}
		v.suffixes = append(v.suffixes, alpineSuffix{order, num})
		s = s[numEnd:]
	}
	return v, true
}

func compareAlpine(a, b alpineVersion) int {
	for i := 0; i < max(len(a.numbers), len(b.numbers)); i++ {
		// A missing component sorts lower: 1.0 < 1.0.1.
		if i >= len(a.numbers) {
			return -1
		}
		if i >= len(b.numbers) {
			return 1
		}
		if c := sign(a.numbers[i] - b.numbers[i]); c != 0 {
			return c
		}
	}
	if c := sign(int(a.letter) - int(b.letter)); c != 0 {
		return c
	}
	for i := 0; i < max(len(a.suffixes), len(b.suffixes)); i++ {
		var sa, sb alpineSuffix // zero value: no suffix
		if i < len(a.suffixes) {
			sa = a.suffixes[i]
		}
		if i < len(b.suffixes) {
			sb = b.suffixes[i]
		}
		if c := sign(sa.order - sb.order); c != 0 {
			return c
		}
		if c := sign(sa.number - sb.number); c != 0 {
			return c
		}
	}
	return sign(a.revision - b.revision)
}
