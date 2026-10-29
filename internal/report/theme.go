package report

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/0x48core/vulnhound/pkg/types"
)

// Theme maps output roles to ANSI SGR parameters such as "1;31" (bold red).
// An empty value leaves that role uncolored.
type Theme map[string]string

// Roles that can be styled, in the order shown in help text.
var themeRoles = []string{
	"critical", "high", "medium", "low", "unknown",
	"package", "version", "meta", "id", "summary",
	"upgrade", "partial", "nofix", "title",
}

// DefaultTheme returns the built-in colors.
func DefaultTheme() Theme {
	return Theme{
		"critical": "1;97;41", // bold white on red
		"high":     "1;31",    // bold red
		"medium":   "1;33",    // bold yellow
		"low":      "1;36",    // bold cyan
		"unknown":  "1;90",    // bold grey
		"package":  "1",       // bold
		"version":  "",
		"meta":     "2", // dim: ecosystem, location, tags
		"id":       "",
		"summary":  "",
		"upgrade":  "32", // green: an upgrade fixes everything
		"partial":  "33", // yellow: an upgrade fixes some
		"nofix":    "31", // red: no fix available
		"title":    "1",
	}
}

var sgrPattern = regexp.MustCompile(`^[0-9;]*$`)

// ParseTheme applies overrides in the form "role=SGR:role=SGR", the same
// shape as GREP_COLORS, on top of the default theme. Invalid entries are
// skipped and reported, so a typo never breaks the output.
func ParseTheme(spec string) (Theme, []error) {
	t := DefaultTheme()
	var errs []error
	for entry := range strings.SplitSeq(spec, ":") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		role, sgr, ok := strings.Cut(entry, "=")
		role = strings.ToLower(strings.TrimSpace(role))
		switch {
		case !ok:
			errs = append(errs, fmt.Errorf("%q: want role=SGR", entry))
		case !slices.Contains(themeRoles, role):
			errs = append(errs, fmt.Errorf("%q: unknown role %q (valid: %s)", entry, role, strings.Join(themeRoles, ", ")))
		case !sgrPattern.MatchString(sgr):
			errs = append(errs, fmt.Errorf("%q: %q is not an SGR code like 1;31", entry, sgr))
		default:
			t[role] = sgr
		}
	}
	return t, errs
}

func severityRole(s types.Severity) string {
	return strings.ToLower(s.String())
}

// styler applies a theme, or nothing when color is off.
type styler struct {
	theme Theme
	color bool
	links bool
}

func (s styler) paint(role, text string) string {
	code := s.theme[role]
	if !s.color || code == "" || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

// link wraps text in an OSC 8 hyperlink. Terminals without support show the
// text unchanged.
func (s styler) link(url, text string) string {
	if !s.links || url == "" {
		return text
	}
	return "\x1b]8;;" + url + "\x1b\\" + text + "\x1b]8;;\x1b\\"
}
