// Package ignore suppresses accepted findings listed in a .vulnhoundignore
// file.
//
// Each non-empty line names one vulnerability, optionally narrowed to a
// package and given an expiry date, followed by an optional reason:
//
//	# Not reachable: we never parse untrusted HTML.
//	GO-2026-6860
//	GHSA-j88v-2chj-qfwx  pkg=github.com/jackc/pgx/v5  until=2026-12-31  # upgrade planned in Q4
//
// The ID matches a finding's ID or any of its aliases, so a CVE ID works
// too. After the until date the entry stops applying, so accepted risks are
// reviewed instead of being hidden forever.
package ignore

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/0x48core/vulnhound/pkg/types"
)

// DefaultFile is read from the scan root when no file is given.
const DefaultFile = ".vulnhoundignore"

// Rule is one line of an ignore file.
type Rule struct {
	ID      string
	Package string    // empty: any package
	Until   time.Time // zero: never expires
	Reason  string
	Line    int
}

// Parse reads rules. Malformed lines are errors, so a typo cannot silently
// leave a finding unignored or ignore the wrong one.
func Parse(r io.Reader) ([]Rule, error) {
	var rules []Rule
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line, reason, _ := strings.Cut(sc.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		rule := Rule{ID: fields[0], Reason: strings.TrimSpace(reason), Line: n}
		for _, f := range fields[1:] {
			key, value, ok := strings.Cut(f, "=")
			switch {
			case ok && key == "pkg" && value != "":
				rule.Package = value
			case ok && key == "until":
				t, err := time.Parse(time.DateOnly, value)
				if err != nil {
					return nil, fmt.Errorf("line %d: until=%q: want YYYY-MM-DD", n, value)
				}
				rule.Until = t
			default:
				return nil, fmt.Errorf("line %d: unexpected %q (want pkg=NAME or until=YYYY-MM-DD)", n, f)
			}
		}
		rules = append(rules, rule)
	}
	return rules, sc.Err()
}

// Apply splits findings into those still reported and those ignored. Rules
// whose until date is before today are skipped with a warning.
func Apply(rules []Rule, findings []types.Finding, now time.Time) (kept []types.Finding, ignored []types.IgnoredFinding) {
	today := now.Truncate(24 * time.Hour)
	var active []Rule
	for _, r := range rules {
		if !r.Until.IsZero() && r.Until.Before(today) {
			slog.Warn("ignore rule expired; finding is reported again",
				"line", r.Line, "id", r.ID, "until", r.Until.Format(time.DateOnly))
			continue
		}
		active = append(active, r)
	}

	used := make(map[int]bool)
	kept = []types.Finding{}
	for _, f := range findings {
		if r, ok := match(active, f); ok {
			used[r.Line] = true
			ig := types.IgnoredFinding{Finding: f, Reason: r.Reason}
			if !r.Until.IsZero() {
				ig.Until = r.Until.Format(time.DateOnly)
			}
			ignored = append(ignored, ig)
			continue
		}
		kept = append(kept, f)
	}
	for _, r := range active {
		if !used[r.Line] {
			slog.Debug("ignore rule matched nothing", "line", r.Line, "id", r.ID)
		}
	}
	return kept, ignored
}

func match(rules []Rule, f types.Finding) (Rule, bool) {
	for _, r := range rules {
		if r.Package != "" && r.Package != f.Package.Name {
			continue
		}
		if strings.EqualFold(r.ID, f.VulnID) {
			return r, true
		}
		for _, a := range f.Aliases {
			if strings.EqualFold(r.ID, a) {
				return r, true
			}
		}
	}
	return Rule{}, false
}
