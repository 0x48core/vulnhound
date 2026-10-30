package matcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/0x48core/vulnhound/internal/osvdb"
	"github.com/0x48core/vulnhound/internal/version"
	"github.com/0x48core/vulnhound/pkg/types"
)

// Offline matches packages against a local copy of the OSV database
// instead of the API, evaluating affected ranges itself.
type Offline struct {
	DB  *osvdb.DB
	Now func() time.Time // for staleness warnings; defaults to time.Now
}

// Match implements Matcher.
func (o *Offline) Match(_ context.Context, pkgs []types.Package) ([]types.Finding, error) {
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	parsed := map[string]*osvVuln{} // by ID: a record can affect many packages
	keyVulns := map[advisoryKey][]*osvVuln{}
	missing := map[string]bool{}
	warned := map[string]bool{}

	for _, p := range pkgs {
		k := advisoryKey{p.Ecosystem, p.AdvisoryName(), p.AdvisoryVersion()}
		if _, done := keyVulns[k]; done {
			continue
		}
		records, meta, err := o.DB.Lookup(k.ecosystem, k.name)
		if errors.Is(err, osvdb.ErrNotInstalled) {
			missing[osvdb.Base(k.ecosystem)] = true
			keyVulns[k] = nil
			continue
		}
		if err != nil {
			return nil, err
		}
		if base := osvdb.Base(k.ecosystem); meta.Stale(now()) && !warned[base] {
			warned[base] = true
			slog.Warn("offline database is out of date; run `vulnhound db update`",
				"ecosystem", base, "updated", meta.UpdatedAt.Format(time.DateOnly))
		}

		var affecting []*osvVuln
		for _, raw := range records {
			v, err := parseRecord(raw, parsed)
			if err != nil {
				return nil, err
			}
			if v.Withdrawn == "" && affects(v, k) {
				affecting = append(affecting, v)
			}
		}
		keyVulns[k] = affecting
	}

	if len(missing) > 0 {
		bases := make([]string, 0, len(missing))
		for b := range missing {
			bases = append(bases, b)
		}
		sort.Strings(bases)
		return nil, fmt.Errorf("offline database has no %s data; run `vulnhound db update %s`",
			strings.Join(bases, ", "), strings.Join(bases, " "))
	}

	var findings []types.Finding
	for _, p := range pkgs {
		vs := keyVulns[advisoryKey{p.Ecosystem, p.AdvisoryName(), p.AdvisoryVersion()}]
		findings = append(findings, findingsFor(p, vs)...)
	}
	sortFindings(findings)
	return findings, nil
}

func parseRecord(raw []byte, cache map[string]*osvVuln) (*osvVuln, error) {
	var v osvVuln
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("offline database: %w", err)
	}
	if cached, ok := cache[v.ID]; ok {
		return cached, nil
	}
	cache[v.ID] = &v
	return &v, nil
}

// affects reports whether v affects the package version, following the
// OSV evaluation rules (https://ossf.github.io/osv-schema/#evaluation): the
// version is listed explicitly, or falls inside a SEMVER or ECOSYSTEM
// range. GIT ranges describe commits and are ignored.
func affects(v *osvVuln, k advisoryKey) bool {
	for _, a := range v.Affected {
		if a.Package.Ecosystem != k.ecosystem || a.Package.Name != k.name {
			continue
		}
		if slices.Contains(a.Versions, k.version) {
			return true
		}
		for _, r := range a.Ranges {
			if (r.Type == "SEMVER" || r.Type == "ECOSYSTEM") && inEvents(k.ecosystem, k.version, r.Events) {
				return true
			}
		}
	}
	return false
}

// inEvents evaluates one range: walking the events in version order, an
// introduced event at or below the version opens the range, and a fixed
// event at or below it (or a last_affected event below it) closes it.
// Ranges whose versions cannot be compared are treated as not affecting;
// the explicit versions list still applies.
func inEvents(eco, v string, events []osvEvent) bool {
	if !version.Comparable(eco, v) {
		return false
	}
	at := func(e osvEvent) string {
		switch {
		case e.Introduced != "":
			return e.Introduced
		case e.Fixed != "":
			return e.Fixed
		}
		return e.LastAffected
	}
	sorted := slices.Clone(events)
	for _, e := range sorted {
		if x := at(e); x != "0" && !version.Comparable(eco, x) {
			return false
		}
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := at(sorted[i]), at(sorted[j])
		if a == "0" || b == "0" {
			return a == "0" && b != "0"
		}
		c, _ := version.Compare(eco, a, b)
		return c < 0
	})

	affected := false
	for _, e := range sorted {
		switch {
		case e.Introduced != "":
			if c, _ := version.Compare(eco, v, e.Introduced); e.Introduced == "0" || c >= 0 {
				affected = true
			}
		case e.Fixed != "":
			if c, _ := version.Compare(eco, v, e.Fixed); c >= 0 {
				affected = false
			}
		case e.LastAffected != "":
			if c, _ := version.Compare(eco, v, e.LastAffected); c > 0 {
				affected = false
			}
		}
	}
	return affected
}
