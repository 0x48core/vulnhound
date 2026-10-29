// Package matcher looks up vulnerabilities for packages.
package matcher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/semver"
	"golang.org/x/sync/errgroup"

	"github.com/0x48core/vulnhound/pkg/types"
)

// Matcher finds vulnerabilities affecting packages.
type Matcher interface {
	Match(ctx context.Context, pkgs []types.Package) ([]types.Finding, error)
}

const (
	DefaultOSVURL = "https://api.osv.dev"
	// osvBatchLimit is the maximum number of queries per querybatch request.
	osvBatchLimit = 1000
)

// OSV queries the OSV.dev API. querybatch returns only vulnerability IDs,
// so each distinct ID is then fetched from /v1/vulns/{id} for details.
type OSV struct {
	BaseURL     string
	Client      *http.Client
	UserAgent   string
	Concurrency int // parallel detail fetches; defaults to 8
}

// NewOSV returns an OSV matcher with sensible defaults.
func NewOSV(userAgent string) *OSV {
	return &OSV{
		BaseURL:     DefaultOSVURL,
		Client:      &http.Client{Timeout: 30 * time.Second},
		UserAgent:   userAgent,
		Concurrency: 8,
	}
}

// osvVuln is the subset of the OSV schema vulnhound uses.
// See https://ossf.github.io/osv-schema/.
type osvVuln struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Aliases   []string `json:"aliases"`
	Withdrawn string   `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
			} `json:"events"`
		} `json:"ranges"`
		DatabaseSpecific  osvSeverityHolder `json:"database_specific"`
		EcosystemSpecific osvSeverityHolder `json:"ecosystem_specific"`
	} `json:"affected"`
	DatabaseSpecific osvSeverityHolder `json:"database_specific"`
}

type osvSeverityHolder struct {
	Severity any `json:"severity"` // usually a string; some databases use other shapes
}

type osvQuery struct {
	Package   osvQueryPackage `json:"package"`
	Version   string          `json:"version"`
	PageToken string          `json:"page_token,omitempty"`
}

type osvQueryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

// Match implements Matcher.
func (o *OSV) Match(ctx context.Context, pkgs []types.Package) ([]types.Finding, error) {
	ids, err := o.queryIDs(ctx, pkgs)
	if err != nil {
		return nil, err
	}
	var unique []string
	seen := make(map[string]bool)
	for _, list := range ids {
		for _, id := range list {
			if !seen[id] {
				seen[id] = true
				unique = append(unique, id)
			}
		}
	}
	vulns, err := o.fetchVulns(ctx, unique)
	if err != nil {
		return nil, err
	}

	var findings []types.Finding
	for i, p := range pkgs {
		var vs []*osvVuln
		for _, id := range ids[i] {
			if v := vulns[id]; v != nil && v.Withdrawn == "" {
				vs = append(vs, v)
			}
		}
		findings = append(findings, findingsFor(p, vs)...)
	}
	sortFindings(findings)
	return findings, nil
}

// queryIDs returns, for each package, the IDs of vulnerabilities affecting
// it, following next_page_token until every query is exhausted.
func (o *OSV) queryIDs(ctx context.Context, pkgs []types.Package) ([][]string, error) {
	ids := make([][]string, len(pkgs))
	for start := 0; start < len(pkgs); start += osvBatchLimit {
		end := min(start+osvBatchLimit, len(pkgs))

		// pending maps a position in the current request to a package index.
		pending := make([]int, 0, end-start)
		tokens := make(map[int]string)
		for i := start; i < end; i++ {
			pending = append(pending, i)
		}
		for len(pending) > 0 {
			req := struct {
				Queries []osvQuery `json:"queries"`
			}{Queries: make([]osvQuery, len(pending))}
			for qi, pi := range pending {
				req.Queries[qi] = osvQuery{
					Package:   osvQueryPackage{Name: pkgs[pi].Name, Ecosystem: pkgs[pi].Ecosystem},
					Version:   pkgs[pi].Version,
					PageToken: tokens[pi],
				}
			}
			var resp osvBatchResponse
			if err := o.do(ctx, http.MethodPost, "/v1/querybatch", req, &resp); err != nil {
				return nil, fmt.Errorf("osv querybatch: %w", err)
			}
			if len(resp.Results) != len(pending) {
				return nil, fmt.Errorf("osv querybatch: got %d results for %d queries", len(resp.Results), len(pending))
			}
			var next []int
			for qi, r := range resp.Results {
				pi := pending[qi]
				for _, v := range r.Vulns {
					ids[pi] = append(ids[pi], v.ID)
				}
				if r.NextPageToken != "" {
					tokens[pi] = r.NextPageToken
					next = append(next, pi)
				}
			}
			pending = next
		}
	}
	return ids, nil
}

func (o *OSV) fetchVulns(ctx context.Context, ids []string) (map[string]*osvVuln, error) {
	var mu sync.Mutex
	out := make(map[string]*osvVuln, len(ids))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(max(o.Concurrency, 1))
	for _, id := range ids {
		g.Go(func() error {
			var v osvVuln
			if err := o.do(gctx, http.MethodGet, "/v1/vulns/"+url.PathEscape(id), nil, &v); err != nil {
				return fmt.Errorf("osv vuln %s: %w", id, err)
			}
			mu.Lock()
			out[id] = &v
			mu.Unlock()
			return nil
		})
	}
	return out, g.Wait()
}

// do performs a JSON request, retrying rate limits and server errors.
func (o *OSV) do(ctx context.Context, method, path string, body, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	const attempts = 3
	var lastErr error
	for attempt := range attempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(o.BaseURL, "/")+path, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if o.UserAgent != "" {
			req.Header.Set("User-Agent", o.UserAgent)
		}
		resp, err := o.Client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		data, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close() // body fully read; a close error changes nothing
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(data))
			slog.Debug("osv retry", "path", path, "attempt", attempt+1, "err", lastErr)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(data))
		}
		return json.Unmarshal(data, out)
	}
	return lastErr
}

// findingsFor turns the vulnerabilities reported for one package into
// findings, merging records that alias each other (for example GO-2023-x
// and GHSA-y describing the same flaw).
func findingsFor(p types.Package, vulns []*osvVuln) []types.Finding {
	var groups [][]*osvVuln
	for _, v := range vulns {
		ids := append([]string{v.ID}, v.Aliases...)
		merged := -1
		for gi := 0; gi < len(groups); gi++ {
			if !groupHasAny(groups[gi], ids) {
				continue
			}
			if merged < 0 {
				groups[gi] = append(groups[gi], v)
				merged = gi
			} else {
				// v links two existing groups: fold gi into merged.
				groups[merged] = append(groups[merged], groups[gi]...)
				groups = slices.Delete(groups, gi, gi+1)
				gi--
			}
		}
		if merged < 0 {
			groups = append(groups, []*osvVuln{v})
		}
	}

	findings := make([]types.Finding, 0, len(groups))
	for _, g := range groups {
		findings = append(findings, mergeGroup(p, g))
	}
	return findings
}

func groupHasAny(group []*osvVuln, ids []string) bool {
	for _, v := range group {
		if slices.Contains(ids, v.ID) {
			return true
		}
		for _, a := range v.Aliases {
			if slices.Contains(ids, a) {
				return true
			}
		}
	}
	return false
}

func mergeGroup(p types.Package, group []*osvVuln) types.Finding {
	// Representative: the record with the highest severity, ties broken by ID
	// so output is deterministic.
	type scored struct {
		v     *osvVuln
		sev   types.Severity
		score float64
	}
	all := make([]scored, len(group))
	for i, v := range group {
		sev, score := vulnSeverity(v)
		all[i] = scored{v, sev, score}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].sev != all[j].sev {
			return all[i].sev > all[j].sev
		}
		return all[i].v.ID < all[j].v.ID
	})
	rep := all[0]

	f := types.Finding{
		Package:   p,
		VulnID:    rep.v.ID,
		Severity:  rep.sev,
		CVSSScore: rep.score,
		URL:       "https://osv.dev/vulnerability/" + rep.v.ID,
	}
	aliases := make(map[string]bool)
	for _, s := range all {
		aliases[s.v.ID] = true
		for _, a := range s.v.Aliases {
			aliases[a] = true
		}
		if f.Summary == "" {
			f.Summary = s.v.Summary
		}
		if f.FixedIn == "" {
			f.FixedIn = fixedVersion(p, s.v)
		}
		if s.score > f.CVSSScore {
			f.CVSSScore = s.score
		}
	}
	delete(aliases, rep.v.ID)
	for a := range aliases {
		f.Aliases = append(f.Aliases, a)
	}
	sort.Strings(f.Aliases)
	return f
}

// vulnSeverity derives a severity from, in order of preference: a CVSS v3
// vector, the record-level database_specific.severity (GitHub advisories),
// or a per-package severity.
func vulnSeverity(v *osvVuln) (types.Severity, float64) {
	for _, s := range v.Severity {
		if s.Type != "CVSS_V3" {
			continue
		}
		if score, err := cvss3BaseScore(s.Score); err == nil {
			return types.SeverityFromScore(score), score
		}
	}
	if sev, ok := severityOf(v.DatabaseSpecific); ok {
		return sev, 0
	}
	for _, a := range v.Affected {
		if sev, ok := severityOf(a.DatabaseSpecific); ok {
			return sev, 0
		}
		if sev, ok := severityOf(a.EcosystemSpecific); ok {
			return sev, 0
		}
	}
	return types.SeverityUnknown, 0
}

func severityOf(h osvSeverityHolder) (types.Severity, bool) {
	s, ok := h.Severity.(string)
	if !ok {
		return types.SeverityUnknown, false
	}
	sev, err := types.ParseSeverity(s)
	return sev, err == nil && sev != types.SeverityUnknown
}

// fixedVersion returns the version that fixes v for p: the "fixed" event
// closing the range that contains p.Version. If versions in this ecosystem
// cannot be compared, or no range contains p.Version (OSV may match on an
// explicit version list), it lists every fixed version instead.
func fixedVersion(p types.Package, v *osvVuln) string {
	cur, comparable := canonical(p.Ecosystem, p.Version)
	var all []string
	for _, a := range v.Affected {
		if a.Package.Name != p.Name || a.Package.Ecosystem != p.Ecosystem {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			introduced := ""
			for _, e := range r.Events {
				switch {
				case e.Introduced != "":
					introduced = e.Introduced
				case e.Fixed != "":
					all = append(all, e.Fixed)
					if comparable && inRange(p.Ecosystem, cur, introduced, e.Fixed) {
						return displayVersion(p.Ecosystem, e.Fixed)
					}
				}
			}
		}
	}
	if len(all) == 0 {
		return ""
	}
	slices.Sort(all)
	all = slices.Compact(all)
	for i := range all {
		all[i] = displayVersion(p.Ecosystem, all[i])
	}
	return strings.Join(all, ", ")
}

func inRange(eco, cur, introduced, fixed string) bool {
	fx, ok := canonical(eco, fixed)
	if !ok || semver.Compare(cur, fx) >= 0 {
		return false
	}
	if introduced == "" || introduced == "0" {
		return true
	}
	in, ok := canonical(eco, introduced)
	return ok && semver.Compare(cur, in) >= 0
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

// displayVersion formats an OSV version the way the ecosystem writes it:
// OSV stores Go versions without the "v" prefix that go.mod uses.
func displayVersion(eco, v string) string {
	if eco == types.EcosystemGo && !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

func sortFindings(fs []types.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Package.Name != b.Package.Name {
			return a.Package.Name < b.Package.Name
		}
		if a.Package.Version != b.Package.Version {
			return a.Package.Version < b.Package.Version
		}
		return a.VulnID < b.VulnID
	})
}
