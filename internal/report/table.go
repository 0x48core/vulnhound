package report

import (
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/0x48core/vulnhound/internal/version"
	"github.com/0x48core/vulnhound/pkg/types"
)

// group is every finding for one package, plus the single upgrade that
// fixes as many of them as possible.
type group struct {
	pkg      types.Package
	findings []types.Finding
	top      types.Severity
	upgrade  string // highest single fixed version; "" if none is known
	fixes    int    // findings fixed by upgrading to upgrade
}

// writeTable renders findings grouped by package:
//
//	Scanned 33 packages in /path/to/project
//	Found 3 vulnerabilities in 1 package: 2 critical · 1 low
//
//	github.com/jackc/pgx/v5 v5.7.5  → v5.9.2  Go · go.mod
//	  CRITICAL  GHSA-9jj7-4m8r-rfcm  v5.9.0  Memory-safety vulnerability in …
//	  LOW       GHSA-j88v-2chj-qfwx  v5.9.2  pgx: SQL Injection via …
//
//	Upgrading 1 package fixes 3 of 3 vulnerabilities.
//
// Column widths are measured on plain text and color is added afterwards,
// so any theme lines up.
func writeTable(w io.Writer, r *types.Report, opts Options) error {
	theme := opts.Theme
	if theme == nil {
		theme = DefaultTheme()
	}
	s := styler{theme: theme, color: opts.Color, links: opts.Color && opts.Hyperlinks}
	var b strings.Builder

	fmt.Fprintf(&b, "Scanned %s in %s\n",
		s.paint("title", plural(len(r.Packages), "package")), r.Target)

	if len(r.Findings) == 0 {
		fmt.Fprintf(&b, "%s\n", s.paint("upgrade", "✔ No known vulnerabilities found."))
		writeIgnored(&b, s, r)
		_, err := io.WriteString(w, b.String())
		return err
	}

	groups := groupFindings(r.Findings)
	fmt.Fprintf(&b, "Found %s in %s: %s\n",
		s.paint("title", plural(len(r.Findings), "vulnerability")),
		plural(len(groups), "package"),
		severityCounts(s, r.Findings))

	// Column widths shared by every group so rows line up down the page.
	var sevW, idW, fixW int
	for _, f := range r.Findings {
		sevW = max(sevW, width(f.Severity.String()))
		idW = max(idW, width(f.VulnID))
		fixW = max(fixW, width(fixCell(f)))
	}
	const maxFixW = 20
	fixW = min(fixW, maxFixW)
	// Summaries fill what is left of the terminal width, so rows never wrap.
	// On very narrow terminals they are dropped rather than cut to a stub.
	summaryW, showSummary := 0, true // 0: unlimited
	if opts.Width > 0 {
		used := 2 + sevW + 2 + idW + 2 + fixW + 2
		summaryW = opts.Width - used
		showSummary = summaryW >= 10
	}

	upgradable, fixable := 0, 0
	for _, g := range groups {
		b.WriteString("\n")
		b.WriteString(groupHeader(s, g))
		b.WriteString("\n")
		for _, f := range g.findings {
			sev := f.Severity.String()
			fix := truncate(fixCell(f), maxFixW)
			fixRole := "version"
			if f.FixedIn == "" {
				fixRole = "nofix"
			}
			row := fmt.Sprintf("  %s%s  %s%s  %s",
				s.paint(severityRole(f.Severity), sev), pad(sev, sevW),
				s.link(f.URL, s.paint("id", f.VulnID)), pad(f.VulnID, idW),
				s.paint(fixRole, fix))
			if summary := truncate(f.Summary, summaryW); showSummary && summary != "" {
				row += pad(fix, fixW) + "  " + s.paint("summary", summary)
			}
			b.WriteString(row)
			b.WriteByte('\n')
		}
		if g.upgrade != "" {
			upgradable++
			fixable += g.fixes
		}
	}

	if upgradable > 0 {
		fmt.Fprintf(&b, "\n%s\n", s.paint("upgrade", fmt.Sprintf("Upgrading %s fixes %d of %s.",
			plural(upgradable, "package"), fixable, plural(len(r.Findings), "vulnerability"))))
	}
	writeIgnored(&b, s, r)
	_, err := io.WriteString(w, b.String())
	return err
}

// writeIgnored notes suppressed findings, so they are never invisible.
func writeIgnored(b *strings.Builder, s styler, r *types.Report) {
	if len(r.Ignored) == 0 {
		return
	}
	ids := make([]string, len(r.Ignored))
	for i, f := range r.Ignored {
		ids[i] = f.VulnID
	}
	const maxIDs = 5
	list := strings.Join(ids[:min(len(ids), maxIDs)], ", ")
	if len(ids) > maxIDs {
		list += fmt.Sprintf(", +%d more", len(ids)-maxIDs)
	}
	fmt.Fprintf(b, "%s\n", s.paint("meta", fmt.Sprintf("Ignored %s by %s: %s",
		plural(len(r.Ignored), "vulnerability"), r.IgnoreFile, list)))
}

// groupFindings groups findings by package, most severe package first.
func groupFindings(findings []types.Finding) []group {
	index := make(map[string]int)
	var groups []group
	for _, f := range findings {
		i, ok := index[f.Package.Key()]
		if !ok {
			i = len(groups)
			index[f.Package.Key()] = i
			groups = append(groups, group{pkg: f.Package})
		}
		groups[i].findings = append(groups[i].findings, f)
		groups[i].top = max(groups[i].top, f.Severity)
	}

	for i := range groups {
		g := &groups[i]
		sort.SliceStable(g.findings, func(a, b int) bool {
			if g.findings[a].Severity != g.findings[b].Severity {
				return g.findings[a].Severity > g.findings[b].Severity
			}
			return g.findings[a].VulnID < g.findings[b].VulnID
		})
		g.upgrade, g.fixes = bestUpgrade(g.pkg.Ecosystem, g.findings)
	}

	sort.SliceStable(groups, func(a, b int) bool {
		ga, gb := groups[a], groups[b]
		if ga.top != gb.top {
			return ga.top > gb.top
		}
		if len(ga.findings) != len(gb.findings) {
			return len(ga.findings) > len(gb.findings)
		}
		return ga.pkg.Name < gb.pkg.Name
	})
	return groups
}

// bestUpgrade returns the highest single fixed version among findings and
// how many findings it fixes. Findings with no fix, or with a list of
// possible fixes, are not counted.
func bestUpgrade(eco string, findings []types.Finding) (string, int) {
	best, count := "", 0
	for _, f := range findings {
		if f.FixedIn == "" || strings.Contains(f.FixedIn, ",") || !version.Comparable(eco, f.FixedIn) {
			continue
		}
		count++
		if best == "" {
			best = f.FixedIn
		} else if c, _ := version.Compare(eco, f.FixedIn, best); c > 0 {
			best = f.FixedIn
		}
	}
	return best, count
}

func groupHeader(s styler, g group) string {
	var advice string
	switch {
	case g.upgrade == "":
		advice = s.paint("nofix", "no fix available")
	case g.fixes == len(g.findings):
		advice = s.paint("upgrade", "→ "+g.upgrade)
	default:
		advice = s.paint("partial", fmt.Sprintf("→ %s fixes %d of %d", g.upgrade, g.fixes, len(g.findings)))
	}

	meta := []string{g.pkg.Ecosystem, location(g.pkg)}
	if !g.pkg.Direct && declaredInManifest(g.pkg) {
		meta = append(meta, "indirect")
	}
	if g.pkg.Dev {
		meta = append(meta, "dev")
	}
	return fmt.Sprintf("%s %s  %s  %s",
		s.paint("package", g.pkg.Name),
		s.paint("version", g.pkg.Version),
		advice,
		s.paint("meta", strings.Join(meta, " · ")))
}

func severityCounts(s styler, findings []types.Finding) string {
	counts := make(map[types.Severity]int)
	for _, f := range findings {
		counts[f.Severity]++
	}
	var parts []string
	for sev := types.SeverityCritical; sev >= types.SeverityUnknown; sev-- {
		if counts[sev] > 0 {
			label := fmt.Sprintf("%d %s", counts[sev], strings.ToLower(sev.String()))
			parts = append(parts, s.paint(severityRole(sev), label))
		}
	}
	return strings.Join(parts, " · ")
}

func fixCell(f types.Finding) string {
	if f.FixedIn == "" {
		return "no fix"
	}
	return f.FixedIn
}

func location(p types.Package) string {
	switch len(p.Locations) {
	case 0:
		return "-"
	case 1:
		return p.Locations[0].String()
	}
	return fmt.Sprintf("%s (+%d)", p.Locations[0], len(p.Locations)-1)
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	if stem, ok := strings.CutSuffix(noun, "y"); ok {
		return fmt.Sprintf("%d %sies", n, stem)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// width is the display width of plain text, counted in runes.
func width(s string) int { return utf8.RuneCountInString(s) }

func pad(s string, w int) string {
	return strings.Repeat(" ", max(w-width(s), 0))
}

// truncate collapses whitespace and shortens s to n runes; n <= 0 means no
// limit.
func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if n <= 0 || width(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// declaredInManifest reports whether the package comes from a dependency
// manifest, where direct and indirect are meaningful. OS packages and
// modules read from binaries have no such distinction.
func declaredInManifest(p types.Package) bool {
	for _, l := range p.Locations {
		switch path.Base(l.Path) {
		case "go.mod", "package-lock.json":
			return true
		}
	}
	return false
}
