package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/0x48core/vulnhound/pkg/types"
)

func sampleReport() *types.Report {
	pgx := types.Package{Name: "github.com/jackc/pgx/v5", Version: "v5.7.5", Ecosystem: "Go", Locations: []types.Location{{Path: "go.mod", Line: 5}}, Direct: true}
	crypto := types.Package{Name: "golang.org/x/crypto", Version: "v0.55.0", Ecosystem: "Go", Locations: []types.Location{{Path: "go.mod", Line: 9}, {Path: "tools/go.mod"}}}
	return &types.Report{
		Target:   "/src/app",
		Packages: []types.Package{pgx, crypto, {Name: "clean", Version: "1.0.0", Ecosystem: "npm"}},
		Findings: []types.Finding{
			{Package: crypto, VulnID: "GO-2026-5932", Severity: types.SeverityUnknown, Summary: "openpgp is   unmaintained"},
			{Package: crypto, VulnID: "GO-2026-6354", Severity: types.SeverityUnknown, FixedIn: "v0.56.0", Summary: "DoS on deadlocked channel"},
			{Package: pgx, VulnID: "GHSA-j88v-2chj-qfwx", Severity: types.SeverityLow, FixedIn: "v5.9.2", Summary: "SQL injection", URL: "https://osv.dev/vulnerability/GHSA-j88v-2chj-qfwx"},
			{Package: pgx, VulnID: "GHSA-9jj7-4m8r-rfcm", Severity: types.SeverityCritical, FixedIn: "v5.9.0", Summary: "Memory-safety vulnerability"},
		},
	}
}

func render(t *testing.T, r *types.Report, opts Options) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, "table", r, opts); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestTablePlain(t *testing.T) {
	got := render(t, sampleReport(), Options{})
	want := `Scanned 3 packages in /src/app
Found 4 vulnerabilities in 2 packages: 1 critical · 1 low · 2 unknown

github.com/jackc/pgx/v5 v5.7.5  → v5.9.2  Go · go.mod:5
  CRITICAL  GHSA-9jj7-4m8r-rfcm  v5.9.0   Memory-safety vulnerability
  LOW       GHSA-j88v-2chj-qfwx  v5.9.2   SQL injection

golang.org/x/crypto v0.55.0  → v0.56.0 fixes 1 of 2  Go · go.mod:9 (+1) · indirect
  UNKNOWN   GO-2026-5932         no fix   openpgp is unmaintained
  UNKNOWN   GO-2026-6354         v0.56.0  DoS on deadlocked channel

Upgrading 2 packages fixes 3 of 4 vulnerabilities.
`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestTableNoFindings(t *testing.T) {
	r := &types.Report{Target: "/src/app", Packages: make([]types.Package, 1)}
	got := render(t, r, Options{})
	if want := "Scanned 1 package in /src/app\n✔ No known vulnerabilities found.\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestTableNoFixAvailable(t *testing.T) {
	p := types.Package{Name: "x", Version: "1.0.0", Ecosystem: "npm", Direct: true}
	r := &types.Report{Target: "/t", Packages: []types.Package{p}, Findings: []types.Finding{
		{Package: p, VulnID: "GHSA-1", Severity: types.SeverityHigh},
	}}
	got := render(t, r, Options{})
	if !strings.Contains(got, "x 1.0.0  no fix available") {
		t.Errorf("missing no-fix advice:\n%s", got)
	}
	if strings.Contains(got, "Upgrading") {
		t.Errorf("no upgrade footer expected when nothing is fixable:\n%s", got)
	}
}

func TestTableColorAlignment(t *testing.T) {
	// A theme with different code lengths per role must not shift columns.
	theme := DefaultTheme()
	theme["critical"] = "1;97;41"
	theme["low"] = "36"
	got := stripANSI(render(t, sampleReport(), Options{Color: true, Theme: theme}))
	plain := render(t, sampleReport(), Options{})
	if got != plain {
		t.Errorf("colored output differs from plain once codes are stripped:\n%s\n---\n%s", got, plain)
	}
}

func TestTableHyperlinksAndWidth(t *testing.T) {
	got := render(t, sampleReport(), Options{Color: true, Hyperlinks: true, Width: 60})
	link := "\x1b]8;;https://osv.dev/vulnerability/GHSA-j88v-2chj-qfwx\x1b\\"
	if !strings.Contains(got, link) {
		t.Errorf("missing OSC 8 hyperlink:\n%q", got)
	}
	for line := range strings.SplitSeq(stripANSI(got), "\n") {
		if strings.HasPrefix(line, "  ") && width(line) > 60 {
			t.Errorf("row exceeds width 60 (%d): %q", width(line), line)
		}
	}

	// Too narrow for a useful summary: drop it instead of wrapping.
	narrow := stripANSI(render(t, sampleReport(), Options{Width: 45}))
	if strings.Contains(narrow, "Memory") || strings.Contains(narrow, "  v5.9.0 ") {
		t.Errorf("summaries (and trailing padding) should be dropped at width 45:\n%s", narrow)
	}
}

func TestParseTheme(t *testing.T) {
	theme, errs := ParseTheme("critical=1;31 : nofix= : bogus=1 : high=red : low")
	if theme["critical"] != "1;31" || theme["nofix"] != "" {
		t.Errorf("overrides not applied: critical=%q nofix=%q", theme["critical"], theme["nofix"])
	}
	if theme["high"] != DefaultTheme()["high"] {
		t.Errorf("invalid entry must keep the default, got high=%q", theme["high"])
	}
	if len(errs) != 3 {
		t.Errorf("got %d errors, want 3 (unknown role, bad SGR, missing '='): %v", len(errs), errs)
	}
}

func TestJSONUnchanged(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "json", sampleReport(), Options{Color: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "\x1b") {
		t.Error("JSON must never contain escape codes")
	}
	var r types.Report
	if err := json.Unmarshal(buf.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
}

// stripANSI removes SGR color codes and OSC 8 hyperlinks.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\x1b' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch s[i+1] {
		case '[': // CSI ... final byte 'm'
			j := strings.IndexByte(s[i:], 'm')
			i += j
		case ']': // OSC ... ST (ESC \)
			j := strings.Index(s[i:], "\x1b\\")
			i += j + 1
		}
	}
	return b.String()
}

func TestSARIF(t *testing.T) {
	r := sampleReport()
	var buf bytes.Buffer
	if err := Write(&buf, "sarif", r, Options{ToolVersion: "v9.9.9", PathPrefix: "services/api", Color: true}); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	if run.Tool.Driver.Version != "v9.9.9" || len(run.Tool.Driver.Rules) != 4 {
		t.Errorf("driver = %+v", run.Tool.Driver)
	}
	// crypto is declared in two files, so its 2 findings give 4 results.
	if len(run.Results) != 6 {
		t.Fatalf("got %d results, want 6", len(run.Results))
	}
	byRule := map[string]sarifRule{}
	for _, rule := range run.Tool.Driver.Rules {
		byRule[rule.ID] = rule
	}
	if got := byRule["GHSA-9jj7-4m8r-rfcm"]; got.Properties.SecuritySeverity != "9.5" || got.DefaultConfiguration.Level != "error" {
		t.Errorf("critical rule = %+v", got)
	}
	if got := byRule["GO-2026-5932"]; got.Properties.SecuritySeverity != "" || got.DefaultConfiguration.Level != "warning" {
		t.Errorf("unknown-severity rule = %+v", got)
	}

	seen := map[string]bool{}
	for _, res := range run.Results {
		loc := res.Locations[0].PhysicalLocation
		seen[fmt.Sprintf("%s %s:%d", res.RuleID, loc.ArtifactLocation.URI, loc.Region.StartLine)] = true
		if res.PartialFingerprints["vulnhound/v1"] == "" {
			t.Errorf("%s: missing fingerprint", res.RuleID)
		}
	}
	for _, want := range []string{
		"GHSA-9jj7-4m8r-rfcm services/api/go.mod:5",
		"GO-2026-5932 services/api/go.mod:9",
		"GO-2026-5932 services/api/tools/go.mod:1", // unknown line falls back to 1
	} {
		if !seen[want] {
			t.Errorf("missing result %q in %v", want, seen)
		}
	}
	if strings.Contains(buf.String(), "\x1b") {
		t.Error("SARIF must never contain escape codes")
	}
}

func TestTableIgnoredFooter(t *testing.T) {
	r := sampleReport()
	r.Ignored = []types.IgnoredFinding{{Finding: types.Finding{VulnID: "GHSA-skip"}}}
	r.IgnoreFile = ".vulnhoundignore"
	if got := render(t, r, Options{}); !strings.HasSuffix(got, "Ignored 1 vulnerability by .vulnhoundignore: GHSA-skip\n") {
		t.Errorf("missing ignored footer:\n%s", got)
	}
}
