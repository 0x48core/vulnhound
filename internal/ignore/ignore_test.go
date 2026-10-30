package ignore

import (
	"strings"
	"testing"
	"time"

	"github.com/0x48core/vulnhound/pkg/types"
)

func TestParse(t *testing.T) {
	rules, err := Parse(strings.NewReader(`
# comment only

GO-2026-6860
GHSA-j88v  pkg=github.com/jackc/pgx/v5  until=2026-12-31  # upgrade planned
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2: %+v", len(rules), rules)
	}
	r := rules[1]
	if r.ID != "GHSA-j88v" || r.Package != "github.com/jackc/pgx/v5" || r.Reason != "upgrade planned" || r.Line != 5 {
		t.Errorf("rule = %+v", r)
	}
	if got := r.Until.Format(time.DateOnly); got != "2026-12-31" {
		t.Errorf("until = %s", got)
	}

	for _, bad := range []string{"X until=31/12/2026", "X pkg=", "X reason"} {
		if _, err := Parse(strings.NewReader(bad)); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestApply(t *testing.T) {
	pgx := types.Package{Name: "github.com/jackc/pgx/v5"}
	other := types.Package{Name: "other"}
	findings := []types.Finding{
		{Package: pgx, VulnID: "GHSA-aaaa", Aliases: []string{"CVE-2026-1"}},
		{Package: pgx, VulnID: "GHSA-bbbb"},
		{Package: other, VulnID: "GHSA-bbbb"},
		{Package: other, VulnID: "GHSA-cccc"},
	}
	rules := []Rule{
		{ID: "cve-2026-1", Reason: "alias, case-insensitive", Line: 1},
		{ID: "GHSA-bbbb", Package: "github.com/jackc/pgx/v5", Line: 2},
		{ID: "GHSA-cccc", Until: date("2026-01-01"), Line: 3}, // expired
	}
	kept, ignored := Apply(rules, findings, date("2026-10-30"))

	if len(ignored) != 2 || ignored[0].VulnID != "GHSA-aaaa" || ignored[0].Reason != "alias, case-insensitive" {
		t.Errorf("ignored = %+v", ignored)
	}
	if len(kept) != 2 || kept[0].Package.Name != "other" || kept[1].VulnID != "GHSA-cccc" {
		t.Errorf("kept = %+v; pkg= must scope the rule and expired rules must not apply", kept)
	}
}

func TestApplyUntilIsInclusive(t *testing.T) {
	f := []types.Finding{{VulnID: "X"}}
	_, ignored := Apply([]Rule{{ID: "X", Until: date("2026-10-30")}}, f, date("2026-10-30").Add(15*time.Hour))
	if len(ignored) != 1 {
		t.Error("a rule must still apply on its until date")
	}
	if ignored[0].Until != "2026-10-30" {
		t.Errorf("until = %q", ignored[0].Until)
	}
}

func date(s string) time.Time {
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err)
	}
	return t
}
