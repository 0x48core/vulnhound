package matcher

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/0x48core/vulnhound/pkg/types"
)

func TestCVSS3BaseScore(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N", 0},
	}
	for _, tt := range tests {
		got, err := cvss3BaseScore(tt.vector)
		if err != nil {
			t.Errorf("%s: %v", tt.vector, err)
			continue
		}
		if got != tt.want {
			t.Errorf("%s = %v, want %v", tt.vector, got, tt.want)
		}
	}
	for _, bad := range []string{"CVSS:4.0/AV:N", "CVSS:3.1/AV:X/AC:L", "garbage"} {
		if _, err := cvss3BaseScore(bad); err == nil {
			t.Errorf("%s: expected error", bad)
		}
	}
}

// fakeOSV serves canned querybatch results keyed by "name@version" and
// vulnerability records keyed by ID. A result with two pages is split on
// next_page_token to exercise pagination.
type fakeOSV struct {
	results map[string][][]string // name@version -> pages of IDs
	vulns   map[string]string     // id -> JSON record
}

func (f *fakeOSV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
		var req struct {
			Queries []osvQuery `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		type vuln struct {
			ID string `json:"id"`
		}
		type result struct {
			Vulns         []vuln `json:"vulns,omitempty"`
			NextPageToken string `json:"next_page_token,omitempty"`
		}
		var resp struct {
			Results []result `json:"results"`
		}
		for _, q := range req.Queries {
			pages := f.results[q.Package.Name+"@"+q.Version]
			page := 0
			if q.PageToken != "" {
				page = 1
			}
			var res result
			if page < len(pages) {
				for _, id := range pages[page] {
					res.Vulns = append(res.Vulns, vuln{id})
				}
				if page+1 < len(pages) {
					res.NextPageToken = "page2"
				}
			}
			resp.Results = append(resp.Results, res)
		}
		json.NewEncoder(w).Encode(resp)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
		rec, ok := f.vulns[strings.TrimPrefix(r.URL.Path, "/v1/vulns/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(rec))
	default:
		http.NotFound(w, r)
	}
}

func TestOSVMatch(t *testing.T) {
	fake := &fakeOSV{
		results: map[string][][]string{
			"github.com/gin-gonic/gin@v1.9.0": {{"GO-2023-1737"}, {"GHSA-2c4m-59x9-fr2g"}},
			"lodash@4.17.15":                  {{"GHSA-p6mc-m468-83gw", "GHSA-old-withdrawn"}},
		},
		vulns: map[string]string{
			// The Go record has no severity; its GHSA alias does.
			"GO-2023-1737": `{"id":"GO-2023-1737","aliases":["CVE-2023-29401","GHSA-2c4m-59x9-fr2g"],
				"summary":"Improper handling of filenames in gin",
				"affected":[{"package":{"ecosystem":"Go","name":"github.com/gin-gonic/gin"},
					"ranges":[{"type":"SEMVER","events":[{"introduced":"1.3.1-0.20190301021747-ccb9e902956d"},{"fixed":"1.9.1"}]}]}]}`,
			"GHSA-2c4m-59x9-fr2g": `{"id":"GHSA-2c4m-59x9-fr2g","aliases":["CVE-2023-29401"],
				"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"}],
				"affected":[{"package":{"ecosystem":"Go","name":"github.com/gin-gonic/gin"},
					"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.3.1"},{"fixed":"1.9.1"}]}]}]}`,
			"GHSA-p6mc-m468-83gw": `{"id":"GHSA-p6mc-m468-83gw","aliases":["CVE-2020-8203"],
				"summary":"Prototype Pollution in lodash",
				"database_specific":{"severity":"HIGH"},
				"affected":[{"package":{"ecosystem":"npm","name":"lodash"},
					"ranges":[{"type":"SEMVER","events":[{"introduced":"3.7.0"},{"fixed":"4.17.19"}]}]}]}`,
			"GHSA-old-withdrawn": `{"id":"GHSA-old-withdrawn","withdrawn":"2021-01-01T00:00:00Z"}`,
		},
	}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	o := NewOSV("vulnhound-test")
	o.BaseURL = srv.URL
	pkgs := []types.Package{
		{Name: "github.com/gin-gonic/gin", Version: "v1.9.0", Ecosystem: types.EcosystemGo},
		{Name: "lodash", Version: "4.17.15", Ecosystem: types.EcosystemNpm},
		{Name: "left-pad", Version: "1.3.0", Ecosystem: types.EcosystemNpm},
	}
	findings, err := o.Match(context.Background(), pkgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(findings), findings)
	}

	// Sorted by severity: HIGH lodash first, then MEDIUM gin.
	lodash, gin := findings[0], findings[1]
	if lodash.VulnID != "GHSA-p6mc-m468-83gw" || lodash.Severity != types.SeverityHigh || lodash.FixedIn != "4.17.19" {
		t.Errorf("lodash finding = %+v", lodash)
	}
	if gin.VulnID != "GHSA-2c4m-59x9-fr2g" {
		t.Errorf("gin representative = %s, want the GHSA record that carries severity", gin.VulnID)
	}
	if gin.Severity != types.SeverityMedium || gin.CVSSScore != 4.3 {
		t.Errorf("gin severity = %v (%v), want MEDIUM (4.3)", gin.Severity, gin.CVSSScore)
	}
	if gin.FixedIn != "v1.9.1" {
		t.Errorf("gin fixed = %q, want v1.9.1", gin.FixedIn)
	}
	if gin.Summary != "Improper handling of filenames in gin" {
		t.Errorf("gin summary = %q, want it borrowed from the GO record", gin.Summary)
	}
	if want := []string{"CVE-2023-29401", "GO-2023-1737"}; !reflect.DeepEqual(gin.Aliases, want) {
		t.Errorf("gin aliases = %v, want %v", gin.Aliases, want)
	}
}

func TestOSVMatchHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer srv.Close()
	o := NewOSV("")
	o.BaseURL = srv.URL
	_, err := o.Match(context.Background(), []types.Package{{Name: "x", Version: "1.0.0", Ecosystem: "npm"}})
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("err = %v, want a 400 error", err)
	}
}

func TestFixedVersionFallsBackToList(t *testing.T) {
	var v osvVuln
	json.Unmarshal([]byte(`{"affected":[{"package":{"ecosystem":"npm","name":"x"},"ranges":[
		{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.0"}]},
		{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"2.0.5"}]}]}]}`), &v)
	p := types.Package{Name: "x", Version: "2.0.1", Ecosystem: "npm"}
	if got := fixedVersion(p, &v); got != "2.0.5" {
		t.Errorf("in-range fix = %q, want 2.0.5", got)
	}
	p.Version = "not-semver"
	if got := fixedVersion(p, &v); got != "1.2.0, 2.0.5" {
		t.Errorf("fallback = %q, want both fixes", got)
	}
}
