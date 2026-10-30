package matcher

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0x48core/vulnhound/internal/osvdb"
	"github.com/0x48core/vulnhound/pkg/types"
)

func TestInEvents(t *testing.T) {
	ev := func(kind, v string) osvEvent {
		switch kind {
		case "i":
			return osvEvent{Introduced: v}
		case "f":
			return osvEvent{Fixed: v}
		}
		return osvEvent{LastAffected: v}
	}
	tests := []struct {
		eco, v string
		events []osvEvent
		want   bool
	}{
		{"Go", "v1.9.0", []osvEvent{ev("i", "0"), ev("f", "1.9.1")}, true},
		{"Go", "v1.9.1", []osvEvent{ev("i", "0"), ev("f", "1.9.1")}, false},
		{"Go", "v1.2.0", []osvEvent{ev("i", "1.3.0"), ev("f", "1.4.0")}, false},
		// Two segments, listed out of order: sorting must not matter.
		{"npm", "2.0.1", []osvEvent{ev("i", "2.0.0"), ev("f", "2.0.5"), ev("i", "0"), ev("f", "1.2.0")}, true},
		{"npm", "1.5.0", []osvEvent{ev("i", "2.0.0"), ev("f", "2.0.5"), ev("i", "0"), ev("f", "1.2.0")}, false},
		// last_affected is inclusive.
		{"npm", "3.0.0", []osvEvent{ev("i", "0"), ev("l", "3.0.0")}, true},
		{"npm", "3.0.1", []osvEvent{ev("i", "0"), ev("l", "3.0.0")}, false},
		// No fix yet: affected from introduced onwards.
		{"Alpine:v3.19", "1.2.4_git20230717-r4", []osvEvent{ev("i", "0")}, true},
		// Distro ordering: ~ sorts before the release.
		{"Debian:12", "3.0.11-1~deb12u1", []osvEvent{ev("i", "0"), ev("f", "3.0.11-1~deb12u2")}, true},
		{"Debian:12", "3.0.11-1~deb12u2", []osvEvent{ev("i", "0"), ev("f", "3.0.11-1~deb12u2")}, false},
		// Uncomparable versions never match a range.
		{"PyPI", "1.0", []osvEvent{ev("i", "0")}, false},
		{"Go", "v1.0.0", []osvEvent{ev("i", "garbage")}, false},
	}
	for _, tt := range tests {
		if got := inEvents(tt.eco, tt.v, tt.events); got != tt.want {
			t.Errorf("inEvents(%s, %s, %+v) = %v, want %v", tt.eco, tt.v, tt.events, got, tt.want)
		}
	}
}

// newOfflineDB installs fake dumps through the real update path.
func newOfflineDB(t *testing.T, dumps map[string]map[string]string) *osvdb.DB {
	t.Helper()
	zips := map[string][]byte{}
	for eco, files := range dumps {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for name, body := range files {
			w, _ := zw.Create(name)
			w.Write([]byte(body))
		}
		zw.Close()
		zips["/"+eco+"/all.zip"] = buf.Bytes()
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, ok := zips[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(data)
	}))
	t.Cleanup(srv.Close)
	db := osvdb.New(t.TempDir())
	db.BaseURL = srv.URL
	for eco := range dumps {
		if _, err := db.Update(context.Background(), eco); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOfflineMatch(t *testing.T) {
	db := newOfflineDB(t, map[string]map[string]string{
		"Go": {
			// Same records as the online test: aliases must merge the same way.
			"GO-2023-1737.json": `{"id":"GO-2023-1737","aliases":["CVE-2023-29401","GHSA-2c4m-59x9-fr2g"],
				"summary":"Improper handling of filenames in gin",
				"affected":[{"package":{"ecosystem":"Go","name":"github.com/gin-gonic/gin"},
					"ranges":[{"type":"SEMVER","events":[{"introduced":"1.3.1-0.20190301021747-ccb9e902956d"},{"fixed":"1.9.1"}]}]}]}`,
			"GHSA-2c4m-59x9-fr2g.json": `{"id":"GHSA-2c4m-59x9-fr2g","aliases":["CVE-2023-29401"],
				"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"}],
				"affected":[{"package":{"ecosystem":"Go","name":"github.com/gin-gonic/gin"},
					"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.3.1"},{"fixed":"1.9.1"}]}]}]}`,
			// Fixed before the installed version: must not match.
			"GO-OLD.json": `{"id":"GO-OLD","affected":[{"package":{"ecosystem":"Go","name":"github.com/gin-gonic/gin"},
				"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.4.0"}]}]}]}`,
			// Matched by the explicit versions list only.
			"GO-LIST.json": `{"id":"GO-LIST","affected":[{"package":{"ecosystem":"Go","name":"example.com/x"},"versions":["v0.1.0"]}]}`,
		},
		"Debian": {
			"DSA-1.json": `{"id":"DSA-1","summary":"openssl security update","affected":[
				{"package":{"ecosystem":"Debian:12","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.11-1~deb12u2"}]}]},
				{"package":{"ecosystem":"Debian:11","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.1.1w-0+deb11u1"}]}]}]}`,
		},
	})
	m := &Offline{DB: db}
	pkgs := []types.Package{
		{Name: "github.com/gin-gonic/gin", Version: "v1.9.0", Ecosystem: "Go"},
		{Name: "example.com/x", Version: "v0.1.0", Ecosystem: "Go"},
		{Name: "example.com/clean", Version: "v1.0.0", Ecosystem: "Go"},
		{Name: "libssl3", Version: "3.0.11-1~deb12u1", Ecosystem: "Debian:12", SourceName: "openssl"},
		{Name: "libcrypto3", Version: "3.0.11-1~deb12u1", Ecosystem: "Debian:12", SourceName: "openssl"},
	}
	findings, err := m.Match(context.Background(), pkgs)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]types.Finding{}
	for _, f := range findings {
		got[f.Package.Name+" "+f.VulnID] = f
	}
	if len(findings) != 4 {
		t.Errorf("got %d findings, want 4: %v", len(findings), keys(got))
	}
	gin := got["github.com/gin-gonic/gin GHSA-2c4m-59x9-fr2g"]
	if gin.Severity != types.SeverityMedium || gin.FixedIn != "v1.9.1" || len(gin.Aliases) != 2 {
		t.Errorf("gin = %+v (want the GO and GHSA records merged, as online)", gin)
	}
	if _, ok := got["example.com/x GO-LIST"]; !ok {
		t.Error("explicit versions list not matched")
	}
	for _, name := range []string{"libssl3", "libcrypto3"} {
		if f := got[name+" DSA-1"]; f.FixedIn != "3.0.11-1~deb12u2" {
			t.Errorf("%s: %+v (Debian:12 range only, not Debian:11)", name, f)
		}
	}
}

func TestOfflineMissingEcosystem(t *testing.T) {
	db := newOfflineDB(t, map[string]map[string]string{"Go": {}})
	_, err := (&Offline{DB: db}).Match(context.Background(), []types.Package{
		{Name: "lodash", Version: "4.17.15", Ecosystem: "npm"},
		{Name: "musl", Version: "1.2.4-r2", Ecosystem: "Alpine:v3.19"},
	})
	if err == nil || !strings.Contains(err.Error(), "vulnhound db update Alpine npm") {
		t.Errorf("err = %v, want a hint naming the missing ecosystems", err)
	}
}

func TestOfflineWarnsWhenStale(t *testing.T) {
	db := newOfflineDB(t, map[string]map[string]string{"Go": {}})
	m := &Offline{DB: db, Now: func() time.Time { return time.Now().Add(30 * 24 * time.Hour) }}
	// Staleness is a warning, not an error.
	if _, err := m.Match(context.Background(), []types.Package{{Name: "x", Version: "v1.0.0", Ecosystem: "Go"}}); err != nil {
		t.Fatal(err)
	}
}

func keys(m map[string]types.Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
