package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x48core/vulnhound/pkg/types"
)

// newFakeOSV reports one HIGH vulnerability for lodash@4.17.15 and nothing
// for anything else.
func newFakeOSV(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			var req struct {
				Queries []struct {
					Package struct{ Name string } `json:"package"`
					Version string                `json:"version"`
				} `json:"queries"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			var results []string
			for _, q := range req.Queries {
				if q.Package.Name == "lodash" && q.Version == "4.17.15" {
					results = append(results, `{"vulns":[{"id":"GHSA-p6mc-m468-83gw"}]}`)
				} else {
					results = append(results, `{}`)
				}
			}
			w.Write([]byte(`{"results":[` + strings.Join(results, ",") + `]}`))
		case "/v1/vulns/GHSA-p6mc-m468-83gw":
			w.Write([]byte(`{"id":"GHSA-p6mc-m468-83gw","summary":"Prototype Pollution in lodash",
				"database_specific":{"severity":"HIGH"},
				"affected":[{"package":{"ecosystem":"npm","name":"lodash"},
					"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.19"}]}]}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func writeProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	lock := `{"lockfileVersion":3,"packages":{
		"":{"dependencies":{"lodash":"^4.17.0"},"devDependencies":{"jest":"*"}},
		"node_modules/lodash":{"version":"4.17.15"},
		"node_modules/jest":{"version":"29.0.0","dev":true}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestScanDirTable(t *testing.T) {
	osv := newFakeOSV(t)
	out, err := runCLI(t, "scan", "dir", writeProject(t), "--osv-url", osv.URL)
	if err != nil {
		t.Fatalf("scan failed: %v\n%s", err, out)
	}
	for _, want := range []string{"Packages: 2", "1 HIGH", "lodash", "GHSA-p6mc-m468-83gw", "4.17.19"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("color codes written to a non-terminal")
	}
}

func TestScanDirJSONSkipDev(t *testing.T) {
	osv := newFakeOSV(t)
	out, err := runCLI(t, "scan", "dir", writeProject(t), "--osv-url", osv.URL, "--format", "json", "--skip-dev")
	if err != nil {
		t.Fatalf("scan failed: %v\n%s", err, out)
	}
	var r types.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(r.Packages) != 1 || r.Packages[0].Name != "lodash" {
		t.Errorf("packages = %+v, want only lodash", r.Packages)
	}
	if len(r.Findings) != 1 || r.Findings[0].Severity != types.SeverityHigh {
		t.Errorf("findings = %+v", r.Findings)
	}
}

func TestScanDirFailOn(t *testing.T) {
	osv := newFakeOSV(t)
	dir := writeProject(t)

	if _, err := runCLI(t, "scan", "dir", dir, "--osv-url", osv.URL, "--fail-on", "high"); !errors.Is(err, errFindings) {
		t.Errorf("--fail-on high: err = %v, want errFindings", err)
	}
	if _, err := runCLI(t, "scan", "dir", dir, "--osv-url", osv.URL, "--fail-on", "critical"); err != nil {
		t.Errorf("--fail-on critical: err = %v, want nil", err)
	}
	if _, err := runCLI(t, "scan", "dir", dir, "--fail-on", "bogus"); err == nil || errors.Is(err, errFindings) {
		t.Errorf("--fail-on bogus: err = %v, want a usage error", err)
	}
}
