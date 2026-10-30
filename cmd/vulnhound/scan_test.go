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
	for _, want := range []string{"Scanned 2 packages", "1 high", "lodash 4.17.15  → 4.17.19", "GHSA-p6mc-m468-83gw"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Error("escape codes written to a non-terminal")
	}
}

func TestScanDirColor(t *testing.T) {
	osv := newFakeOSV(t)
	dir := writeProject(t)

	t.Setenv("VULNHOUND_COLORS", "high=35")
	out, err := runCLI(t, "scan", "dir", dir, "--osv-url", osv.URL, "--color", "always")
	if err != nil {
		t.Fatalf("scan failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "\x1b[35mHIGH\x1b[0m") {
		t.Errorf("--color always with a custom theme should color HIGH magenta:\n%q", out)
	}
	if strings.Contains(out, "\x1b]8;") {
		t.Error("hyperlinks must only be written to a terminal")
	}

	out, err = runCLI(t, "scan", "dir", dir, "--osv-url", osv.URL, "--color", "always", "--no-color")
	if err != nil || strings.Contains(out, "\x1b") {
		t.Errorf("--no-color must win: err=%v\n%q", err, out)
	}

	if _, err := runCLI(t, "scan", "dir", dir, "--color", "sometimes"); err == nil || !strings.Contains(err.Error(), "--color") {
		t.Errorf("--color sometimes: err = %v, want a usage error", err)
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

func TestScanDirIgnoreFile(t *testing.T) {
	osv := newFakeOSV(t)
	dir := writeProject(t)
	rules := "GHSA-p6mc-m468-83gw  pkg=lodash  # not reachable\n"
	if err := os.WriteFile(filepath.Join(dir, ".vulnhoundignore"), []byte(rules), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runCLI(t, "scan", "dir", dir, "--osv-url", osv.URL, "--fail-on", "low")
	if err != nil {
		t.Fatalf("an ignored finding must not trip --fail-on: %v\n%s", err, out)
	}
	if !strings.Contains(out, "No known vulnerabilities") || !strings.Contains(out, "Ignored 1 vulnerability by .vulnhoundignore: GHSA-p6mc-m468-83gw") {
		t.Errorf("unexpected output:\n%s", out)
	}

	out, err = runCLI(t, "scan", "dir", dir, "--osv-url", osv.URL, "-f", "json")
	if err != nil {
		t.Fatal(err)
	}
	var r types.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 || len(r.Ignored) != 1 || r.Ignored[0].Reason != "not reachable" {
		t.Errorf("findings=%+v ignored=%+v", r.Findings, r.Ignored)
	}

	// An explicit --ignore-file replaces the default, and a broken file fails fast.
	bad := filepath.Join(t.TempDir(), "bad-ignore")
	os.WriteFile(bad, []byte("GHSA-x until=never\n"), 0o644)
	if _, err := runCLI(t, "scan", "dir", dir, "--osv-url", osv.URL, "--ignore-file", bad); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Errorf("bad ignore file: err = %v, want a line-numbered error", err)
	}
}

func TestScanDirExclude(t *testing.T) {
	osv := newFakeOSV(t)
	dir := writeProject(t)
	fixture := filepath.Join(dir, "testdata", "old")
	os.MkdirAll(fixture, 0o755)
	os.WriteFile(filepath.Join(fixture, "go.mod"), []byte("module x\nrequire golang.org/x/text v0.3.0\n"), 0o644)

	out, err := runCLI(t, "scan", "dir", dir, "--osv-url", osv.URL, "--exclude", "testdata")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Scanned 2 packages") {
		t.Errorf("testdata/ should be excluded:\n%s", out)
	}
	if _, err := runCLI(t, "scan", "dir", dir, "--exclude", "[bad"); err == nil || !strings.Contains(err.Error(), "invalid exclude pattern") {
		t.Errorf("--exclude [bad: err = %v", err)
	}
}

func TestScanDirSARIF(t *testing.T) {
	osv := newFakeOSV(t)
	dir := writeProject(t)
	out, err := runCLI(t, "scan", "dir", dir, "--osv-url", osv.URL, "-f", "sarif")
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string }    `json:"artifactLocation"`
						Region           struct{ StartLine int } `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\n%s", err, out)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 || len(log.Runs[0].Results) != 1 {
		t.Fatalf("unexpected SARIF:\n%s", out)
	}
	loc := log.Runs[0].Results[0].Locations[0].PhysicalLocation
	// The temp dir is outside the working directory, so URIs stay target-relative.
	if loc.ArtifactLocation.URI != "package-lock.json" || loc.Region.StartLine != 3 {
		t.Errorf("location = %+v, want package-lock.json line 3", loc)
	}
}

func TestScanDirSARIFOutputAlongsideTable(t *testing.T) {
	osv := newFakeOSV(t)
	sarif := filepath.Join(t.TempDir(), "out.sarif")
	out, err := runCLI(t, "scan", "dir", writeProject(t), "--osv-url", osv.URL, "--sarif-output", sarif)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Scanned 2 packages") {
		t.Errorf("table should still go to stdout:\n%s", out)
	}
	data, err := os.ReadFile(sarif)
	if err != nil || !strings.Contains(string(data), `"version": "2.1.0"`) {
		t.Errorf("SARIF file not written: %v\n%s", err, data)
	}
}
