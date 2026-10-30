package analyzer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/0x48core/vulnhound/pkg/types"
)

const debianOSRelease = `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
ID=debian
`

func TestDpkgStatus(t *testing.T) {
	status := `Package: libssl3
Status: install ok installed
Architecture: arm64
Source: openssl
Version: 3.0.11-1~deb12u2
Description: Secure Sockets Layer toolkit
 multi-line description that is ignored

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0

Package: libc6
Status: install ok installed
Source: glibc (2.36-9+deb12u4)
Version: 2.36-9+deb12u4+b1
`
	fsys := fstest.MapFS{
		"usr/lib/os-release":  {Data: []byte(debianOSRelease)},
		"var/lib/dpkg/status": {Data: []byte(status)},
	}
	pkgs, err := Dpkg{}.Analyze(context.Background(), fsys, "var/lib/dpkg/status")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2 (deinstalled skipped): %+v", len(pkgs), pkgs)
	}
	ssl, libc := pkgs[0], pkgs[1]
	if ssl.Ecosystem != "Debian:12" || ssl.SourceName != "openssl" || ssl.AdvisoryVersion() != "3.0.11-1~deb12u2" || ssl.Locations[0].Line != 1 {
		t.Errorf("libssl3 = %+v", ssl)
	}
	if ssl.PURL != "pkg:deb/debian/libssl3@3.0.11-1~deb12u2" {
		t.Errorf("purl = %s", ssl.PURL)
	}
	// Binary-only rebuilds (+b1) carry the source version separately.
	if libc.AdvisoryName() != "glibc" || libc.AdvisoryVersion() != "2.36-9+deb12u4" || libc.Version != "2.36-9+deb12u4+b1" || libc.Locations[0].Line != 13 {
		t.Errorf("libc6 = %+v", libc)
	}
}

func TestDpkgDistrolessStatusD(t *testing.T) {
	a := Dpkg{}
	for p, want := range map[string]bool{
		"var/lib/dpkg/status.d/base-files":         true,
		"var/lib/dpkg/status.d/base-files.md5sums": false,
		"var/lib/dpkg/status-old":                  false,
	} {
		if got := a.Match(p); got != want {
			t.Errorf("Match(%q) = %v", p, got)
		}
	}
	fsys := fstest.MapFS{
		"etc/os-release":                   {Data: []byte(debianOSRelease)},
		"var/lib/dpkg/status.d/base-files": {Data: []byte("Package: base-files\nVersion: 12.4+deb12u5\n")},
	}
	pkgs, err := a.Analyze(context.Background(), fsys, "var/lib/dpkg/status.d/base-files")
	if err != nil || len(pkgs) != 1 || pkgs[0].AdvisoryName() != "base-files" {
		t.Errorf("pkgs = %+v, err = %v", pkgs, err)
	}
}

func TestOSVEcosystem(t *testing.T) {
	for _, tt := range []struct {
		rel  osRelease
		want string
	}{
		{osRelease{ID: "debian", VersionID: "12"}, "Debian:12"},
		{osRelease{ID: "ubuntu", VersionID: "22.04", Version: "22.04.4 LTS (Jammy Jellyfish)"}, "Ubuntu:22.04:LTS"},
		{osRelease{ID: "ubuntu", VersionID: "23.10", Version: "23.10 (Mantic Minotaur)"}, "Ubuntu:23.10"},
		{osRelease{ID: "alpine", VersionID: "3.19.1"}, "Alpine:v3.19"},
	} {
		got, err := tt.rel.osvEcosystem()
		if err != nil || got != tt.want {
			t.Errorf("%+v: got %q, %v; want %q", tt.rel, got, err, tt.want)
		}
	}
	for _, bad := range []osRelease{{ID: "debian"}, {ID: "fedora", VersionID: "40"}, {ID: "alpine", VersionID: "edge"}} {
		if _, err := bad.osvEcosystem(); err == nil {
			t.Errorf("%+v: expected an error", bad)
		}
	}
}

func TestApk(t *testing.T) {
	installed := `C:Q1abc=
P:musl
V:1.2.4_git20230717-r4
A:aarch64
o:musl

C:Q1def=
P:libcrypto3
V:3.1.4-r5
o:openssl
`
	fsys := fstest.MapFS{
		"etc/os-release":       {Data: []byte("ID=alpine\nVERSION_ID=3.19.1\n")},
		"lib/apk/db/installed": {Data: []byte(installed)},
	}
	pkgs, err := Apk{}.Analyze(context.Background(), fsys, "lib/apk/db/installed")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("pkgs = %+v", pkgs)
	}
	crypto := pkgs[1]
	if crypto.Name != "libcrypto3" || crypto.AdvisoryName() != "openssl" || crypto.Ecosystem != "Alpine:v3.19" || crypto.Locations[0].Line != 8 {
		t.Errorf("libcrypto3 = %+v", crypto)
	}
}

// goBinary builds vulnhound's CLI once and returns its path. A binary
// from `go build` always embeds its module dependencies; the test binary
// itself does not on every Go version (Go 1.26 records only the Go
// version), so the tests must not rely on it.
func goBinary(t *testing.T) string {
	t.Helper()
	goBinaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "vulnhound-gobinary-*")
		if err != nil {
			goBinaryErr = err
			return
		}
		goBinaryDir = dir
		goBinaryPath = filepath.Join(dir, "vulnhound"+exeSuffix())
		cmd := exec.Command("go", "build", "-o", goBinaryPath, "github.com/0x48core/vulnhound/cmd/vulnhound")
		if out, err := cmd.CombinedOutput(); err != nil {
			goBinaryErr = fmt.Errorf("go build: %v\n%s", err, out)
		}
	})
	if goBinaryErr != nil {
		t.Fatal(goBinaryErr)
	}
	return goBinaryPath
}

var (
	goBinaryOnce sync.Once
	goBinaryDir  string
	goBinaryPath string
	goBinaryErr  error
)

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

func TestMain(m *testing.M) {
	code := m.Run()
	if goBinaryDir != "" {
		_ = os.RemoveAll(goBinaryDir)
	}
	os.Exit(code)
}

func TestGoBinary(t *testing.T) {
	exe := goBinary(t)
	info, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	a := GoBinary{}
	if !a.MatchFile(exe, info.Mode(), info.Size()) {
		t.Fatalf("Go binary (%s, %d bytes) should match", info.Mode(), info.Size())
	}
	if a.MatchFile("x", 0o644, info.Size()) || a.MatchFile("x", 0o755, 100) {
		t.Error("non-executable or tiny files must not match")
	}

	pkgs, err := a.Analyze(context.Background(), os.DirFS(filepath.Dir(exe)), filepath.Base(exe))
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]types.Package{}
	for _, p := range pkgs {
		found[p.Name] = p
	}
	if std, ok := found["stdlib"]; !ok || std.Version == "" || std.Version[0] == 'g' {
		t.Errorf("stdlib = %+v, want the Go version without the go prefix", std)
	}
	// vulnhound depends on cobra and golang.org/x/sync (see go.mod).
	for name, version := range map[string]string{"github.com/spf13/cobra": "v1.8.1", "golang.org/x/sync": "v0.24.0"} {
		if dep, ok := found[name]; !ok || dep.Version != version || dep.Locations[0].Path != filepath.Base(exe) {
			t.Errorf("%s = %+v, want %s (all: %v)", name, dep, version, pkgs)
		}
	}

	// A non-Go file is skipped silently, not an error.
	fsys := fstest.MapFS{"script": {Data: []byte("#!/bin/sh\necho hi\n"), Mode: 0o755}}
	if pkgs, err := a.Analyze(context.Background(), fsys, "script"); err != nil || len(pkgs) != 0 {
		t.Errorf("non-Go file: pkgs=%v err=%v", pkgs, err)
	}
}

func TestCatalogForImageUsesFileMatcher(t *testing.T) {
	data, err := os.ReadFile(goBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{
		"usr/local/bin/app": {Data: data, Mode: 0o755},
		"usr/share/doc/app": {Data: data, Mode: 0o644}, // not executable
	}
	pkgs, err := Catalog(context.Background(), fsys, ForImage(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	locs := map[string]bool{}
	for _, p := range pkgs {
		for _, l := range p.Locations {
			locs[l.Path] = true
		}
	}
	if !locs["usr/local/bin/app"] || locs["usr/share/doc/app"] {
		t.Errorf("locations = %v", locs)
	}
	// Directory scans keep their manifest-only analyzer set.
	pkgs, _ = Catalog(context.Background(), fsys, Default(), Options{})
	if len(pkgs) != 0 {
		t.Errorf("Default() must not read binaries: %+v", pkgs)
	}
}
