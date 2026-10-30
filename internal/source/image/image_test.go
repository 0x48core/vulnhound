package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// entry is one tar header in a test layer.
type entry struct {
	name, body, link string
	typ              byte
	mode             int64
}

func file(name, body string) entry {
	return entry{name: name, body: body, typ: tar.TypeReg, mode: 0o644}
}
func exe(name, body string) entry {
	return entry{name: name, body: body, typ: tar.TypeReg, mode: 0o755}
}
func symlink(name, to string) entry {
	return entry{name: name, link: to, typ: tar.TypeSymlink, mode: 0o777}
}
func hardlink(name, to string) entry {
	return entry{name: name, link: to, typ: tar.TypeLink, mode: 0o644}
}
func whiteout(dir, name string) entry { return file(dir+"/.wh."+name, "") }
func opaque(dir string) entry         { return file(dir+"/.wh..wh..opq", "") }

func layerTar(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: e.mode, Linkname: e.link, Size: int64(len(e.body))}
		if e.typ != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	return buf.Bytes()
}

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write(b)
	gz.Close()
	return buf.Bytes()
}

func wantAll(string, fs.FileMode, int64) bool { return true }

// files lists the regular files under root with their content.
func files(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			t.Errorf("symlink created on disk: %s", p)
		}
		rel, _ := filepath.Rel(root, p)
		data, _ := os.ReadFile(p)
		out[filepath.ToSlash(rel)] = string(data)
		return nil
	})
	return out
}

func TestFlattenWhiteoutsAndLinks(t *testing.T) {
	root := t.TempDir()
	f := newFlattener(root, wantAll)
	layers := [][]entry{
		{
			file("usr/lib/os-release", "ID=debian"),
			symlink("etc/os-release", "../usr/lib/os-release"),
			file("app/old.txt", "old"),
			file("app/keep/a.txt", "a"),
			file("cache/x", "x"),
			file("data/v1", "1"),
			exe("bin/tool", "tool-v1"),
		},
		{
			whiteout("app", "old.txt"), // delete one file
			opaque("cache"),            // empty a directory...
			file("cache/y", "y"),       // ...then repopulate it in the same layer
			whiteout("", "data"),       // delete a whole directory
			exe("bin/tool", "tool-v2"), // overwrite
			hardlink("bin/tool-link", "bin/tool"),
			symlink("evil", "../../../../etc/passwd"), // must stay inside the root
			file("../../escape.txt", "nope"),          // traversal is clamped to the root
			symlink("loop-a", "loop-b"),
			symlink("loop-b", "loop-a"),
		},
	}
	for i, l := range layers {
		if err := f.apply(i, bytes.NewReader(layerTar(t, l...))); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.finish(); err != nil {
		t.Fatal(err)
	}

	got := files(t, root)
	want := map[string]string{
		"usr/lib/os-release": "ID=debian",
		"etc/os-release":     "ID=debian", // symlink resolved by copying
		"app/keep/a.txt":     "a",
		"cache/y":            "y",
		"bin/tool":           "tool-v2",
		"bin/tool-link":      "tool-v2",
		"escape.txt":         "nope",
	}
	if !equalMaps(got, want) {
		t.Errorf("flattened files:\n got %v\nwant %v", sorted(got), sorted(want))
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "escape.txt")); err == nil {
		t.Error("a file escaped the root")
	}
	if info, err := os.Stat(filepath.Join(root, "bin/tool")); err != nil || info.Mode().Perm()&0o111 == 0 {
		t.Errorf("executable bit lost: %v %v", info.Mode(), err)
	}
}

func TestFlattenOnlyWanted(t *testing.T) {
	root := t.TempDir()
	want := func(p string, mode fs.FileMode, size int64) bool { return p == "var/lib/dpkg/status" }
	f := newFlattener(root, want)
	f.apply(0, bytes.NewReader(layerTar(t, file("var/lib/dpkg/status", "pkgs"), file("usr/share/big", "ignored"))))
	f.finish()
	if got := files(t, root); !equalMaps(got, map[string]string{"var/lib/dpkg/status": "pkgs"}) {
		t.Errorf("got %v", got)
	}
}

func TestParseReference(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, tt := range []struct{ in, registry, repo, tag, digest, api string }{
		{"nginx", "docker.io", "library/nginx", "latest", "", "registry-1.docker.io"},
		{"nginx:1.25", "docker.io", "library/nginx", "1.25", "", "registry-1.docker.io"},
		{"bitnami/redis:7.2", "docker.io", "bitnami/redis", "7.2", "", "registry-1.docker.io"},
		{"ghcr.io/org/app:v1", "ghcr.io", "org/app", "v1", "", "ghcr.io"},
		{"localhost:5000/app", "localhost:5000", "app", "latest", "", "localhost:5000"},
		{"gcr.io/distroless/static@" + digest, "gcr.io", "distroless/static", "", digest, "gcr.io"},
		{"alpine:3.19@" + digest, "docker.io", "library/alpine", "3.19", digest, "registry-1.docker.io"},
	} {
		r, err := ParseReference(tt.in)
		if err != nil {
			t.Errorf("%s: %v", tt.in, err)
			continue
		}
		if r.Registry != tt.registry || r.Repository != tt.repo || r.Tag != tt.tag || r.Digest != tt.digest || r.apiHost() != tt.api {
			t.Errorf("%s: got %+v (api %s)", tt.in, r, r.apiHost())
		}
	}
	for _, bad := range []string{"", "UPPER/case", "nginx@sha256:short", "nginx:bad tag", "a//b"} {
		if _, err := ParseReference(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestParsePlatform(t *testing.T) {
	p, err := ParsePlatform("linux/arm64/v8")
	if err != nil || p.String() != "linux/arm64/v8" {
		t.Errorf("got %v, %v", p, err)
	}
	for _, bad := range []string{"linux", "linux/", "/amd64", "a/b/c/d"} {
		if _, err := ParsePlatform(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

// fakeRegistry serves one multi-platform image behind Bearer token auth.
type fakeRegistry struct {
	blobs     map[string][]byte // digest -> content
	manifests map[string][]byte // tag or digest -> content
	types     map[string]string // tag or digest -> media type
	tamper    string            // digest whose content is served corrupted
}

func digestOf(b []byte) string { return "sha256:" + sha256Hex(b) }

func (r *fakeRegistry) add(mediaType string, v any, tags ...string) string {
	data, _ := json.Marshal(v)
	d := digestOf(data)
	for _, k := range append(tags, d) {
		r.manifests[k], r.types[k] = data, mediaType
	}
	return d
}

func (r *fakeRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/token" {
		if req.URL.Query().Get("scope") != "repository:team/app:pull" {
			http.Error(w, "bad scope", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"token": "t0k"})
		return
	}
	if req.Header.Get("Authorization") != "Bearer t0k" {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="http://%s/token",service="fake"`, req.Host))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	rest, ok := strings.CutPrefix(req.URL.Path, "/v2/team/app/")
	if !ok {
		http.NotFound(w, req)
		return
	}
	switch kind, ref, _ := strings.Cut(rest, "/"); kind {
	case "manifests":
		data, ok := r.manifests[ref]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"errors":[{"code":"MANIFEST_UNKNOWN","message":"manifest unknown"}]}`))
			return
		}
		w.Header().Set("Content-Type", r.types[ref])
		w.Write(data)
	case "blobs":
		data := r.blobs[ref]
		if ref == r.tamper {
			data = append([]byte(nil), data...)
			data[len(data)-1] ^= 0xff
		}
		w.Write(data)
	}
}

func newFakeRegistry(t *testing.T) (*fakeRegistry, string) {
	t.Helper()
	reg := &fakeRegistry{blobs: map[string][]byte{}, manifests: map[string][]byte{}, types: map[string]string{}}
	layer := func(entries ...entry) descriptor {
		data := gzipBytes(layerTar(t, entries...))
		d := digestOf(data)
		reg.blobs[d] = data
		return descriptor{MediaType: mediaOCILayerGzip, Digest: d, Size: int64(len(data))}
	}
	image := func(arch string) descriptor {
		m := manifest{MediaType: mediaOCIManifest, Layers: []descriptor{
			layer(file("etc/os-release", "ID=alpine\nVERSION_ID=3.19.1\n"), file("arch", arch)),
			layer(file("lib/apk/db/installed", "P:musl\nV:1.2.4-r2\n")),
		}}
		d := reg.add(mediaOCIManifest, m)
		return descriptor{MediaType: mediaOCIManifest, Digest: d, Platform: &Platform{OS: "linux", Architecture: arch}}
	}
	amd, arm := image("amd64"), image("arm64")
	reg.add(mediaOCIIndex, manifest{MediaType: mediaOCIIndex, Manifests: []descriptor{amd, arm}}, "1.0")

	srv := httptest.NewServer(reg)
	t.Cleanup(srv.Close)
	t.Setenv("DOCKER_CONFIG", t.TempDir()) // no host credentials
	return reg, strings.TrimPrefix(srv.URL, "http://")
}

func TestRemoteMultiPlatform(t *testing.T) {
	_, host := newFakeRegistry(t)
	ctx := context.Background()

	for _, arch := range []string{"amd64", "arm64"} {
		target, err := Remote{Ref: host + "/team/app:1.0", Platform: Platform{OS: "linux", Architecture: arch}, Want: wantAll}.Open(ctx)
		if err != nil {
			t.Fatalf("%s: %v", arch, err)
		}
		got, _ := fs.ReadFile(target.FS, "arch")
		db, _ := fs.ReadFile(target.FS, "lib/apk/db/installed")
		if string(got) != arch || !strings.Contains(string(db), "P:musl") {
			t.Errorf("%s: arch=%q db=%q", arch, got, db)
		}
		if !strings.Contains(target.Name, host+"/team/app:1.0@sha256:") || target.Type != "image" {
			t.Errorf("target = %s (%s)", target.Name, target.Type)
		}
		root := target.FS
		target.Close()
		if _, err := fs.Stat(root, "arch"); err == nil {
			t.Error("Close must remove the extracted files")
		}
	}

	_, err := Remote{Ref: host + "/team/app:1.0", Platform: Platform{OS: "linux", Architecture: "s390x"}, Want: wantAll}.Open(ctx)
	if err == nil || !strings.Contains(err.Error(), "linux/amd64, linux/arm64") {
		t.Errorf("unknown platform: err = %v, want the available platforms listed", err)
	}
	_, err = Remote{Ref: host + "/team/app:nope", Platform: DefaultPlatform(), Want: wantAll}.Open(ctx)
	if err == nil || !strings.Contains(err.Error(), "MANIFEST_UNKNOWN") {
		t.Errorf("missing tag: err = %v", err)
	}
}

func TestRemoteRejectsTamperedLayer(t *testing.T) {
	reg, host := newFakeRegistry(t)
	failures := 0
	for d := range reg.blobs {
		reg.tamper = d // corrupt one layer at a time
		_, err := Remote{Ref: host + "/team/app:1.0", Platform: Platform{OS: "linux", Architecture: "amd64"}, Want: wantAll}.Open(context.Background())
		if err == nil {
			continue // an arm64 layer: not part of this pull
		}
		failures++
		// Corruption is caught by gzip's own checksum or by the digest check.
		if !errors.Is(err, errDigestMismatch) && !strings.Contains(err.Error(), "gzip") && !strings.Contains(err.Error(), "checksum") {
			t.Errorf("tampered %s: unexpected error %v", d, err)
		}
	}
	if failures != 2 {
		t.Errorf("%d pulls failed, want 2 (each amd64 layer)", failures)
	}
}

func TestArchiveDockerSaveAndOCILayout(t *testing.T) {
	base := layerTar(t, file("etc/os-release", "ID=alpine\nVERSION_ID=3.19.1\n"), file("tmp/x", "x"))
	top := gzipBytes(layerTar(t, whiteout("tmp", "x"), file("lib/apk/db/installed", "P:musl\nV:1.2.4-r2\n")))

	// docker save: manifest.json pointing at layer files.
	dockerSave := writeTar(t, map[string][]byte{
		"manifest.json": mustJSON([]map[string]any{{"RepoTags": []string{"app:dev"}, "Layers": []string{"aaa/layer.tar", "bbb/layer.tar"}}}),
		"aaa/layer.tar": base,
		"bbb/layer.tar": top,
		"aaa/VERSION":   []byte("1.0"),
		"config.json":   []byte("{}"),
	})

	// OCI layout: index.json -> manifest blob -> layer blobs.
	baseD, topD := digestOf(base), digestOf(top)
	m := mustJSON(manifest{MediaType: mediaOCIManifest, Layers: []descriptor{
		{MediaType: mediaOCILayer, Digest: baseD}, {MediaType: mediaOCILayerGzip, Digest: topD},
	}})
	ociLayout := writeTar(t, map[string][]byte{
		"oci-layout":          []byte(`{"imageLayoutVersion":"1.0.0"}`),
		"index.json":          mustJSON(manifest{Manifests: []descriptor{{MediaType: mediaOCIManifest, Digest: digestOf(m)}}}),
		blobPath(digestOf(m)): m,
		blobPath(baseD):       base,
		blobPath(topD):        top,
	})

	for name, p := range map[string]string{"docker save": dockerSave, "OCI layout": ociLayout, "gzipped": gzipFile(t, dockerSave)} {
		target, err := Archive{Path: p, Platform: DefaultPlatform(), Want: wantAll}.Open(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := fs.Stat(target.FS, "tmp/x"); err == nil {
			t.Errorf("%s: whiteout not applied", name)
		}
		if db, _ := fs.ReadFile(target.FS, "lib/apk/db/installed"); !strings.Contains(string(db), "musl") {
			t.Errorf("%s: missing package db", name)
		}
		if name == "docker save" && target.Name != "app:dev" {
			t.Errorf("name = %q, want the repo tag", target.Name)
		}
		target.Close()
	}

	notImage := writeTar(t, map[string][]byte{"README": []byte("hi")})
	if _, err := (Archive{Path: notImage, Want: wantAll}).Open(context.Background()); err == nil || !strings.Contains(err.Error(), "not an image archive") {
		t.Errorf("non-image tar: err = %v", err)
	}
}

func writeTar(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	var es []entry
	for name, body := range entries {
		es = append(es, file(name, string(body)))
	}
	sort.Slice(es, func(i, j int) bool { return es[i].name < es[j].name })
	p := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(p, layerTar(t, es...), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func gzipFile(t *testing.T, p string) string {
	t.Helper()
	data, _ := os.ReadFile(p)
	out := p + ".gz"
	os.WriteFile(out, gzipBytes(data), 0o644)
	return out
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func sorted(m map[string]string) []string {
	var out []string
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

func TestVerifyingReader(t *testing.T) {
	body := []byte("layer bytes")
	ok := &verifyingReader{rc: io.NopCloser(bytes.NewReader(body)), h: sha256.New(), want: sha256Hex(body)}
	if _, err := io.ReadAll(ok); err != nil {
		t.Errorf("matching digest: %v", err)
	}
	bad := &verifyingReader{rc: io.NopCloser(bytes.NewReader(body)), h: sha256.New(), want: sha256Hex([]byte("other"))}
	if _, err := io.ReadAll(bad); !errors.Is(err, errDigestMismatch) {
		t.Errorf("mismatched digest: err = %v", err)
	}
}
