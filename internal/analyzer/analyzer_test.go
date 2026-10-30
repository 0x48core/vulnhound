package analyzer

import (
	"context"
	"os"
	"reflect"
	"sort"
	"testing"
	"testing/fstest"

	"github.com/0x48core/vulnhound/pkg/types"
)

// summary is the subset of Package fields the tests assert on.
type summary struct {
	Name, Version string
	Direct, Dev   bool
	Line          int
}

func summarize(pkgs []types.Package) []summary {
	out := make([]summary, len(pkgs))
	for i, p := range pkgs {
		out[i] = summary{p.Name, p.Version, p.Direct, p.Dev, p.Locations[0].Line}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func TestGoMod(t *testing.T) {
	pkgs, err := GoMod{}.Analyze(context.Background(), os.DirFS("testdata/gomod"), "go.mod")
	if err != nil {
		t.Fatal(err)
	}
	want := []summary{
		{"example.com/new", "v1.2.0", true, false, 9},
		{"github.com/gin-gonic/gin", "v1.9.0", true, false, 6},
		{"golang.org/x/net", "v0.17.0", false, false, 7},
	}
	if got := summarize(pkgs); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	for _, p := range pkgs {
		if p.Name == "github.com/gin-gonic/gin" && p.PURL != "pkg:golang/github.com/gin-gonic/gin@v1.9.0" {
			t.Errorf("purl = %q", p.PURL)
		}
	}
}

func TestNpmLockV3(t *testing.T) {
	pkgs, err := NpmLock{}.Analyze(context.Background(), os.DirFS("testdata/npm-v3"), "package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	want := []summary{
		{"@babel/core", "7.20.0", true, true, 15},
		{"lodash", "4.17.15", true, false, 13},
		{"minimist", "1.2.0", true, false, 14},
		{"semver", "6.3.0", false, true, 16},
	}
	if got := summarize(pkgs); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	for _, p := range pkgs {
		if p.Name == "@babel/core" && p.PURL != "pkg:npm/%40babel/core@7.20.0" {
			t.Errorf("purl = %q", p.PURL)
		}
	}
}

func TestNpmLockV1(t *testing.T) {
	pkgs, err := NpmLock{}.Analyze(context.Background(), os.DirFS("testdata/npm-v1"), "package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	want := []summary{
		{"@scope/real", "2.0.0", false, false, 12},
		{"debug", "2.6.9", false, true, 11},
		{"express", "4.17.1", true, false, 5},
		{"qs", "6.7.0", false, false, 8},
	}
	if got := summarize(pkgs); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestCatalogDedupesAndSkipsDirs(t *testing.T) {
	lock := []byte(`{"lockfileVersion":3,"packages":{
		"":{"dependencies":{"lodash":"*"}},
		"node_modules/lodash":{"version":"4.17.15"}}}`)
	fsys := fstest.MapFS{
		"a/package-lock.json":              {Data: lock},
		"b/package-lock.json":              {Data: lock},
		"node_modules/x/package-lock.json": {Data: lock},
		"broken/package-lock.json":         {Data: []byte("{not json")},
		"svc/go.mod":                       {Data: []byte("module x\nrequire golang.org/x/text v0.3.0\n")},
		"vendor/golang.org/x/text/go.mod":  {Data: []byte("module golang.org/x/text\n")},
	}
	pkgs, err := Catalog(context.Background(), fsys, Default(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2: %+v", len(pkgs), pkgs)
	}
	// Sorted by ecosystem: "Go" < "npm".
	if pkgs[0].Name != "golang.org/x/text" || pkgs[1].Name != "lodash" {
		t.Errorf("unexpected order: %+v", pkgs)
	}
	if want := []types.Location{{Path: "a/package-lock.json", Line: 3}, {Path: "b/package-lock.json", Line: 3}}; !reflect.DeepEqual(pkgs[1].Locations, want) {
		t.Errorf("locations = %v, want %v", pkgs[1].Locations, want)
	}
}

func TestCatalogExclude(t *testing.T) {
	mod := func(dep string) *fstest.MapFile {
		return &fstest.MapFile{Data: []byte("module x\nrequire " + dep + " v1.0.0\n")}
	}
	fsys := fstest.MapFS{
		"go.mod":                  mod("example.com/root"),
		"testdata/go.mod":         mod("example.com/fixture"),
		"svc/a/testdata/go.mod":   mod("example.com/nested-fixture"),
		"examples/legacy/go.mod":  mod("example.com/legacy"),
		"examples/current/go.mod": mod("example.com/current"),
		"tools/go.mod":            mod("example.com/tools"),
	}
	pkgs, err := Catalog(context.Background(), fsys, Default(), Options{
		Exclude: []string{"testdata", "examples/legacy", "/tools/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range pkgs {
		names = append(names, p.Name)
	}
	if want := []string{"example.com/current", "example.com/root"}; !reflect.DeepEqual(names, want) {
		t.Errorf("got %v, want %v", names, want)
	}

	if _, err := Catalog(context.Background(), fsys, Default(), Options{Exclude: []string{"[x"}}); err == nil {
		t.Error("malformed pattern must be an error")
	}
}
