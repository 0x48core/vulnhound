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
}

func summarize(pkgs []types.Package) []summary {
	out := make([]summary, len(pkgs))
	for i, p := range pkgs {
		out[i] = summary{p.Name, p.Version, p.Direct, p.Dev}
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
		{"example.com/new", "v1.2.0", true, false},
		{"github.com/gin-gonic/gin", "v1.9.0", true, false},
		{"golang.org/x/net", "v0.17.0", false, false},
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
		{"@babel/core", "7.20.0", true, true},
		{"lodash", "4.17.15", true, false},
		{"minimist", "1.2.0", true, false},
		{"semver", "6.3.0", false, true},
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
		{"@scope/real", "2.0.0", false, false},
		{"debug", "2.6.9", false, true},
		{"express", "4.17.1", true, false},
		{"qs", "6.7.0", false, false},
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
	if want := []string{"a/package-lock.json", "b/package-lock.json"}; !reflect.DeepEqual(pkgs[1].Locations, want) {
		t.Errorf("locations = %v, want %v", pkgs[1].Locations, want)
	}
}
