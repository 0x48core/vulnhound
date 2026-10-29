package analyzer

import (
	"context"
	"io/fs"
	"path"

	"golang.org/x/mod/modfile"

	"github.com/0x48core/vulnhound/internal/purl"
	"github.com/0x48core/vulnhound/pkg/types"
)

// GoMod parses go.mod files.
//
// go.mod is used rather than go.sum because go.sum also lists module
// versions that were considered during resolution but are not part of the
// build, which would produce false positives. Since Go 1.17, go.mod lists
// every module the main module needs, including indirect ones.
type GoMod struct{}

func (GoMod) Name() string { return "gomod" }

func (GoMod) Match(p string) bool { return path.Base(p) == "go.mod" }

func (GoMod) Analyze(_ context.Context, fsys fs.FS, p string) ([]types.Package, error) {
	data, err := fs.ReadFile(fsys, p)
	if err != nil {
		return nil, err
	}
	// Parse rather than ParseLax: ParseLax discards replace directives.
	f, err := modfile.Parse(p, data, nil)
	if err != nil {
		return nil, err
	}

	// Replacements redirect a module to another version or a local path.
	// A replacement without an Old.Version applies to every version.
	type modKey struct{ path, version string }
	replaced := make(map[modKey]*modfile.Replace)
	for _, r := range f.Replace {
		replaced[modKey{r.Old.Path, r.Old.Version}] = r
	}

	pkgs := make([]types.Package, 0, len(f.Require))
	for _, req := range f.Require {
		name, version := req.Mod.Path, req.Mod.Version
		r := replaced[modKey{name, version}]
		if r == nil {
			r = replaced[modKey{name, ""}]
		}
		if r != nil {
			if r.New.Version == "" {
				// Local filesystem replacement: nothing to look up.
				continue
			}
			name, version = r.New.Path, r.New.Version
		}
		pkgs = append(pkgs, types.Package{
			Name:      name,
			Version:   version,
			Ecosystem: types.EcosystemGo,
			PURL:      purl.Build("golang", name, version),
			Locations: []string{p},
			Direct:    !req.Indirect,
		})
	}
	return pkgs, nil
}
