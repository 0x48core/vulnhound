package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/0x48core/vulnhound/internal/purl"
	"github.com/0x48core/vulnhound/pkg/types"
)

// NpmLock parses package-lock.json (lockfileVersion 1, 2, and 3).
type NpmLock struct{}

func (NpmLock) Name() string { return "npm" }

func (NpmLock) Match(p string) bool { return path.Base(p) == "package-lock.json" }

type npmLockfile struct {
	LockfileVersion int                      `json:"lockfileVersion"`
	Packages        map[string]npmPackage    `json:"packages"`     // v2, v3
	Dependencies    map[string]npmDependency `json:"dependencies"` // v1, v2
}

type npmPackage struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dev                  bool              `json:"dev"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type npmDependency struct {
	Version      string                   `json:"version"`
	Dev          bool                     `json:"dev"`
	Dependencies map[string]npmDependency `json:"dependencies"`
}

func (NpmLock) Analyze(_ context.Context, fsys fs.FS, p string) ([]types.Package, error) {
	data, err := fs.ReadFile(fsys, p)
	if err != nil {
		return nil, err
	}
	var lock npmLockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	// Line numbers are best effort: a package without one is still reported.
	lines, err := jsonKeyLines(data)
	if err != nil {
		lines = nil
	}
	if len(lock.Packages) > 0 {
		return npmFromPackages(lock.Packages, p, lines), nil
	}
	return npmFromDependencies(lock.Dependencies, rootDeps(fsys, p), p, lines), nil
}

// npmFromPackages handles the flat "packages" map of lockfile v2/v3, keyed
// by install path such as "node_modules/a/node_modules/@scope/b".
func npmFromPackages(entries map[string]npmPackage, file string, lines map[string]int) []types.Package {
	direct := make(map[string]bool)
	if root, ok := entries[""]; ok {
		for _, m := range []map[string]string{root.Dependencies, root.DevDependencies, root.OptionalDependencies, root.PeerDependencies} {
			for name := range m {
				direct[name] = true
			}
		}
	}

	var pkgs []types.Package
	for key, e := range entries {
		idx := strings.LastIndex(key, "node_modules/")
		// Skip the root project, workspace members, and symlinks to them.
		if idx < 0 || e.Link {
			continue
		}
		installName := key[idx+len("node_modules/"):]
		name := installName
		if e.Name != "" {
			name = e.Name // aliased install: "node_modules/alias" -> real name
		}
		if !isRegistryVersion(e.Version) {
			continue
		}
		isTopLevel := idx == 0
		loc := types.Location{Path: file, Line: lines["packages\x00"+key]}
		pkgs = append(pkgs, npmPackageOf(name, e.Version, loc, isTopLevel && direct[installName], e.Dev))
	}
	return pkgs
}

// npmFromDependencies handles the nested "dependencies" tree of lockfile v1.
func npmFromDependencies(deps map[string]npmDependency, direct map[string]bool, file string, lines map[string]int) []types.Package {
	var pkgs []types.Package
	var walk func(map[string]npmDependency, string, bool)
	walk = func(m map[string]npmDependency, parent string, topLevel bool) {
		for installName, d := range m {
			keyPath := parent + "\x00" + installName
			loc := types.Location{Path: file, Line: lines[keyPath]}
			name, version := installName, d.Version
			// Aliases are recorded as "npm:<real-name>@<version>".
			if real, ok := strings.CutPrefix(version, "npm:"); ok {
				if at := strings.LastIndex(real, "@"); at > 0 {
					name, version = real[:at], real[at+1:]
				}
			}
			if isRegistryVersion(version) {
				pkgs = append(pkgs, npmPackageOf(name, version, loc, topLevel && direct[installName], d.Dev))
			}
			walk(d.Dependencies, keyPath+"\x00dependencies", false)
		}
	}
	walk(deps, "dependencies", true)
	return pkgs
}

// rootDeps reads the package.json next to a v1 lockfile to learn which
// dependencies are direct. v1 lockfiles do not record this themselves.
func rootDeps(fsys fs.FS, lockPath string) map[string]bool {
	direct := make(map[string]bool)
	data, err := fs.ReadFile(fsys, path.Join(path.Dir(lockPath), "package.json"))
	if err != nil {
		return direct
	}
	var manifest npmPackage
	if json.Unmarshal(data, &manifest) != nil {
		return direct
	}
	for _, m := range []map[string]string{manifest.Dependencies, manifest.DevDependencies, manifest.OptionalDependencies, manifest.PeerDependencies} {
		for name := range m {
			direct[name] = true
		}
	}
	return direct
}

// isRegistryVersion rejects empty versions and non-registry sources such as
// "git+ssh://...", "file:../x", or tarball URLs, which OSV cannot match.
func isRegistryVersion(v string) bool {
	return v != "" && !strings.Contains(v, ":")
}

func npmPackageOf(name, version string, loc types.Location, direct, dev bool) types.Package {
	return types.Package{
		Name:      name,
		Version:   version,
		Ecosystem: types.EcosystemNpm,
		PURL:      purl.Build("npm", name, version),
		Locations: []types.Location{loc},
		Direct:    direct,
		Dev:       dev,
	}
}
