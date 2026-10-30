// Package osvdb keeps a local copy of the OSV vulnerability database, one
// dump per ecosystem from https://osv-vulnerabilities.storage.googleapis.com,
// for offline scanning.
//
// Layout under the database directory:
//
//	<Ecosystem>/all.zip     the OSV dump: one JSON record per file
//	<Ecosystem>/index.json  "affected ecosystem\tpackage name" -> zip entries
//	<Ecosystem>/meta.json   ETag, update time, counts
//
// The index lets a scan read only the records for the packages it found
// instead of parsing the whole dump.
package osvdb

import (
	"archive/zip"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultURL serves the per-ecosystem dumps.
const DefaultURL = "https://osv-vulnerabilities.storage.googleapis.com"

// Ecosystems lists the dumps vulnhound can use, by OSV base ecosystem.
var Ecosystems = []string{"Go", "npm", "Debian", "Ubuntu", "Alpine"}

// DefaultEcosystems are downloaded when none are named. Ubuntu is left out
// because its dump is several times larger than all the others together.
var DefaultEcosystems = []string{"Go", "npm", "Debian", "Alpine"}

// StaleAfter is when Meta.Stale starts reporting true.
const StaleAfter = 7 * 24 * time.Hour

// DefaultDir is $VULNHOUND_DB_DIR, or "vulnhound/osv" in the user cache
// directory (~/Library/Caches on macOS, ~/.cache on Linux).
func DefaultDir() (string, error) {
	if dir := os.Getenv("VULNHOUND_DB_DIR"); dir != "" {
		return dir, nil
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cache, "vulnhound", "osv"), nil
}

// Base returns the dump an ecosystem belongs to: "Debian:12" -> "Debian".
func Base(ecosystem string) string {
	base, _, _ := strings.Cut(ecosystem, ":")
	return base
}

// Meta describes one installed dump.
type Meta struct {
	Ecosystem string    `json:"ecosystem"`
	ETag      string    `json:"etag"`
	UpdatedAt time.Time `json:"updated_at"`
	Size      int64     `json:"size"`
	Records   int       `json:"records"`
}

// Stale reports whether the dump is older than StaleAfter.
func (m Meta) Stale(now time.Time) bool { return now.Sub(m.UpdatedAt) > StaleAfter }

// DB is a local database directory.
type DB struct {
	Dir     string
	BaseURL string // DefaultURL when empty
	Client  *http.Client

	mu   sync.Mutex
	open map[string]*reader
}

// New returns a DB in dir.
func New(dir string) *DB {
	return &DB{Dir: dir, BaseURL: DefaultURL, Client: &http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}}}
}

// UpdateResult reports what Update did.
type UpdateResult struct {
	Changed bool // false: the remote dump has not changed since the last update
	Meta    Meta
}

// Update downloads the dump for a base ecosystem if it changed, verifies it
// against the MD5 that Cloud Storage reports, and rebuilds the index. The
// previous copy stays usable until the new one is complete.
func (db *DB) Update(ctx context.Context, ecosystem string) (UpdateResult, error) {
	if !slices.Contains(Ecosystems, ecosystem) {
		return UpdateResult{}, fmt.Errorf("unknown ecosystem %q (supported: %s)", ecosystem, strings.Join(Ecosystems, ", "))
	}
	dir := filepath.Join(db.Dir, ecosystem)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return UpdateResult{}, err
	}
	old, _ := readMeta(dir)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(db.baseURL(), "/")+"/"+ecosystem+"/all.zip", nil)
	if err != nil {
		return UpdateResult{}, err
	}
	if old.ETag != "" && fileExists(filepath.Join(dir, "all.zip")) && fileExists(filepath.Join(dir, "index.json")) {
		req.Header.Set("If-None-Match", old.ETag)
	}
	resp, err := db.Client.Do(req)
	if err != nil {
		return UpdateResult{}, fmt.Errorf("download %s: %w", ecosystem, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotModified {
		old.UpdatedAt = time.Now().UTC() // checked just now: still current
		return UpdateResult{Changed: false, Meta: old}, writeMeta(dir, old)
	}
	if resp.StatusCode != http.StatusOK {
		return UpdateResult{}, fmt.Errorf("download %s: %s", ecosystem, resp.Status)
	}

	tmpZip := filepath.Join(dir, "all.zip.tmp")
	size, sum, err := download(resp.Body, tmpZip)
	if err != nil {
		_ = os.Remove(tmpZip)
		return UpdateResult{}, fmt.Errorf("download %s: %w", ecosystem, err)
	}
	if want := googMD5(resp.Header); want != "" && want != sum {
		_ = os.Remove(tmpZip)
		return UpdateResult{}, fmt.Errorf("download %s: MD5 mismatch (got %s, want %s)", ecosystem, sum, want)
	}

	index, records, err := buildIndex(tmpZip)
	if err != nil {
		_ = os.Remove(tmpZip)
		return UpdateResult{}, fmt.Errorf("index %s: %w", ecosystem, err)
	}
	tmpIndex := filepath.Join(dir, "index.json.tmp")
	if err := writeJSON(tmpIndex, index); err != nil {
		_ = os.Remove(tmpZip)
		return UpdateResult{}, err
	}

	// Close a reader of the previous copy before replacing its files.
	db.mu.Lock()
	if r, ok := db.open[ecosystem]; ok {
		_ = r.zip.Close()
		delete(db.open, ecosystem)
	}
	db.mu.Unlock()
	if err := os.Rename(tmpZip, filepath.Join(dir, "all.zip")); err != nil {
		return UpdateResult{}, err
	}
	if err := os.Rename(tmpIndex, filepath.Join(dir, "index.json")); err != nil {
		return UpdateResult{}, err
	}
	meta := Meta{Ecosystem: ecosystem, ETag: resp.Header.Get("ETag"), UpdatedAt: time.Now().UTC(), Size: size, Records: records}
	return UpdateResult{Changed: true, Meta: meta}, writeMeta(dir, meta)
}

// Status lists the installed dumps, in Ecosystems order.
func (db *DB) Status() []Meta {
	var out []Meta
	for _, eco := range Ecosystems {
		if m, err := readMeta(filepath.Join(db.Dir, eco)); err == nil {
			out = append(out, m)
		}
	}
	return out
}

// ErrNotInstalled is returned by Lookup when an ecosystem's dump is missing.
var ErrNotInstalled = errors.New("not in the offline database")

// Lookup returns the raw OSV records that list name in ecosystem (e.g.
// "Debian:12", "openssl") among their affected packages.
func (db *DB) Lookup(ecosystem, name string) ([][]byte, Meta, error) {
	r, err := db.reader(Base(ecosystem))
	if err != nil {
		return nil, Meta{}, err
	}
	var out [][]byte
	for _, entry := range r.index[ecosystem+"\t"+name] {
		f, err := r.zip.Open(entry)
		if err != nil {
			return nil, r.meta, err
		}
		data, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			return nil, r.meta, err
		}
		out = append(out, data)
	}
	return out, r.meta, nil
}

// Close releases open dumps.
func (db *DB) Close() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	var errs []error
	for eco, r := range db.open {
		errs = append(errs, r.zip.Close())
		delete(db.open, eco)
	}
	return errors.Join(errs...)
}

type reader struct {
	zip   *zip.ReadCloser
	index map[string][]string
	meta  Meta
}

func (db *DB) reader(base string) (*reader, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if r, ok := db.open[base]; ok {
		return r, nil
	}
	dir := filepath.Join(db.Dir, base)
	meta, err := readMeta(dir)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", base, ErrNotInstalled)
	}
	zr, err := zip.OpenReader(filepath.Join(dir, "all.zip"))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", base, ErrNotInstalled)
	}
	var index map[string][]string
	if err := readJSON(filepath.Join(dir, "index.json"), &index); err != nil {
		_ = zr.Close()
		return nil, fmt.Errorf("%s: %w", base, ErrNotInstalled)
	}
	if db.open == nil {
		db.open = map[string]*reader{}
	}
	r := &reader{zip: zr, index: index, meta: meta}
	db.open[base] = r
	return r, nil
}

// buildIndex maps each affected (ecosystem, package) to the zip entries
// that mention it. Withdrawn records are left out.
func buildIndex(zipPath string) (map[string][]string, int, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = zr.Close() }()

	index := map[string][]string{}
	records := 0
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, 0, err
		}
		var rec struct {
			Withdrawn string `json:"withdrawn"`
			Affected  []struct {
				Package struct {
					Ecosystem string `json:"ecosystem"`
					Name      string `json:"name"`
				} `json:"package"`
			} `json:"affected"`
		}
		err = json.NewDecoder(rc).Decode(&rec)
		_ = rc.Close()
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", f.Name, err)
		}
		if rec.Withdrawn != "" {
			continue
		}
		records++
		seen := map[string]bool{}
		for _, a := range rec.Affected {
			key := a.Package.Ecosystem + "\t" + a.Package.Name
			if !seen[key] {
				seen[key] = true
				index[key] = append(index[key], f.Name)
			}
		}
	}
	for k := range index {
		sort.Strings(index[k])
	}
	return index, records, nil
}

func download(r io.Reader, dst string) (int64, string, error) {
	f, err := os.Create(dst)
	if err != nil {
		return 0, "", err
	}
	h := md5.New()
	n, err := io.Copy(io.MultiWriter(f, h), r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return n, base64.StdEncoding.EncodeToString(h.Sum(nil)), err
}

// googMD5 returns the base64 MD5 from Cloud Storage's
// "x-goog-hash: crc32c=...,md5=..." header, or "" if absent.
func googMD5(h http.Header) string {
	for _, v := range h.Values("X-Goog-Hash") {
		for part := range strings.SplitSeq(v, ",") {
			if sum, ok := strings.CutPrefix(strings.TrimSpace(part), "md5="); ok {
				return sum
			}
		}
	}
	return ""
}

func (db *DB) baseURL() string {
	if db.BaseURL == "" {
		return DefaultURL
	}
	return db.BaseURL
}

func readMeta(dir string) (Meta, error) {
	var m Meta
	err := readJSON(filepath.Join(dir, "meta.json"), &m)
	return m, err
}

func writeMeta(dir string, m Meta) error {
	return writeJSON(filepath.Join(dir, "meta.json"), m)
}

func readJSON(p string, v any) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return json.NewDecoder(f).Decode(v)
}

func writeJSON(p string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o644)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
