package osvdb

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, _ := zw.Create(name)
		w.Write([]byte(body))
	}
	zw.Close()
	return buf.Bytes()
}

// fakeBucket serves Go/all.zip with an ETag and an x-goog-hash MD5.
type fakeBucket struct {
	data      []byte
	etag      string
	badMD5    bool
	downloads int
}

func (b *fakeBucket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/Go/all.zip" {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("If-None-Match") == b.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	b.downloads++
	sum := md5.Sum(b.data)
	if b.badMD5 {
		sum[0] ^= 0xff
	}
	w.Header().Set("ETag", b.etag)
	w.Header().Add("X-Goog-Hash", "crc32c=AAAAAA==")
	w.Header().Add("X-Goog-Hash", "md5="+base64.StdEncoding.EncodeToString(sum[:]))
	w.Write(b.data)
}

func TestUpdateAndLookup(t *testing.T) {
	bucket := &fakeBucket{etag: `"v1"`, data: zipOf(t, map[string]string{
		"GO-1.json": `{"id":"GO-1","affected":[{"package":{"ecosystem":"Go","name":"example.com/a"}},{"package":{"ecosystem":"Go","name":"example.com/b"}}]}`,
		"GO-2.json": `{"id":"GO-2","affected":[{"package":{"ecosystem":"Go","name":"example.com/a"}}]}`,
		"GO-3.json": `{"id":"GO-3","withdrawn":"2024-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"Go","name":"example.com/a"}}]}`,
	})}
	srv := httptest.NewServer(bucket)
	defer srv.Close()

	db := New(t.TempDir())
	db.BaseURL = srv.URL
	ctx := context.Background()

	res, err := db.Update(ctx, "Go")
	if err != nil || !res.Changed || res.Meta.Records != 2 || res.Meta.ETag != `"v1"` {
		t.Fatalf("first update: %+v, %v", res, err)
	}
	recs, meta, err := db.Lookup("Go", "example.com/a")
	if err != nil || len(recs) != 2 || meta.Records != 2 {
		t.Fatalf("lookup a: %d records, %v (withdrawn GO-3 must be left out)", len(recs), err)
	}
	if !strings.Contains(string(recs[0]), `"GO-1"`) || !strings.Contains(string(recs[1]), `"GO-2"`) {
		t.Errorf("records = %s", recs)
	}
	if recs, _, _ := db.Lookup("Go", "example.com/none"); len(recs) != 0 {
		t.Errorf("unknown package: %d records", len(recs))
	}

	// Unchanged upstream: no second download, but the check time moves.
	before := res.Meta.UpdatedAt
	time.Sleep(10 * time.Millisecond)
	res, err = db.Update(ctx, "Go")
	if err != nil || res.Changed || bucket.downloads != 1 || !res.Meta.UpdatedAt.After(before) {
		t.Errorf("second update: %+v, downloads=%d, %v", res, bucket.downloads, err)
	}

	// A new version replaces the old one, even while a reader is open.
	bucket.etag = `"v2"`
	bucket.data = zipOf(t, map[string]string{"GO-9.json": `{"id":"GO-9","affected":[{"package":{"ecosystem":"Go","name":"example.com/a"}}]}`})
	if res, err = db.Update(ctx, "Go"); err != nil || !res.Changed {
		t.Fatalf("third update: %+v, %v", res, err)
	}
	if recs, _, _ := db.Lookup("Go", "example.com/a"); len(recs) != 1 || !strings.Contains(string(recs[0]), "GO-9") {
		t.Errorf("after update: %s", recs)
	}
	if st := db.Status(); len(st) != 1 || st[0].Ecosystem != "Go" {
		t.Errorf("status = %+v", st)
	}
	db.Close()
}

func TestUpdateRejectsCorruptDownload(t *testing.T) {
	bucket := &fakeBucket{etag: `"v1"`, badMD5: true, data: zipOf(t, map[string]string{"a.json": `{}`})}
	srv := httptest.NewServer(bucket)
	defer srv.Close()
	db := New(t.TempDir())
	db.BaseURL = srv.URL
	if _, err := db.Update(context.Background(), "Go"); err == nil || !strings.Contains(err.Error(), "MD5 mismatch") {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := db.Lookup("Go", "x"); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("a failed download must not install anything: %v", err)
	}
}

func TestUpdateUnknownEcosystem(t *testing.T) {
	if _, err := New(t.TempDir()).Update(context.Background(), "PyPI"); err == nil || !strings.Contains(err.Error(), "supported:") {
		t.Errorf("err = %v", err)
	}
}

func TestBaseAndStale(t *testing.T) {
	for in, want := range map[string]string{"Debian:12": "Debian", "Ubuntu:22.04:LTS": "Ubuntu", "Go": "Go", "Alpine:v3.19": "Alpine"} {
		if got := Base(in); got != want {
			t.Errorf("Base(%q) = %q", in, got)
		}
	}
	now := time.Now()
	if (Meta{UpdatedAt: now.Add(-6 * 24 * time.Hour)}).Stale(now) || !(Meta{UpdatedAt: now.Add(-8 * 24 * time.Hour)}).Stale(now) {
		t.Error("staleness threshold is 7 days")
	}
}
