package image

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// registry is a minimal client for the OCI Distribution API
// (https://github.com/opencontainers/distribution-spec), enough to pull
// manifests and layers anonymously or with credentials from the Docker
// config file.
type registry struct {
	ref    Reference
	scheme string // "https", or "http" for localhost registries and tests
	client *http.Client
	creds  *basicAuth

	mu    sync.Mutex
	token string
}

type basicAuth struct{ user, pass string }

const maxManifestSize = 8 << 20

func newRegistry(ref Reference) *registry {
	scheme := "https"
	if host, _, _ := strings.Cut(ref.Registry, ":"); host == "localhost" || host == "127.0.0.1" {
		scheme = "http"
	}
	return &registry{
		ref:    ref,
		scheme: scheme,
		client: &http.Client{Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
		}},
		creds: dockerConfigAuth(ref.Registry),
	}
}

// manifest fetches a manifest or index by tag or digest. When the
// reference is a digest the content is verified against it.
func (r *registry) manifest(ctx context.Context, refOrDigest string) (manifest, string, error) {
	resp, err := r.get(ctx, "/manifests/"+refOrDigest, manifestAccept)
	if err != nil {
		return manifest{}, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestSize))
	if err != nil {
		return manifest{}, "", err
	}
	digest := "sha256:" + sha256Hex(data)
	if strings.HasPrefix(refOrDigest, "sha256:") && digest != refOrDigest {
		return manifest{}, "", fmt.Errorf("manifest digest mismatch: got %s, want %s", digest, refOrDigest)
	}
	m, err := parseManifest(data)
	if err != nil {
		return m, "", err
	}
	if m.MediaType == "" {
		m.MediaType = strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0])
	}
	return m, digest, nil
}

// blob streams a blob. The returned reader fails at EOF if the content
// does not match the digest, so a tampered layer is never trusted.
func (r *registry) blob(ctx context.Context, digest string) (io.ReadCloser, error) {
	if !digestPattern.MatchString(digest) {
		return nil, fmt.Errorf("unsupported digest %q", digest)
	}
	resp, err := r.get(ctx, "/blobs/"+digest, "")
	if err != nil {
		return nil, err
	}
	return &verifyingReader{rc: resp.Body, h: sha256.New(), want: strings.TrimPrefix(digest, "sha256:")}, nil
}

// get performs an authenticated GET, answering a Bearer challenge once.
func (r *registry) get(ctx context.Context, apiPath, accept string) (*http.Response, error) {
	u := r.scheme + "://" + r.ref.apiHost() + "/v2/" + r.ref.Repository + apiPath
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		r.mu.Lock()
		token := r.token
		r.mu.Unlock()
		switch {
		case token != "":
			req.Header.Set("Authorization", "Bearer "+token)
		case r.creds != nil:
			req.SetBasicAuth(r.creds.user, r.creds.pass)
		}

		resp, err := r.client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			challenge := resp.Header.Get("WWW-Authenticate")
			_ = resp.Body.Close()
			if err := r.authenticate(ctx, challenge); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			return nil, registryError(r.ref, resp.StatusCode, body)
		}
		return resp, nil
	}
}

// authenticate obtains a pull token for the repository from the realm in
// a "Bearer realm=...,service=...,scope=..." challenge.
func (r *registry) authenticate(ctx context.Context, challenge string) error {
	scheme, params, _ := strings.Cut(challenge, " ")
	if !strings.EqualFold(scheme, "Bearer") {
		if r.creds == nil {
			return fmt.Errorf("%s requires credentials; log in with `docker login %s`", r.ref.Registry, r.ref.Registry)
		}
		return nil // retry with basic auth
	}
	p := parseChallenge(params)
	realm, err := url.Parse(p["realm"])
	if err != nil || realm.Scheme == "" {
		return fmt.Errorf("invalid auth challenge from %s: %q", r.ref.Registry, challenge)
	}
	q := realm.Query()
	if p["service"] != "" {
		q.Set("service", p["service"])
	}
	q.Set("scope", "repository:"+r.ref.Repository+":pull")
	realm.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return err
	}
	if r.creds != nil {
		req.SetBasicAuth(r.creds.user, r.creds.pass)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("get registry token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("get registry token: %s", resp.Status)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return fmt.Errorf("get registry token: %w", err)
	}
	r.mu.Lock()
	r.token = tok.Token
	if r.token == "" {
		r.token = tok.AccessToken
	}
	r.mu.Unlock()
	return nil
}

func parseChallenge(params string) map[string]string {
	out := map[string]string{}
	for len(params) > 0 {
		key, rest, ok := strings.Cut(params, "=")
		if !ok {
			break
		}
		key = strings.TrimSpace(strings.TrimLeft(key, ","))
		var value string
		if strings.HasPrefix(rest, `"`) {
			end := strings.IndexByte(rest[1:], '"')
			if end < 0 {
				break
			}
			value, rest = rest[1:1+end], rest[2+end:]
		} else {
			value, rest, _ = strings.Cut(rest, ",")
		}
		out[strings.ToLower(key)] = value
		params = strings.TrimLeft(rest, ", ")
	}
	return out
}

func registryError(ref Reference, status int, body []byte) error {
	var e struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	msg := http.StatusText(status)
	if json.Unmarshal(body, &e) == nil && len(e.Errors) > 0 {
		msg = e.Errors[0].Code + ": " + e.Errors[0].Message
	}
	if status == http.StatusNotFound || status == http.StatusUnauthorized {
		msg += fmt.Sprintf(" (check that %s exists and you can pull it)", ref)
	}
	return fmt.Errorf("registry %s: %s", ref.Registry, msg)
}

// dockerConfigAuth reads inline credentials for a registry from
// $DOCKER_CONFIG/config.json or ~/.docker/config.json. Credential helpers
// (credsStore, credHelpers) are not supported.
func dockerConfigAuth(registry string) *basicAuth {
	dir := os.Getenv("DOCKER_CONFIG")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		dir = filepath.Join(home, ".docker")
	}
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return nil
	}
	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
		CredsStore string `json:"credsStore"`
	}
	if json.Unmarshal(data, &cfg) != nil {
		return nil
	}
	keys := []string{registry, "https://" + registry, "http://" + registry}
	if registry == dockerHub {
		keys = append(keys, "https://index.docker.io/v1/", "index.docker.io")
	}
	for _, k := range keys {
		entry, ok := cfg.Auths[k]
		if !ok || entry.Auth == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(entry.Auth)
		if err != nil {
			continue
		}
		if user, pass, ok := strings.Cut(string(raw), ":"); ok {
			return &basicAuth{user, pass}
		}
	}
	if cfg.CredsStore != "" {
		slog.Debug("docker credential helpers are not supported; pulling anonymously", "registry", registry, "credsStore", cfg.CredsStore)
	}
	return nil
}

// verifyingReader hashes a blob as it is read and fails at EOF on a
// digest mismatch.
type verifyingReader struct {
	rc   io.ReadCloser
	h    hash.Hash
	want string
}

var errDigestMismatch = errors.New("blob digest mismatch")

func (v *verifyingReader) Read(p []byte) (int, error) {
	n, err := v.rc.Read(p)
	v.h.Write(p[:n])
	if errors.Is(err, io.EOF) && hex.EncodeToString(v.h.Sum(nil)) != v.want {
		return n, fmt.Errorf("%w: want sha256:%s", errDigestMismatch, v.want)
	}
	return n, err
}

func (v *verifyingReader) Close() error { return v.rc.Close() }

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
