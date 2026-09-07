// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// serveSocket runs an HTTP server on a unix socket and returns its path. The
// handler mimics the Confidential Space launcher's /v1/token endpoint.
func serveSocket(t *testing.T, h http.Handler) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets not supported on windows")
	}
	// Unix socket paths are length-limited (~104 bytes on darwin), and the default
	// TMPDIR is too deep — use a short dir directly under /tmp.
	dir, err := os.MkdirTemp("/tmp", "cfdt")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "t.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

func TestConfidentialSpaceTokenSource(t *testing.T) {
	var gotAudience, gotTokenType string
	sock := serveSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/token" || r.Method != http.MethodPost {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var body tokenRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotAudience = body.Audience
		gotTokenType = body.TokenType
		_, _ = w.Write([]byte("eyJhbGciOi.attestation.jwt\n"))
	}))

	src := NewConfidentialSpaceTokenSource(&http.Client{Timeout: 2 * time.Second})
	src.SocketPath = sock

	tok, err := src.Token(context.Background(), "https://iam.googleapis.com/prov")
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "eyJhbGciOi.attestation.jwt" {
		t.Errorf("token = %q (trailing whitespace should be trimmed)", tok)
	}
	if gotAudience != "https://iam.googleapis.com/prov" {
		t.Errorf("audience = %q", gotAudience)
	}
	if gotTokenType != "OIDC" {
		t.Errorf("token_type = %q, want OIDC", gotTokenType)
	}
}

func TestConfidentialSpaceTokenSourceServerError(t *testing.T) {
	sock := serveSocket(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "attestation unavailable", http.StatusServiceUnavailable)
	}))
	src := NewConfidentialSpaceTokenSource(nil)
	src.SocketPath = sock

	if _, err := src.Token(context.Background(), "aud"); err == nil {
		t.Fatal("expected error on launcher 503")
	}
}

func TestConfidentialSpaceTokenSourceEmptyToken(t *testing.T) {
	sock := serveSocket(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("   \n"))
	}))
	src := NewConfidentialSpaceTokenSource(nil)
	src.SocketPath = sock

	if _, err := src.Token(context.Background(), "aud"); err == nil {
		t.Fatal("expected error on empty token")
	}
}

func TestConfidentialSpaceTokenSourceNoSocket(t *testing.T) {
	src := NewConfidentialSpaceTokenSource(&http.Client{Timeout: time.Second})
	src.SocketPath = filepath.Join(t.TempDir(), "does-not-exist.sock")
	if _, err := src.Token(context.Background(), "aud"); err == nil {
		t.Fatal("expected dial error when the socket is absent")
	}
}

func TestDefaultTokenSourceIsConfidentialSpace(t *testing.T) {
	c, err := New(Config{KMSKeyName: testKey, WIFAudience: "//iam.googleapis.com/x"})
	if err != nil {
		t.Fatal(err)
	}
	fed, ok := c.tokenSrc.(*federatedTokenSource)
	if !ok {
		t.Fatalf("default token source = %T, want *federatedTokenSource", c.tokenSrc)
	}
	if _, ok := fed.attest.(*ConfidentialSpaceTokenSource); !ok {
		t.Errorf("default attestation source = %T, want *ConfidentialSpaceTokenSource", fed.attest)
	}
}
