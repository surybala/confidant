// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/surybala/confidant/shared/kms"
)

// mockGoogle stands in for STS, IAM Credentials, and Cloud KMS. The mock "KEK"
// is a byte-wise XOR so encrypt/decrypt genuinely round-trips through the HTTP
// and base64 layers, without any real key material.
type mockGoogle struct {
	mu sync.Mutex

	kekPad byte // mock KEK transform

	// captured for assertions
	stsCalls        int
	kmsBearer       string // Authorization seen by the KMS decrypt/encrypt call
	subjectToken    string // subjectToken the STS exchange received
	stsAudience     string
	impersonateSA   string // service account seen at the IAM endpoint
	impersonateUsed bool

	// canned responses
	fedToken   string
	saToken    string
	stsStatus  int // 0 => 200
	kmsStatus  int // 0 => 200
	iamStatus  int // 0 => 200
	fedExpires int // expires_in seconds (0 => 3599)
}

func newMockGoogle() *mockGoogle {
	return &mockGoogle{kekPad: 0xAB, fedToken: "fed-token", saToken: "sa-token", fedExpires: 3599}
}

func (m *mockGoogle) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/token", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.stsCalls++
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		m.subjectToken = body["subjectToken"]
		m.stsAudience = body["audience"]
		status := m.stsStatus
		exp := m.fedExpires
		tok := m.fedToken
		m.mu.Unlock()

		if status != 0 {
			writeGoogleErr(w, status, "sts denied")
			return
		}
		writeJSON(w, map[string]any{"access_token": tok, "expires_in": exp, "token_type": "Bearer"})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, ":generateAccessToken"):
			m.mu.Lock()
			m.impersonateUsed = true
			m.impersonateSA = strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/projects/-/serviceAccounts/"), ":generateAccessToken")
			status := m.iamStatus
			tok := m.saToken
			m.mu.Unlock()
			if status != 0 {
				writeGoogleErr(w, status, "impersonation denied")
				return
			}
			writeJSON(w, map[string]any{"accessToken": tok, "expireTime": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})

		case strings.HasSuffix(r.URL.Path, ":decrypt"):
			m.recordBearer(r)
			if m.kmsStatus != 0 {
				writeGoogleErr(w, m.kmsStatus, "kms decrypt denied")
				return
			}
			var body struct {
				Ciphertext string `json:"ciphertext"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			wrapped, _ := base64.StdEncoding.DecodeString(body.Ciphertext)
			writeJSON(w, map[string]any{"plaintext": base64.StdEncoding.EncodeToString(m.xor(wrapped))})

		case strings.HasSuffix(r.URL.Path, ":encrypt"):
			m.recordBearer(r)
			if m.kmsStatus != 0 {
				writeGoogleErr(w, m.kmsStatus, "kms encrypt denied")
				return
			}
			var body struct {
				Plaintext string `json:"plaintext"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			dek, _ := base64.StdEncoding.DecodeString(body.Plaintext)
			writeJSON(w, map[string]any{"ciphertext": base64.StdEncoding.EncodeToString(m.xor(dek)), "name": "mock-kek"})

		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
		}
	})
	return mux
}

func (m *mockGoogle) recordBearer(r *http.Request) {
	m.mu.Lock()
	m.kmsBearer = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	m.mu.Unlock()
}

func (m *mockGoogle) xor(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ m.kekPad
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeGoogleErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": msg, "code": status}})
}

// fakeAttestation returns a canned attestation token and records the audience.
type fakeAttestation struct {
	token    string
	audience string
	err      error
}

func (f *fakeAttestation) Token(_ context.Context, audience string) (string, error) {
	f.audience = audience
	if f.err != nil {
		return "", f.err
	}
	return f.token, nil
}

const testKey = "projects/p/locations/global/keyRings/r/cryptoKeys/k"

func newTestClient(t *testing.T, m *mockGoogle, att *fakeAttestation, cfgMut func(*Config)) *Client {
	t.Helper()
	srv := httptest.NewServer(m.handler())
	t.Cleanup(srv.Close)

	cfg := Config{
		KMSKeyName:             testKey,
		WIFAudience:            "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/prov",
		STSEndpoint:            srv.URL + "/v1/token",
		IAMCredentialsEndpoint: srv.URL,
		KMSEndpoint:            srv.URL,
	}
	if cfgMut != nil {
		cfgMut(&cfg)
	}
	c, err := New(cfg, WithAttestationTokenSource(att), WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFederatedEncryptDecryptRoundTrip(t *testing.T) {
	m := newMockGoogle()
	att := &fakeAttestation{token: "attestation-jwt"}
	c := newTestClient(t, m, att, nil)

	dek := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	wrapped, err := c.Encrypt(context.Background(), dek)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := c.DecryptDEK(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(dek) {
		t.Errorf("round trip = %q, want %q", got, dek)
	}

	// The attestation token flowed through STS as the subject token.
	if m.subjectToken != "attestation-jwt" {
		t.Errorf("STS subjectToken = %q, want attestation-jwt", m.subjectToken)
	}
	// The federated token was the bearer used at KMS.
	if m.kmsBearer != "fed-token" {
		t.Errorf("KMS bearer = %q, want fed-token", m.kmsBearer)
	}
	// The attestation audience was derived from the WIF audience.
	wantAud := "https://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/prov"
	if att.audience != wantAud {
		t.Errorf("attestation audience = %q, want %q", att.audience, wantAud)
	}
}

func TestFullEnvelopeThroughUnwrapper(t *testing.T) {
	m := newMockGoogle()
	c := newTestClient(t, m, &fakeAttestation{token: "jwt"}, nil)

	// Seal a secret with a real random DEK wrapped by the (mock) KMS, then unwrap
	// through the production EnvelopeUnwrapper — end to end across the seam.
	secret := []byte("sk-REAL-VALUE")
	aad := []byte("record=openai/personal")
	env, err := kms.SealKMS(context.Background(), c.Encrypt, secret, aad, testKey)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	u, err := kms.NewEnvelopeUnwrapper(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := u.Unwrap(context.Background(), env, aad)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if string(got) != string(secret) {
		t.Errorf("unwrap = %q, want %q", got, secret)
	}
}

func TestImpersonationPath(t *testing.T) {
	m := newMockGoogle()
	c := newTestClient(t, m, &fakeAttestation{token: "jwt"}, func(cfg *Config) {
		cfg.ServiceAccount = "broker@proj.iam.gserviceaccount.com"
	})

	if _, err := c.DecryptDEK(context.Background(), []byte("wrapped-dek")); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !m.impersonateUsed {
		t.Fatal("impersonation endpoint was not called")
	}
	if m.impersonateSA != "broker@proj.iam.gserviceaccount.com" {
		t.Errorf("impersonated SA = %q", m.impersonateSA)
	}
	// The SA token (not the raw federated token) must be the KMS bearer.
	if m.kmsBearer != "sa-token" {
		t.Errorf("KMS bearer = %q, want sa-token", m.kmsBearer)
	}
}

func TestAccessTokenIsCached(t *testing.T) {
	m := newMockGoogle()
	c := newTestClient(t, m, &fakeAttestation{token: "jwt"}, nil)

	for i := 0; i < 3; i++ {
		if _, err := c.DecryptDEK(context.Background(), []byte("w")); err != nil {
			t.Fatalf("decrypt %d: %v", i, err)
		}
	}
	if m.stsCalls != 1 {
		t.Errorf("STS calls = %d, want 1 (token should be cached)", m.stsCalls)
	}
}

func TestSTSFailureFailsClosed(t *testing.T) {
	m := newMockGoogle()
	m.stsStatus = http.StatusForbidden // WIF condition not met (e.g. wrong image digest)
	c := newTestClient(t, m, &fakeAttestation{token: "jwt"}, nil)

	if _, err := c.DecryptDEK(context.Background(), []byte("w")); err == nil {
		t.Fatal("expected fail-closed error when STS denies")
	}
}

func TestKMSFailureFailsClosed(t *testing.T) {
	m := newMockGoogle()
	m.kmsStatus = http.StatusInternalServerError
	c := newTestClient(t, m, &fakeAttestation{token: "jwt"}, nil)

	if _, err := c.DecryptDEK(context.Background(), []byte("w")); err == nil {
		t.Fatal("expected fail-closed error when KMS errors")
	}
}

func TestAttestationFailureFailsClosed(t *testing.T) {
	m := newMockGoogle()
	att := &fakeAttestation{err: errors.New("no launcher socket")}
	c := newTestClient(t, m, att, nil)

	if _, err := c.DecryptDEK(context.Background(), []byte("w")); err == nil {
		t.Fatal("expected fail-closed error when attestation is unavailable")
	}
	if m.stsCalls != 0 {
		t.Errorf("STS should not be called when attestation fails; calls = %d", m.stsCalls)
	}
}

func TestStaticTokenSourceForEnrollment(t *testing.T) {
	m := newMockGoogle()
	srv := httptest.NewServer(m.handler())
	t.Cleanup(srv.Close)

	c, err := New(Config{KMSKeyName: testKey, KMSEndpoint: srv.URL},
		WithStaticAccessToken("operator-token"), WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	dek := []byte("0123456789abcdef0123456789abcdef")
	wrapped, err := c.Encrypt(context.Background(), dek)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if m.stsCalls != 0 {
		t.Errorf("static token must not hit STS; calls = %d", m.stsCalls)
	}
	if m.kmsBearer != "operator-token" {
		t.Errorf("KMS bearer = %q, want operator-token", m.kmsBearer)
	}
	// And it decrypts back.
	got, err := c.DecryptDEK(context.Background(), wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(dek) {
		t.Errorf("round trip = %q", got)
	}
}

func TestDefaultHTTPClientDoesNotFollowGoogleRedirects(t *testing.T) {
	var redirected bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected = true
	}))
	t.Cleanup(target.Close)

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	c, err := New(Config{KMSKeyName: testKey, KMSEndpoint: redirector.URL}, WithStaticAccessToken("operator-token"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Encrypt(context.Background(), []byte("0123456789abcdef0123456789abcdef")); err == nil {
		t.Fatal("expected KMS call to fail on redirect response")
	}
	if redirected {
		t.Fatal("default Google API client followed a redirect")
	}
}

func TestNewRequiresKeyName(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error when KMSKeyName is empty")
	}
}

func TestFederatedRequiresWIFAudience(t *testing.T) {
	m := newMockGoogle()
	srv := httptest.NewServer(m.handler())
	t.Cleanup(srv.Close)
	// No WIFAudience → the federated source cannot exchange.
	c, err := New(Config{KMSKeyName: testKey, KMSEndpoint: srv.URL, STSEndpoint: srv.URL + "/v1/token"},
		WithAttestationTokenSource(&fakeAttestation{token: "jwt"}), WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.DecryptDEK(context.Background(), []byte("w")); err == nil {
		t.Fatal("expected error without WIFAudience")
	}
}

func TestName(t *testing.T) {
	c, _ := New(Config{KMSKeyName: testKey}, WithStaticAccessToken("t"))
	if c.Name() != "gcp-kms" {
		t.Errorf("Name = %q", c.Name())
	}
}

func TestDeriveAttestationAudience(t *testing.T) {
	got := deriveAttestationAudience("//iam.googleapis.com/projects/1/providers/x")
	want := "https://iam.googleapis.com/projects/1/providers/x"
	if got != want {
		t.Errorf("derive = %q, want %q", got, want)
	}
}

func TestGoogleErrorMessage(t *testing.T) {
	msg := googleErrorMessage([]byte(`{"error":{"message":"permission denied"}}`))
	if msg != "permission denied" {
		t.Errorf("msg = %q", msg)
	}
	if got := googleErrorMessage([]byte("plain text error")); got != "plain text error" {
		t.Errorf("plain msg = %q", got)
	}
	if got := googleErrorMessage(nil); got != "no error body" {
		t.Errorf("empty msg = %q", got)
	}
}
