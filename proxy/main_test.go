// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/surybala/confidant/proxy/internal/config"
	"github.com/surybala/confidant/proxy/internal/kms"
	"github.com/surybala/confidant/proxy/internal/kms/gcp"
	"github.com/surybala/confidant/proxy/internal/policy"
	"github.com/surybala/confidant/proxy/internal/store"
)

func TestBuildUpstreamClientIgnoresEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")

	client, err := buildUpstreamClient(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", client.Transport)
	}
	if tr.Proxy != nil {
		t.Fatal("broker upstream transport must not inherit environment proxy settings")
	}
}

func TestBuildUnwrapperDev(t *testing.T) {
	_, raw, err := kms.GenerateDevKEK()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "dev.kek")
	if err := kms.SaveDevKEKKey(path, raw); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default() // dev mode
	cfg.DevKEKPath = path

	u, err := buildUnwrapper(cfg, slog.Default())
	if err != nil {
		t.Fatalf("buildUnwrapper dev: %v", err)
	}
	if _, ok := u.(*kms.DevKEK); !ok {
		t.Errorf("dev unwrapper = %T, want *kms.DevKEK", u)
	}
}

func TestBuildUnwrapperEnclaveGCP(t *testing.T) {
	cfg := config.Default()
	cfg.Mode = config.ModeEnclave
	cfg.KMSProvider = config.KMSProviderGCP
	cfg.KMSKeyName = "projects/p/locations/global/keyRings/r/cryptoKeys/k"
	cfg.WIFAudience = "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool/providers/prov"
	cfg.KMSServiceAccount = "confidant-broker@p.iam.gserviceaccount.com"

	u, err := buildUnwrapper(cfg, slog.Default())
	if err != nil {
		t.Fatalf("buildUnwrapper enclave: %v", err)
	}
	if _, ok := u.(*kms.EnvelopeUnwrapper); !ok {
		t.Errorf("enclave unwrapper = %T, want *kms.EnvelopeUnwrapper", u)
	}
}

func TestSealForEnclaveRequiresToken(t *testing.T) {
	t.Setenv("GOOGLE_ACCESS_TOKEN", "")
	_, err := sealForEnclave("projects/p/.../cryptoKeys/k", "", "", []byte("secret"), []byte("aad"))
	if err == nil || !strings.Contains(err.Error(), "access token") {
		t.Fatalf("error = %v, want missing-access-token error", err)
	}
}

// mockKMSServer is a minimal Cloud KMS encrypt/decrypt stand-in (XOR "KEK").
func mockKMSServer(t *testing.T) *httptest.Server {
	t.Helper()
	const pad = 0x3c
	xor := func(b []byte) []byte {
		out := make([]byte, len(b))
		for i := range b {
			out[i] = b[i] ^ pad
		}
		return out
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, ":encrypt"):
			var in struct {
				Plaintext string `json:"plaintext"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			dek, _ := base64.StdEncoding.DecodeString(in.Plaintext)
			_ = json.NewEncoder(w).Encode(map[string]string{"ciphertext": base64.StdEncoding.EncodeToString(xor(dek))})
		case strings.HasSuffix(r.URL.Path, ":decrypt"):
			var in struct {
				Ciphertext string `json:"ciphertext"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			wrapped, _ := base64.StdEncoding.DecodeString(in.Ciphertext)
			_ = json.NewEncoder(w).Encode(map[string]string{"plaintext": base64.StdEncoding.EncodeToString(xor(wrapped))})
		default:
			http.Error(w, "unexpected "+r.URL.Path, http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestEnrollKMSProducesUnwrappableEnvelope proves the enrollment seal and the
// enclave unwrap agree: a secret sealed by `enroll -kms-key` is recovered by the
// EnvelopeUnwrapper the serving broker would use.
func TestEnrollKMSProducesUnwrappableEnvelope(t *testing.T) {
	srv := mockKMSServer(t)
	const key = "projects/p/locations/global/keyRings/r/cryptoKeys/k"
	secret := []byte("sk-REAL-enrolled-secret")
	pol := policy.Policy{
		Credential:   policy.Credential{Kind: "static", Inject: policy.Inject{Type: "header", Name: "Authorization"}},
		AllowHosts:   []string{"api.openai.com"},
		AllowMethods: []string{"GET"},
	}
	aad, err := store.EnvelopeAADFor("openai/personal", kms.AlgKMSGCM, key, pol)
	if err != nil {
		t.Fatal(err)
	}

	env, err := sealForEnclave(key, "operator-token", srv.URL, secret, aad)
	if err != nil {
		t.Fatalf("sealForEnclave: %v", err)
	}
	if env.Alg != kms.AlgKMSGCM {
		t.Errorf("alg = %q, want %q", env.Alg, kms.AlgKMSGCM)
	}
	if len(env.WrappedDEK) == 0 {
		t.Fatal("no wrapped DEK")
	}
	if strings.Contains(string(env.Ciphertext), string(secret)) {
		t.Error("ciphertext leaks the secret")
	}

	// Unwrap as the enclave would: a GCP client (static token here stands in for
	// the attestation flow) behind the EnvelopeUnwrapper.
	dec, err := gcp.New(gcp.Config{KMSKeyName: key, KMSEndpoint: srv.URL}, gcp.WithStaticAccessToken("t"))
	if err != nil {
		t.Fatal(err)
	}
	u, err := kms.NewEnvelopeUnwrapper(dec, slog.Default())
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

func TestEnrollKMSUsesEnvToken(t *testing.T) {
	srv := mockKMSServer(t)
	t.Setenv("GOOGLE_ACCESS_TOKEN", "env-token")
	key := "projects/p/locations/global/keyRings/r/cryptoKeys/k"
	aad, err := store.EnvelopeAADFor("openai/personal", kms.AlgKMSGCM, key, policy.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	env, err := sealForEnclave(key, "", srv.URL, []byte("x"), aad)
	if err != nil {
		t.Fatalf("sealForEnclave with env token: %v", err)
	}
	if env.Alg != kms.AlgKMSGCM {
		t.Errorf("alg = %q", env.Alg)
	}
}
