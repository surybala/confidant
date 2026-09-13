// SPDX-License-Identifier: Apache-2.0

// Package gcp implements the GCP flavor of kms.KeyDecryptor: attestation-gated
// key release via Cloud KMS + Workload Identity Federation (WIF).
//
// Unwrap path, per broker-core.md §5 (runs inside the Confidential Space enclave):
//
//  1. Obtain a Confidential Space OIDC attestation token (see attestation.go). Its
//     claims include the enclave's boot measurement and the container image digest.
//  2. Exchange it at the Security Token Service (STS) for a short-lived federated
//     access token. WIF mints one only if the token matches the pinned provider
//     condition (swname==CONFIDENTIAL_SPACE, STABLE, image_digest==<pinned>).
//  3. Impersonate a service account (IAM Credentials) so KMS decrypt IAM can stay
//     scoped to one service account rather than the raw WIF pool.
//  4. Cloud KMS decrypt(wrapped_dek) → plaintext DEK. KMS releases it only to the
//     attested principal, so a stolen store or a tampered image gets nothing.
//
// The KEK never leaves KMS. The DEK is fetched per unwrap; only the short-lived
// GCP access token is cached (operational state, like an OAuth token), never the
// DEK or any KEK material (invariant I-B6). The enrollment counterpart wraps a DEK
// via Encrypt using an operator-supplied access token (WithStaticAccessToken).
//
// This package is stdlib-only by design: the enclave's dependency tree is part of
// its trusted computing base, so the GCP REST calls are made with net/http rather
// than the Google Cloud SDK.
package gcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/surybala/confidant/shared/kms"
)

// Default Google endpoints. Overridable via options for tests/staging.
const (
	defaultSTSEndpoint            = "https://sts.googleapis.com/v1/token"
	defaultIAMCredentialsEndpoint = "https://iamcredentials.googleapis.com"
	defaultKMSEndpoint            = "https://cloudkms.googleapis.com"

	cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
	// tokenRefreshSkew refreshes cached access tokens early so an in-flight call
	// never races the expiry.
	tokenRefreshSkew = 60 * time.Second
)

// Config parameterizes the GCP KMS provider. The security-relevant values
// (KMSKeyName, WIFAudience, ServiceAccount) are measured config in production —
// baked into the attested image — not request-controlled.
type Config struct {
	// KMSKeyName is the KEK resource, e.g.
	// projects/P/locations/global/keyRings/R/cryptoKeys/K. Required.
	KMSKeyName string

	// WIFAudience is the STS audience identifying the workload identity provider,
	// e.g. //iam.googleapis.com/projects/NUM/locations/global/workloadIdentityPools/POOL/providers/PROV.
	// Required for the federated (enclave) flow; unused with a static token.
	WIFAudience string

	// AttestationAudience is the audience requested in the Confidential Space
	// attestation token. Defaults to the WIF provider URL derived from WIFAudience
	// (the leading "//" replaced with "https://"), which is what WIF expects.
	AttestationAudience string

	// ServiceAccount is impersonated after the STS exchange so KMS decrypt can be
	// granted to an SA rather than the raw WIF principal set. Enclave serve-mode
	// validation requires it; tests and enrollment may leave it empty.
	ServiceAccount string

	// Endpoint overrides (tests/staging). Empty uses the Google defaults.
	STSEndpoint            string
	IAMCredentialsEndpoint string
	KMSEndpoint            string
}

// Client implements kms.KeyDecryptor for GCP and provides Encrypt for enrollment.
type Client struct {
	cfg      Config
	http     *http.Client
	log      *slog.Logger
	tokenSrc accessTokenSource

	mu     sync.Mutex // guards the cached access token
	cached cachedToken
}

type cachedToken struct {
	value  string
	expiry time.Time
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets the HTTP client used for all Google API calls (and, for the
// federated source, the attestation socket). Defaults to a 15s-timeout client.
func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) {
		if c != nil {
			cl.http = c
		}
	}
}

// WithLogger sets the structured logger. A nil logger keeps slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(cl *Client) {
		if l != nil {
			cl.log = l
		}
	}
}

// WithAttestationTokenSource overrides how the Confidential Space attestation
// token is obtained (the default reads the launcher socket). Used by tests and by
// alternate attesters.
func WithAttestationTokenSource(ts AttestationTokenSource) Option {
	return func(cl *Client) {
		if ts != nil {
			cl.tokenSrc = &federatedTokenSource{client: cl, attest: ts}
		}
	}
}

// WithStaticAccessToken configures the client to use a fixed GCP OAuth access
// token instead of the attestation→STS exchange. This is the enrollment path:
// the operator supplies a token from `gcloud auth print-access-token`. It has no
// attestation gating and must never be used inside the enclave.
func WithStaticAccessToken(token string) Option {
	return func(cl *Client) {
		cl.tokenSrc = staticTokenSource(token)
	}
}

// New builds a GCP KMS client. By default it uses the federated (attestation)
// token source reading the Confidential Space launcher socket — the enclave path.
// Use WithStaticAccessToken for enrollment on an operator machine.
func New(cfg Config, opts ...Option) (*Client, error) {
	if strings.TrimSpace(cfg.KMSKeyName) == "" {
		return nil, fmt.Errorf("gcp: KMSKeyName is required")
	}
	if cfg.STSEndpoint == "" {
		cfg.STSEndpoint = defaultSTSEndpoint
	}
	if cfg.IAMCredentialsEndpoint == "" {
		cfg.IAMCredentialsEndpoint = defaultIAMCredentialsEndpoint
	}
	if cfg.KMSEndpoint == "" {
		cfg.KMSEndpoint = defaultKMSEndpoint
	}
	if cfg.AttestationAudience == "" && cfg.WIFAudience != "" {
		cfg.AttestationAudience = deriveAttestationAudience(cfg.WIFAudience)
	}

	cl := &Client{
		cfg: cfg,
		http: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		log: slog.Default(),
	}
	for _, o := range opts {
		o(cl)
	}
	// Default token source: federated via the Confidential Space socket.
	if cl.tokenSrc == nil {
		cl.tokenSrc = &federatedTokenSource{client: cl, attest: NewConfidentialSpaceTokenSource(cl.http)}
	}
	return cl, nil
}

// Name implements kms.KeyDecryptor.
func (c *Client) Name() string { return "gcp-kms" }

var _ kms.KeyDecryptor = (*Client)(nil)

// DecryptDEK implements kms.KeyDecryptor: Cloud KMS decrypt of a wrapped DEK.
func (c *Client) DecryptDEK(ctx context.Context, wrappedDEK []byte) ([]byte, error) {
	if len(wrappedDEK) == 0 {
		return nil, fmt.Errorf("empty wrapped DEK")
	}
	token, err := c.accessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("obtain access token: %w", err)
	}

	reqBody, _ := json.Marshal(map[string]string{
		"ciphertext": base64.StdEncoding.EncodeToString(wrappedDEK),
	})
	var out struct {
		Plaintext string `json:"plaintext"`
	}
	url := c.cfg.KMSEndpoint + "/v1/" + c.cfg.KMSKeyName + ":decrypt"
	if err := c.doJSON(ctx, url, token, reqBody, &out); err != nil {
		return nil, fmt.Errorf("kms decrypt: %w", err)
	}
	dek, err := base64.StdEncoding.DecodeString(out.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("kms decrypt: decode plaintext: %w", err)
	}
	c.log.Debug("kms decrypt ok", slog.String("provider", c.Name()), slog.Int("dek_bytes", len(dek)))
	return dek, nil
}

// Encrypt wraps a DEK with the KMS KEK (Cloud KMS encrypt). It is the enrollment
// counterpart to DecryptDEK, and satisfies kms.WrapFunc.
func (c *Client) Encrypt(ctx context.Context, dek []byte) ([]byte, error) {
	if len(dek) == 0 {
		return nil, fmt.Errorf("empty DEK")
	}
	token, err := c.accessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("obtain access token: %w", err)
	}
	reqBody, _ := json.Marshal(map[string]string{
		"plaintext": base64.StdEncoding.EncodeToString(dek),
	})
	var out struct {
		Ciphertext string `json:"ciphertext"`
	}
	url := c.cfg.KMSEndpoint + "/v1/" + c.cfg.KMSKeyName + ":encrypt"
	if err := c.doJSON(ctx, url, token, reqBody, &out); err != nil {
		return nil, fmt.Errorf("kms encrypt: %w", err)
	}
	wrapped, err := base64.StdEncoding.DecodeString(out.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("kms encrypt: decode ciphertext: %w", err)
	}
	return wrapped, nil
}

// accessToken returns a valid GCP OAuth access token, refreshing via the token
// source when the cache is empty or near expiry. The access token is operational
// state; the KEK and DEK are never cached (I-B6).
func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cached.value != "" && time.Now().Before(c.cached.expiry.Add(-tokenRefreshSkew)) {
		return c.cached.value, nil
	}
	tok, ttl, err := c.tokenSrc.accessToken(ctx)
	if err != nil {
		return "", err
	}
	if ttl <= 0 {
		ttl = time.Hour // conservative default when the provider omits expiry
	}
	c.cached = cachedToken{value: tok, expiry: time.Now().Add(ttl)}
	return tok, nil
}

// doJSON POSTs a JSON body with a bearer token and decodes a JSON response. It
// never logs the token or the body (both may carry key material).
func (c *Client) doJSON(ctx context.Context, url, bearer string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("status %d: %s", resp.StatusCode, googleErrorMessage(respBody))
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// deriveAttestationAudience turns a WIF STS audience (//iam.googleapis.com/…) into
// the https:// provider URL that Confidential Space should mint the token for.
func deriveAttestationAudience(wifAudience string) string {
	return "https://iam.googleapis.com/" + strings.TrimPrefix(strings.TrimPrefix(wifAudience, "//iam.googleapis.com/"), "//")
}

// googleErrorMessage extracts a human-readable message from a Google API error
// body without echoing anything secret (error bodies contain no key material).
func googleErrorMessage(body []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if json.Unmarshal(body, &e) == nil {
		if e.Error.Message != "" {
			return e.Error.Message
		}
		if e.ErrorDescription != "" {
			return e.ErrorDescription
		}
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 200 {
		msg = msg[:200]
	}
	if msg == "" {
		return "no error body"
	}
	return msg
}
