// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// accessTokenSource yields a GCP OAuth access token and its lifetime. Two
// implementations: staticTokenSource (a fixed operator token, for enrollment) and
// federatedTokenSource (attestation→STS→optional impersonation, for the enclave).
type accessTokenSource interface {
	accessToken(ctx context.Context) (token string, ttl time.Duration, err error)
}

// staticTokenSource returns a fixed access token (no expiry known).
type staticTokenSource string

func (s staticTokenSource) accessToken(context.Context) (string, time.Duration, error) {
	if s == "" {
		return "", 0, fmt.Errorf("empty static access token")
	}
	return string(s), 0, nil
}

// federatedTokenSource performs the Workload Identity Federation exchange:
// a Confidential Space attestation token is swapped at STS for a federated access
// token, optionally impersonating a service account.
type federatedTokenSource struct {
	client *Client
	attest AttestationTokenSource
}

func (f *federatedTokenSource) accessToken(ctx context.Context) (string, time.Duration, error) {
	c := f.client
	if c.cfg.WIFAudience == "" {
		return "", 0, fmt.Errorf("WIFAudience is required for the federated token source")
	}

	// 1. Confidential Space attestation token (OIDC JWT) for the WIF audience.
	subjectToken, err := f.attest.Token(ctx, c.cfg.AttestationAudience)
	if err != nil {
		return "", 0, fmt.Errorf("attestation token: %w", err)
	}
	c.log.Debug("attestation token obtained",
		slog.String("provider", c.Name()),
		slog.String("audience", c.cfg.AttestationAudience),
		slog.Int("token_bytes", len(subjectToken)))

	// 2. STS token exchange (WIF).
	fedToken, fedTTL, err := f.stsExchange(ctx, subjectToken)
	if err != nil {
		return "", 0, fmt.Errorf("sts exchange: %w", err)
	}
	c.log.Debug("federated token minted", slog.String("provider", c.Name()))

	// 3. Optional service-account impersonation.
	if c.cfg.ServiceAccount == "" {
		return fedToken, fedTTL, nil
	}
	saToken, saExpiry, err := f.impersonate(ctx, fedToken)
	if err != nil {
		return "", 0, fmt.Errorf("impersonate %s: %w", c.cfg.ServiceAccount, err)
	}
	c.log.Debug("service account token minted",
		slog.String("provider", c.Name()), slog.String("service_account", c.cfg.ServiceAccount))
	return saToken, time.Until(saExpiry), nil
}

func (f *federatedTokenSource) stsExchange(ctx context.Context, subjectToken string) (string, time.Duration, error) {
	c := f.client
	reqBody, _ := json.Marshal(map[string]string{
		"audience":           c.cfg.WIFAudience,
		"grantType":          "urn:ietf:params:oauth:grant-type:token-exchange",
		"requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
		"scope":              cloudPlatformScope,
		"subjectTokenType":   "urn:ietf:params:oauth:token-type:jwt",
		"subjectToken":       subjectToken,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.STSEndpoint, bytes.NewReader(reqBody))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return "", 0, fmt.Errorf("status %d: %s", resp.StatusCode, googleErrorMessage(body))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", 0, fmt.Errorf("decode STS response: %w", err)
	}
	if out.AccessToken == "" {
		return "", 0, fmt.Errorf("STS returned no access token")
	}
	return out.AccessToken, time.Duration(out.ExpiresIn) * time.Second, nil
}

func (f *federatedTokenSource) impersonate(ctx context.Context, fedToken string) (string, time.Time, error) {
	c := f.client
	url := fmt.Sprintf("%s/v1/projects/-/serviceAccounts/%s:generateAccessToken",
		c.cfg.IAMCredentialsEndpoint, c.cfg.ServiceAccount)
	reqBody, _ := json.Marshal(map[string]any{
		"scope": []string{cloudPlatformScope},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+fedToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return "", time.Time{}, fmt.Errorf("status %d: %s", resp.StatusCode, googleErrorMessage(body))
	}
	var out struct {
		AccessToken string `json:"accessToken"`
		ExpireTime  string `json:"expireTime"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", time.Time{}, fmt.Errorf("decode impersonation response: %w", err)
	}
	if out.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("impersonation returned no access token")
	}
	expiry, err := time.Parse(time.RFC3339, out.ExpireTime)
	if err != nil {
		expiry = time.Now().Add(time.Hour)
	}
	return out.AccessToken, expiry, nil
}
