// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DefaultTEEServerSocket is the Confidential Space launcher's attestation socket.
// The launcher runs a small HTTP server here that issues OIDC attestation tokens
// bound to the enclave's measurement and container image digest.
const DefaultTEEServerSocket = "/run/container_launcher/teeserver.sock"

// AttestationTokenSource returns a signed attestation token (OIDC JWT) for the
// given audience. In production this is the Confidential Space launcher; tests
// and alternate attesters supply their own.
type AttestationTokenSource interface {
	Token(ctx context.Context, audience string) (string, error)
}

// ConfidentialSpaceTokenSource fetches attestation tokens from the launcher's
// unix-domain socket. It works only inside a Confidential Space VM.
type ConfidentialSpaceTokenSource struct {
	// SocketPath is the launcher socket. Empty uses DefaultTEEServerSocket.
	SocketPath string
	client     *http.Client
}

// NewConfidentialSpaceTokenSource builds a source that dials the launcher socket.
// The passed client's timeout is reused; its transport is replaced with a
// unix-socket dialer (the launcher is not reachable over TCP).
func NewConfidentialSpaceTokenSource(base *http.Client) *ConfidentialSpaceTokenSource {
	timeout := 15 * time.Second
	if base != nil && base.Timeout > 0 {
		timeout = base.Timeout
	}
	src := &ConfidentialSpaceTokenSource{SocketPath: DefaultTEEServerSocket}
	src.client = &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", src.SocketPath)
			},
		},
	}
	return src
}

// tokenRequest is the launcher's /v1/token request body.
type tokenRequest struct {
	Audience  string   `json:"audience"`
	TokenType string   `json:"token_type"`
	Nonces    []string `json:"nonces,omitempty"`
}

// Token implements AttestationTokenSource against the launcher socket.
func (s *ConfidentialSpaceTokenSource) Token(ctx context.Context, audience string) (string, error) {
	reqBody, _ := json.Marshal(tokenRequest{Audience: audience, TokenType: "OIDC"})
	// Host is ignored by the unix dialer but required for a valid URL.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/v1/token", bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("dial launcher socket %s: %w", s.SocketPath, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("launcher status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	token := strings.TrimSpace(string(body))
	if token == "" {
		return "", fmt.Errorf("launcher returned empty token")
	}
	return token, nil
}
