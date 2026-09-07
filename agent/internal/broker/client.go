// SPDX-License-Identifier: Apache-2.0

// Package broker is the agent's client to the broker's /v1/proxy endpoint.
//
// Transport security is mTLS with the broker's server certificate pinned by
// SubjectPublicKeyInfo hash (invariant I-A9): a certificate not matching the pin
// aborts the connection, so a rogue peer cannot impersonate the broker even on
// the tailnet. In production this connection additionally rides the Tailscale
// tailnet (there is no public route to the broker) — that is a deployment/network
// concern, not code here.
//
// The agent presents its enrolled device client certificate; it adds no other
// credential of its own (invariant I-A7).
package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/surybala/confidant/agent/internal/wire"
)

// Client relays requests to the broker over pinned mTLS.
type Client struct {
	endpoint string
	http     *http.Client
}

// Options configures a Client. TLSClientCert is optional in local testing but
// required to authenticate to a real broker.
type Options struct {
	Endpoint      string
	SPKIPin       string           // "sha256/<base64 SPKI>"; required for pinned verification
	TLSClientCert *tls.Certificate // agent device identity (mTLS)
	DialTimeout   time.Duration
}

// New builds a Client from options.
func New(o Options) (*Client, error) {
	if o.Endpoint == "" {
		return nil, fmt.Errorf("broker endpoint is required")
	}
	if o.DialTimeout == 0 {
		o.DialTimeout = 10 * time.Second
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.TLSClientCert != nil {
		tlsCfg.Certificates = []tls.Certificate{*o.TLSClientCert}
	}
	if o.SPKIPin != "" {
		// Pin the broker's public key instead of trusting a CA chain.
		tlsCfg.InsecureSkipVerify = true // verification is done by VerifyPeerCertificate
		tlsCfg.VerifyPeerCertificate = pinVerifier(o.SPKIPin)
	}

	tr := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: o.DialTimeout}).DialContext,
		TLSClientConfig:     tlsCfg,
		TLSHandshakeTimeout: o.DialTimeout,
		ForceAttemptHTTP2:   false, // keep HTTP/1.1 semantics for streaming relay
	}
	return &Client{
		endpoint: strings.TrimRight(o.Endpoint, "/"),
		http:     &http.Client{Transport: tr}, // no global timeout: streaming responses
	}, nil
}

// Relay POSTs the wire request to the broker and returns the live response. The
// caller owns resp.Body and must close it. A non-nil error means the broker was
// unreachable or the transport failed — the caller MUST fail closed (I-A5/I-A12).
func (c *Client) Relay(ctx context.Context, req wire.Request) (*http.Response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/v1/proxy", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	return c.http.Do(httpReq)
}

// SPKIPin returns the "sha256/<base64>" pin of a certificate's public key info.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256/" + base64.StdEncoding.EncodeToString(sum[:])
}

func pinVerifier(pin string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("broker presented no certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse broker certificate: %w", err)
		}
		got := SPKIPin(leaf)
		if subtle.ConstantTimeCompare([]byte(got), []byte(pin)) != 1 {
			return fmt.Errorf("broker certificate pin mismatch")
		}
		return nil
	}
}
