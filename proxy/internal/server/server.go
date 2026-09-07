// SPDX-License-Identifier: Apache-2.0

// Package server wires the broker's HTTP surface and mTLS.
package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/surybala/confidant/proxy/internal/config"
	"github.com/surybala/confidant/proxy/internal/pipeline"
)

// NewMux returns the broker's HTTP handler: liveness plus the proxy pipeline.
func NewMux(h *pipeline.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		// Liveness only — never expose attestation internals or config.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("POST /v1/proxy", h.Handle)
	return mux
}

// BuildServerTLS builds the mTLS server config from cfg. Returns nil (with no
// error) when no server cert is configured, signalling dev plaintext mode.
//
// When ClientCAPath is set, the broker requires and verifies enrolled agent
// client certificates (broker-core.md §4 — the mTLS gate that sits under
// Tailscale).
func BuildServerTLS(cfg config.Config) (*tls.Config, error) {
	if cfg.TLSCertPath == "" || cfg.TLSKeyPath == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}
	tc := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	if cfg.ClientCAPath != "" {
		pool, err := loadCertPool(cfg.ClientCAPath)
		if err != nil {
			return nil, err
		}
		tc.ClientCAs = pool
		tc.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tc, nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certs parsed from %s", path)
	}
	return pool, nil
}
