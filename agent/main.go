// SPDX-License-Identifier: Apache-2.0

// Command confidant-agent is the local, secretless forward proxy
// (see docs/local-agent.md).
//
// It runs a loopback CONNECT proxy that blind-tunnels non-intercepted hosts and,
// for intercepted hosts, MITM-terminates the TLS, detects the inert "cfdt:" ref,
// strips the credential, and relays to the broker over pinned mTLS. It holds no
// secrets and never calls an upstream API on the intercepted path.
//
// Build & run standalone:
//
//	cd agent && go build -o confidant-agent .
//	CONFIDANT_INTERCEPT="api.openai.com,*.amazonaws.com" \
//	CONFIDANT_BROKER="https://confidant-broker.<tailnet>.ts.net:8443" \
//	CONFIDANT_BROKER_SPKI_PIN="sha256/…" \
//	  ./confidant-agent -ca-export ./ca.pem
//	# trust ./ca.pem in your tool, then:
//	HTTPS_PROXY=http://127.0.0.1:8317 curl https://example.com
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/surybala/confidant/agent/internal/broker"
	"github.com/surybala/confidant/agent/internal/ca"
	"github.com/surybala/confidant/agent/internal/config"
	"github.com/surybala/confidant/agent/internal/proxy"
	"github.com/surybala/confidant/agent/internal/wire"
)

func main() {
	configPath := flag.String("config", "", "path to a JSON config file (optional)")
	listen := flag.String("listen", "", "override loopback listen address")
	brokerEndpoint := flag.String("broker", "", "override broker endpoint (https URL)")
	caExport := flag.String("ca-export", "", "write the local MITM CA cert (PEM) to this path and continue")
	logLevel := flag.String("log-level", "info", "log level: debug|info|warn|error")
	flag.Parse()

	log := newLogger(*logLevel)

	cfg := config.FromEnv()
	if *configPath != "" {
		loaded, err := config.Load(*configPath)
		if err != nil {
			log.Error("config load failed", slog.String("err", err.Error()))
			os.Exit(1)
		}
		cfg = loaded
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *brokerEndpoint != "" {
		cfg.BrokerEndpoint = *brokerEndpoint
	}

	// SECURITY (invariant I-A2): loopback only. Refuse to start otherwise.
	if !cfg.IsLoopback() {
		log.Error("refusing to bind non-loopback address", slog.String("listen", cfg.Listen))
		os.Exit(1)
	}

	authority, err := buildCA(cfg, log)
	if err != nil {
		log.Error("CA init failed", slog.String("err", err.Error()))
		os.Exit(1)
	}
	if *caExport != "" {
		if err := os.WriteFile(*caExport, authority.CertPEM(), 0o644); err != nil {
			log.Error("CA export failed", slog.String("err", err.Error()))
			os.Exit(1)
		}
		log.Info("exported MITM CA cert — trust this in your tools", slog.String("path", *caExport))
	}

	brokerClient := buildBroker(cfg, log)

	handler := proxy.New(cfg, authority, brokerClient, log)
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Info("confidant-agent starting",
			slog.String("addr", cfg.Listen),
			slog.Int("intercept_hosts", len(cfg.Intercept)))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server error", slog.String("err", err.Error()))
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("graceful shutdown failed", slog.String("err", err.Error()))
		os.Exit(1)
	}
}

func buildCA(cfg config.Config, log *slog.Logger) (*ca.CA, error) {
	if cfg.CACertPath != "" && cfg.CAKeyPath != "" {
		return ca.LoadOrCreate(cfg.CACertPath, cfg.CAKeyPath, cfg.PermittedCADomains())
	}
	log.Warn("using ephemeral in-memory MITM CA — tools won't trust it until installed; " +
		"set ca_cert_path/ca_key_path and use -ca-export to persist and trust it")
	return ca.New(cfg.PermittedCADomains())
}

func buildBroker(cfg config.Config, log *slog.Logger) proxy.BrokerClient {
	if cfg.BrokerEndpoint == "" {
		log.Warn("no broker endpoint configured — intercepted hosts will fail closed")
		return failClosedBroker{}
	}
	var clientCert *tls.Certificate
	if cfg.ClientCertPath != "" && cfg.ClientKeyPath != "" {
		crt, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
		if err != nil {
			log.Error("client cert load failed; intercepted hosts will fail closed",
				slog.String("err", err.Error()))
			return failClosedBroker{}
		}
		clientCert = &crt
	}
	c, err := broker.New(broker.Options{
		Endpoint:      cfg.BrokerEndpoint,
		SPKIPin:       cfg.ServerSPKIPin,
		TLSClientCert: clientCert,
	})
	if err != nil {
		log.Error("broker client init failed; intercepted hosts will fail closed",
			slog.String("err", err.Error()))
		return failClosedBroker{}
	}
	return c
}

// failClosedBroker is used when no broker is configured: every relay fails, so
// intercepted hosts fail closed (I-A5) rather than leaking anything.
type failClosedBroker struct{}

func (failClosedBroker) Relay(context.Context, wire.Request) (*http.Response, error) {
	return nil, errors.New("no broker configured")
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}
