// SPDX-License-Identifier: Apache-2.0

// Command confidant-proxy is the broker core (see docs/broker-core.md).
//
// Two modes:
//
//	confidant-proxy serve   # run the /v1/proxy pipeline (default)
//	confidant-proxy enroll  # seal a secret + policy into the store
//
// In this Phase-1 local build a dev KEK file stands in for Cloud KMS +
// attestation, and a JSON file stands in for the secret store. Serve with mTLS by
// setting TLS_CERT/TLS_KEY (and CLIENT_CA to require enrolled agent certs);
// without them it runs DEV PLAINTEXT.
//
//	# enroll a secret (reads the secret value from stdin)
//	printf 'sk-live-...' | confidant-proxy enroll \
//	    -id openai/personal -kek dev.kek -store store.json \
//	    -host api.openai.com -methods GET,POST
//
//	# serve
//	SECRET_STORE=store.json DEV_KEK=dev.kek AUDIT_SINK=audit.log \
//	    confidant-proxy serve -listen :8443
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/surybala/confidant/proxy/internal/audit"
	"github.com/surybala/confidant/proxy/internal/config"
	"github.com/surybala/confidant/proxy/internal/credmod"
	"github.com/surybala/confidant/proxy/internal/kms"
	"github.com/surybala/confidant/proxy/internal/pipeline"
	"github.com/surybala/confidant/proxy/internal/policy"
	"github.com/surybala/confidant/proxy/internal/server"
	"github.com/surybala/confidant/proxy/internal/store"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "enroll" {
		if err := runEnroll(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "enroll:", err)
			os.Exit(1)
		}
		return
	}
	// default: serve (accept an explicit "serve" subcommand too)
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "serve" {
		args = args[1:]
	}
	if err := runServe(args); err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		os.Exit(1)
	}
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "", "override listen address")
	logLevel := fs.String("log-level", "", "log level: debug|info|warn|error")
	_ = fs.Parse(args)

	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}

	// Logs on stderr; the audit stream owns stdout when no file is set.
	log := newLogger(cfg.LogLevel, os.Stderr)

	if err := cfg.ValidateForServe(); err != nil {
		return err
	}
	kek, err := kms.LoadDevKEK(cfg.DevKEKPath)
	if err != nil {
		return err
	}
	st, err := store.LoadFile(cfg.StorePath)
	if err != nil {
		return err
	}

	auditor, closeAudit, err := buildAuditor(cfg.AuditPath)
	if err != nil {
		return err
	}
	defer closeAudit()

	upstreamClient, err := buildUpstreamClient(cfg)
	if err != nil {
		return err
	}

	h := pipeline.New(pipeline.Deps{
		Store:     st,
		Unwrapper: kek,
		Modules:   credmod.Default(),
		Limiter:   policy.NewLimiter(),
		Egress:    cfg.EgressAllow,
		Upstream:  upstreamClient,
		Audit:     auditor,
		Log:       log,
		MaxBody:   cfg.MaxBodyBytes,
	})

	tlsCfg, err := server.BuildServerTLS(cfg)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.NewMux(h),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if tlsCfg == nil {
		log.Warn("DEV MODE: serving plaintext HTTP — mTLS/attestation NOT configured",
			slog.String("listen", cfg.Listen))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Info("confidant-proxy starting", slog.String("addr", cfg.Listen), slog.Bool("mtls", tlsCfg != nil))
		var serveErr error
		if tlsCfg != nil {
			serveErr = srv.ListenAndServeTLS("", "")
		} else {
			serveErr = srv.ListenAndServe()
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			log.Error("server error", slog.String("err", serveErr.Error()))
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// buildAuditor returns a hash-chained auditor writing to AUDIT_SINK (a file), or
// to stdout when unset. The returned closer flushes/closes the sink.
func buildAuditor(path string) (audit.Auditor, func(), error) {
	if path == "" {
		return audit.NewChainWriter(os.Stdout), func() {}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open audit sink: %w", err)
	}
	return audit.NewChainWriter(f), func() { _ = f.Close() }, nil
}

// buildUpstreamClient builds the client used for outbound calls to real APIs,
// optionally trusting an extra CA (UPSTREAM_CA) on top of the system roots.
func buildUpstreamClient(cfg config.Config) (*http.Client, error) {
	tr := &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	if cfg.UpstreamCAPath != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		pem, err := os.ReadFile(cfg.UpstreamCAPath)
		if err != nil {
			return nil, fmt.Errorf("read upstream CA: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certs parsed from UPSTREAM_CA")
		}
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	}
	return &http.Client{Timeout: cfg.UpstreamTimeout, Transport: tr}, nil
}

func runEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	id := fs.String("id", "", "secret id, e.g. openai/personal")
	kekPath := fs.String("kek", "dev.kek", "dev KEK file (created if missing)")
	storePath := fs.String("store", "store.json", "secret store JSON file")
	policyPath := fs.String("policy", "", "optional policy JSON file")
	host := fs.String("host", "", "allowed host (when no -policy given)")
	methods := fs.String("methods", "GET,POST", "allowed methods (when no -policy given)")
	_ = fs.Parse(args)

	if *id == "" {
		return errors.New("-id is required")
	}

	kek, err := loadOrCreateKEK(*kekPath)
	if err != nil {
		return err
	}

	secret, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("read secret from stdin: %w", err)
	}
	secret = trimTrailingNewline(secret)
	if len(secret) == 0 {
		return errors.New("empty secret on stdin")
	}
	defer kms.Zero(secret)

	pol, err := buildEnrollPolicy(*policyPath, *host, *methods)
	if err != nil {
		return err
	}

	env, err := kek.Seal(secret)
	if err != nil {
		return err
	}

	st := store.NewMemStore()
	if existing, err := store.LoadFile(*storePath); err == nil {
		for _, r := range existing.All() {
			st.Put(r)
		}
	}
	st.Put(&store.Record{ID: *id, Envelope: env, Policy: pol})
	if err := store.SaveFile(*storePath, st); err != nil {
		return err
	}

	fmt.Printf("enrolled %q -> %s (policy: %d host(s), kind=%s)\n",
		*id, *storePath, len(pol.AllowHosts), pol.Credential.Kind)
	return nil
}

func loadOrCreateKEK(path string) (*kms.DevKEK, error) {
	if kek, err := kms.LoadDevKEK(path); err == nil {
		return kek, nil
	}
	kek, raw, err := kms.GenerateDevKEK()
	if err != nil {
		return nil, err
	}
	if err := kms.SaveDevKEKKey(path, raw); err != nil {
		return nil, err
	}
	kms.Zero(raw)
	fmt.Fprintf(os.Stderr, "created new dev KEK at %s\n", path)
	return kek, nil
}

func buildEnrollPolicy(policyPath, host, methods string) (policy.Policy, error) {
	if policyPath != "" {
		b, err := os.ReadFile(policyPath)
		if err != nil {
			return policy.Policy{}, err
		}
		var p policy.Policy
		if err := json.Unmarshal(b, &p); err != nil {
			return policy.Policy{}, fmt.Errorf("parse policy: %w", err)
		}
		return p, nil
	}
	if host == "" {
		return policy.Policy{}, errors.New("either -policy or -host is required")
	}
	var ms []string
	for _, m := range strings.Split(methods, ",") {
		if m = strings.TrimSpace(m); m != "" {
			ms = append(ms, strings.ToUpper(m))
		}
	}
	return policy.Policy{
		Credential: policy.Credential{
			Kind:   "static",
			Inject: policy.Inject{Type: "header", Name: "Authorization", Template: "Bearer {secret}"},
		},
		AllowHosts:   []string{host},
		AllowMethods: ms,
		Audit:        true,
	}, nil
}

func trimTrailingNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func newLogger(level string, w io.Writer) *slog.Logger {
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
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lvl}))
}
