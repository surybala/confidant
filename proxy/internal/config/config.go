// SPDX-License-Identifier: Apache-2.0

// Package config loads broker configuration.
//
// Two tiers (broker-core.md §3): security-relevant values (KMS key, expected WIF
// provider, credential-module set) are MEASURED — baked into the attested image —
// and are intentionally NOT overridable here. Only operational tunables live in
// this struct and come from the environment (with flag overrides in main).
//
// In the Phase-1 local build there is no Confidential Space or Cloud KMS: a local
// "dev KEK" file stands in for attestation-gated key release, and a JSON file
// stands in for the secret store. Those dev seams are configured here.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds operational (non-security) tunables plus the local dev seams.
type Config struct {
	Mode                 string        // CONFIDANT_MODE: "dev" | "enclave"
	Listen               string        // BROKER_LISTEN (tailnet-only in prod)
	StorePath            string        // SECRET_STORE (file:// JSON in dev)
	DevKEKPath           string        // DEV_KEK (local key file; stands in for KMS)
	EgressAllow          []string      // EGRESS_ALLOW (network allowlist, comma-separated)
	SecretCacheTTL       time.Duration // SECRET_CACHE_TTL (0 = no cache)
	MaxBodyBytes         int64         // MAX_BODY_BYTES
	UpstreamTimeout      time.Duration // UPSTREAM_TIMEOUT
	PerSecretConcurrency int           // PER_SECRET_CONCURRENCY
	LogLevel             string        // LOG_LEVEL (never "debug" in prod)
	AuditPath            string        // AUDIT_SINK (file path in dev)

	// mTLS (broker-core.md §4). In prod the listener is bound tailnet-only.
	TLSCertPath  string // TLS_CERT
	TLSKeyPath   string // TLS_KEY
	ClientCAPath string // CLIENT_CA (enrolled agent CA; enables RequireAndVerifyClientCert)

	// UpstreamCAPath adds a CA to the roots used when verifying real upstream
	// APIs (UPSTREAM_CA). Empty uses the system roots. Useful for private/test
	// upstreams; production may also pin per-policy.
	UpstreamCAPath string // UPSTREAM_CA
}

const (
	ModeDev     = "dev"
	ModeEnclave = "enclave"
)

// Default returns the documented defaults from broker-core.md §3.
func Default() Config {
	return Config{
		Mode:                 ModeDev,
		Listen:               ":8443",
		SecretCacheTTL:       0,
		MaxBodyBytes:         16 << 20, // 16 MiB
		UpstreamTimeout:      30 * time.Second,
		PerSecretConcurrency: 32,
		LogLevel:             "info",
		AuditPath:            "",
	}
}

// FromEnv layers environment variables over the defaults.
func FromEnv() (Config, error) {
	c := Default()
	c.Mode = strings.ToLower(env("CONFIDANT_MODE", c.Mode))
	c.Listen = env("BROKER_LISTEN", c.Listen)
	c.StorePath = env("SECRET_STORE", c.StorePath)
	c.DevKEKPath = env("DEV_KEK", c.DevKEKPath)
	c.LogLevel = env("LOG_LEVEL", c.LogLevel)
	c.AuditPath = env("AUDIT_SINK", c.AuditPath)
	c.TLSCertPath = env("TLS_CERT", c.TLSCertPath)
	c.TLSKeyPath = env("TLS_KEY", c.TLSKeyPath)
	c.ClientCAPath = env("CLIENT_CA", c.ClientCAPath)
	c.UpstreamCAPath = env("UPSTREAM_CA", c.UpstreamCAPath)

	if v := os.Getenv("EGRESS_ALLOW"); v != "" {
		for _, h := range strings.Split(v, ",") {
			if h = strings.TrimSpace(h); h != "" {
				c.EgressAllow = append(c.EgressAllow, h)
			}
		}
	}
	if v := os.Getenv("SECRET_CACHE_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return c, fmt.Errorf("SECRET_CACHE_TTL: %w", err)
		}
		c.SecretCacheTTL = d
	}
	if v := os.Getenv("UPSTREAM_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return c, fmt.Errorf("UPSTREAM_TIMEOUT: %w", err)
		}
		c.UpstreamTimeout = d
	}
	if v := os.Getenv("MAX_BODY_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return c, fmt.Errorf("MAX_BODY_BYTES: %w", err)
		}
		c.MaxBodyBytes = n
	}
	if v := os.Getenv("PER_SECRET_CONCURRENCY"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return c, fmt.Errorf("PER_SECRET_CONCURRENCY: %w", err)
		}
		c.PerSecretConcurrency = n
	}
	return c, nil
}

// ValidateForServe enforces the line between local dev and enclave production
// mode. Dev mode keeps the local KEK/file-store seams; enclave mode refuses to
// start until the production KMS/WIF unwrapper and tailnet-only listener exist.
func (c Config) ValidateForServe() error {
	mode := c.Mode
	if mode == "" {
		mode = ModeDev
	}
	switch mode {
	case ModeDev:
		if c.DevKEKPath == "" || c.StorePath == "" {
			return fmt.Errorf("DEV_KEK and SECRET_STORE are required in dev mode")
		}
		return nil
	case ModeEnclave:
		var problems []string
		if c.TLSCertPath == "" {
			problems = append(problems, "TLS_CERT is required")
		}
		if c.TLSKeyPath == "" {
			problems = append(problems, "TLS_KEY is required")
		}
		if c.ClientCAPath == "" {
			problems = append(problems, "CLIENT_CA is required")
		}
		if len(c.EgressAllow) == 0 {
			problems = append(problems, "EGRESS_ALLOW must be non-empty")
		}
		if c.DevKEKPath != "" {
			problems = append(problems, "DEV_KEK is forbidden")
		}
		problems = append(problems,
			"Cloud KMS/WIF unwrapper is not implemented",
			"tailnet-only tsnet listener is not implemented",
		)
		return fmt.Errorf("enclave mode is not runnable yet: %s", strings.Join(problems, "; "))
	default:
		return fmt.Errorf("CONFIDANT_MODE must be %q or %q, got %q", ModeDev, ModeEnclave, c.Mode)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
