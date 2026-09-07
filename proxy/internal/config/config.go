// SPDX-License-Identifier: Apache-2.0

// Package config loads broker configuration.
//
// Two tiers (broker-core.md §3): security-relevant values must be attestation-bound
// in enclave mode, either by baking them into the image or by pinning explicit
// tee-env values in the WIF provider condition. Test/staging seams remain here for
// local development, but enclave validation rejects any setting that would redirect
// identity or KMS traffic away from Google.
//
// In the Phase-1 local build there is no Confidential Space or Cloud KMS: a local
// "dev KEK" file stands in for attestation-gated key release, and a JSON file
// stands in for the secret store. Those dev seams are configured here.
package config

import (
	"fmt"
	"net"
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

	// Enclave-mode KMS (broker-core.md §5). These select and parameterize the
	// attestation-gated unwrapper. In dev mode they are unused (DevKEK stands in).
	KMSProvider         string // KMS_PROVIDER (default "gcp")
	KMSKeyName          string // KMS_KEY — KEK resource name
	WIFAudience         string // WIF_AUDIENCE — STS audience (//iam.googleapis.com/…)
	AttestationAudience string // ATTESTATION_AUDIENCE — optional; derived from WIF_AUDIENCE if empty
	KMSServiceAccount   string // KMS_SERVICE_ACCOUNT — required SA to impersonate

	// GCP endpoint overrides (GCP_STS_ENDPOINT / GCP_KMS_ENDPOINT /
	// GCP_IAMCREDENTIALS_ENDPOINT). Empty uses the real Google endpoints; set only
	// for staging or tests. Enclave serve mode rejects these.
	GCPSTSEndpoint            string
	GCPKMSEndpoint            string
	GCPIAMCredentialsEndpoint string
}

// KMS provider identifiers.
const (
	KMSProviderGCP = "gcp"
)

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
		KMSProvider:          KMSProviderGCP,
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

	c.KMSProvider = strings.ToLower(env("KMS_PROVIDER", c.KMSProvider))
	c.KMSKeyName = env("KMS_KEY", c.KMSKeyName)
	c.WIFAudience = env("WIF_AUDIENCE", c.WIFAudience)
	c.AttestationAudience = env("ATTESTATION_AUDIENCE", c.AttestationAudience)
	c.KMSServiceAccount = env("KMS_SERVICE_ACCOUNT", c.KMSServiceAccount)
	c.GCPSTSEndpoint = env("GCP_STS_ENDPOINT", c.GCPSTSEndpoint)
	c.GCPKMSEndpoint = env("GCP_KMS_ENDPOINT", c.GCPKMSEndpoint)
	c.GCPIAMCredentialsEndpoint = env("GCP_IAMCREDENTIALS_ENDPOINT", c.GCPIAMCredentialsEndpoint)

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
			problems = append(problems, "CLIENT_CA is required (enrolled agent CA)")
		}
		if len(c.EgressAllow) == 0 {
			problems = append(problems, "EGRESS_ALLOW must be non-empty (default-deny egress)")
		}
		if c.StorePath == "" {
			problems = append(problems, "SECRET_STORE is required")
		}
		if c.DevKEKPath != "" {
			problems = append(problems, "DEV_KEK is forbidden in enclave mode (attestation-gated KMS only)")
		}
		problems = append(problems, c.validateNoGCPEndpointOverrides()...)
		problems = append(problems, c.validateKMS()...)
		if err := c.validateEnclaveListen(); err != nil {
			problems = append(problems, err.Error())
		}
		if len(problems) > 0 {
			return fmt.Errorf("enclave mode misconfigured: %s", strings.Join(problems, "; "))
		}
		return nil
	default:
		return fmt.Errorf("CONFIDANT_MODE must be %q or %q, got %q", ModeDev, ModeEnclave, c.Mode)
	}
}

// validateKMS checks the attestation-gated unwrapper configuration for the
// selected provider.
func (c Config) validateKMS() []string {
	var problems []string
	switch c.KMSProvider {
	case KMSProviderGCP, "":
		if c.KMSKeyName == "" {
			problems = append(problems, "KMS_KEY is required (KEK resource name)")
		} else if !isKMSKeyName(c.KMSKeyName) {
			problems = append(problems, "KMS_KEY must be a Cloud KMS cryptoKey resource name")
		}
		if c.WIFAudience == "" {
			problems = append(problems, "WIF_AUDIENCE is required (Workload Identity Federation provider)")
		} else if !isWIFAudience(c.WIFAudience) {
			problems = append(problems, "WIF_AUDIENCE must be a workload identity provider resource name")
		}
		if c.KMSServiceAccount == "" {
			problems = append(problems, "KMS_SERVICE_ACCOUNT is required (service-account impersonation keeps KMS IAM narrow)")
		} else if !isServiceAccountEmail(c.KMSServiceAccount) {
			problems = append(problems, "KMS_SERVICE_ACCOUNT must be a service account email")
		}
	default:
		problems = append(problems, fmt.Sprintf("unknown KMS_PROVIDER %q (supported: %q)", c.KMSProvider, KMSProviderGCP))
	}
	return problems
}

func (c Config) validateNoGCPEndpointOverrides() []string {
	var problems []string
	if c.GCPSTSEndpoint != "" {
		problems = append(problems, "GCP_STS_ENDPOINT is forbidden in enclave mode")
	}
	if c.GCPKMSEndpoint != "" {
		problems = append(problems, "GCP_KMS_ENDPOINT is forbidden in enclave mode")
	}
	if c.GCPIAMCredentialsEndpoint != "" {
		problems = append(problems, "GCP_IAMCREDENTIALS_ENDPOINT is forbidden in enclave mode")
	}
	return problems
}

func isServiceAccountEmail(v string) bool {
	local, domain, ok := strings.Cut(v, "@")
	return ok && local != "" && strings.HasSuffix(domain, ".iam.gserviceaccount.com")
}

func isKMSKeyName(v string) bool {
	return strings.HasPrefix(v, "projects/") &&
		strings.Contains(v, "/locations/") &&
		strings.Contains(v, "/keyRings/") &&
		strings.Contains(v, "/cryptoKeys/")
}

func isWIFAudience(v string) bool {
	return strings.HasPrefix(v, "//iam.googleapis.com/projects/") &&
		strings.Contains(v, "/locations/global/workloadIdentityPools/") &&
		strings.Contains(v, "/providers/")
}

// validateEnclaveListen rejects an obviously public bind. The broker must be
// reachable only over the tailnet (invariant I-B13); binding to a wildcard
// address (0.0.0.0 / ::) would expose it on every interface. We cannot fully
// verify the interface is the tailnet one, but we can refuse the clearly-wrong
// cases and leave a documented requirement for the operator to bind the tailnet IP.
func (c Config) validateEnclaveListen() error {
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("BROKER_LISTEN %q is not host:port", c.Listen)
	}
	switch host {
	case "", "0.0.0.0", "::":
		return fmt.Errorf("BROKER_LISTEN must bind the tailnet interface IP, not a wildcard address %q (I-B13: no public listener)", c.Listen)
	}
	return nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
