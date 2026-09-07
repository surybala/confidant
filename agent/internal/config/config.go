// SPDX-License-Identifier: Apache-2.0

// Package config loads and validates agent configuration.
//
// IMPORTANT: agent config contains NO secrets (local-agent.md §3). It holds the
// broker endpoint, the agent's device-cert paths, the broker cert pin, the local
// CA paths, the intercept list, the inert ref allowlist, and per-host detection
// rules.
//
// The concrete on-disk format is JSON (stdlib, zero dependencies). The spec's
// TOML example is the intended ergonomic layer and a documented TODO; the shape
// is identical. Configuration may also be constructed programmatically, which is
// how the tests drive the agent.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// Detection modes for locating a credential ref in an outbound request.
const (
	ModeHeader      = "header"        // read a header value (default)
	ModeQuery       = "query"         // read a query parameter
	ModeAWSSDKDummy = "aws-sdk-dummy" // recognize a sentinel access-key-id in a SigV4 header
)

// DetectRule says how to find the ref for a given host pattern.
type DetectRule struct {
	Mode string `json:"mode"` // ModeHeader | ModeQuery | ModeAWSSDKDummy ("" => header)
	// Name is the header or query-parameter name (header/query modes).
	Name string `json:"name"`
	// StripPrefix is removed from the header value before parsing (e.g. "Bearer ").
	StripPrefix string `json:"strip_prefix"`
	// SentinelAccessKeyID is the dummy AWS access-key-id whose presence in the
	// SigV4 Authorization header identifies an aws-sdk-dummy request.
	SentinelAccessKeyID string `json:"sentinel_access_key_id"`
	// Ref is the cfdt: ref this AWS host maps to (aws-sdk-dummy mode only), since
	// the ref is not carried verbatim in the request as it is for header mode.
	Ref string `json:"ref"`
}

// Config is the agent's operating configuration. No secrets belong here.
type Config struct {
	Listen         string                `json:"listen"`           // loopback only
	BrokerEndpoint string                `json:"broker_endpoint"`  // tailnet MagicDNS https URL
	ClientCertPath string                `json:"client_cert_path"` // device identity (mTLS) cert
	ClientKeyPath  string                `json:"client_key_path"`  // device identity (mTLS) key
	ServerSPKIPin  string                `json:"server_spki_pin"`  // broker cert pin ("sha256/…")
	CACertPath     string                `json:"ca_cert_path"`     // local MITM CA cert
	CAKeyPath      string                `json:"ca_key_path"`      // local MITM CA key
	MaxBodyBytes   int64                 `json:"max_body_bytes"`
	Intercept      []string              `json:"intercept"` // host patterns to MITM + route
	Refs           map[string]string     `json:"refs"`      // inert ref allowlist: "cfdt:…" -> secret id
	Detect         map[string]DetectRule `json:"detect"`    // per-host-pattern detection rules
}

// Default returns documented defaults from local-agent.md §3.
func Default() Config {
	return Config{
		Listen:       "127.0.0.1:8317",
		MaxBodyBytes: 16 << 20, // 16 MiB
		Refs:         map[string]string{},
		Detect:       map[string]DetectRule{},
	}
}

// FromEnv layers a few scalar environment variables over the defaults. Lists and
// maps come from a config file (Load) or are set programmatically.
func FromEnv() Config {
	c := Default()
	c.Listen = env("CONFIDANT_LISTEN", c.Listen)
	c.BrokerEndpoint = env("CONFIDANT_BROKER", c.BrokerEndpoint)
	c.ClientCertPath = env("CONFIDANT_CLIENT_CERT", c.ClientCertPath)
	c.ClientKeyPath = env("CONFIDANT_CLIENT_KEY", c.ClientKeyPath)
	c.ServerSPKIPin = env("CONFIDANT_BROKER_SPKI_PIN", c.ServerSPKIPin)
	c.CACertPath = env("CONFIDANT_CA_CERT", c.CACertPath)
	c.CAKeyPath = env("CONFIDANT_CA_KEY", c.CAKeyPath)
	if v := os.Getenv("CONFIDANT_INTERCEPT"); v != "" {
		for _, h := range strings.Split(v, ",") {
			if h = strings.TrimSpace(h); h != "" {
				c.Intercept = append(c.Intercept, h)
			}
		}
	}
	return c
}

// Load reads a JSON config file and layers it over the defaults.
func Load(path string) (Config, error) {
	c := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("parse config: %w", err)
	}
	if c.Refs == nil {
		c.Refs = map[string]string{}
	}
	if c.Detect == nil {
		c.Detect = map[string]DetectRule{}
	}
	return c, nil
}

// Validate checks required fields for running (not for tests that inject a mock
// broker). It intentionally does not require secrets — there are none.
func (c Config) Validate() error {
	if !c.IsLoopback() {
		return fmt.Errorf("listen %q is not a loopback address", c.Listen)
	}
	if c.BrokerEndpoint == "" {
		return fmt.Errorf("broker_endpoint is required")
	}
	if c.MaxBodyBytes <= 0 {
		return fmt.Errorf("max_body_bytes must be positive")
	}
	return nil
}

// IsLoopback reports whether the listen address binds to loopback only.
// Enforces invariant I-A2 at startup.
func (c Config) IsLoopback() bool {
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		host = c.Listen
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// IsIntercepted reports whether host matches any configured intercept pattern.
func (c Config) IsIntercepted(host string) bool {
	for _, pat := range c.Intercept {
		if MatchHost(pat, host) {
			return true
		}
	}
	return false
}

// DetectFor returns the detection rule for host, defaulting to
// Authorization: Bearer header detection when none is configured.
func (c Config) DetectFor(host string) DetectRule {
	for pat, rule := range c.Detect {
		if MatchHost(pat, host) {
			if rule.Mode == "" {
				rule.Mode = ModeHeader
			}
			if rule.Mode == ModeHeader && rule.Name == "" {
				rule.Name = "Authorization"
			}
			return rule
		}
	}
	return DetectRule{Mode: ModeHeader, Name: "Authorization", StripPrefix: "Bearer "}
}

// PermittedCADomains derives the X.509 name-constraint domains for the local CA
// from the intercept list, so the CA cannot mint certs outside those domains
// (invariant I-A6). "*.amazonaws.com" -> "amazonaws.com"; "api.openai.com" stays.
func (c Config) PermittedCADomains() []string {
	seen := map[string]bool{}
	var out []string
	for _, pat := range c.Intercept {
		d := strings.TrimPrefix(pat, "*.")
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// MatchHost matches host against a pattern supporting a leading "*." wildcard.
func MatchHost(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".amazonaws.com"
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}
	return pattern == host
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
