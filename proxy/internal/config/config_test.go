// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestValidateForServeDevRequiresLocalDevInputs(t *testing.T) {
	cfg := Default()
	if err := cfg.ValidateForServe(); err == nil {
		t.Fatal("dev mode without DEV_KEK and SECRET_STORE should fail")
	}

	cfg.DevKEKPath = "dev.kek"
	cfg.StorePath = "store.json"
	if err := cfg.ValidateForServe(); err != nil {
		t.Fatalf("dev mode with local inputs failed: %v", err)
	}
}

func TestValidateForServeRejectsUnknownMode(t *testing.T) {
	cfg := Default()
	cfg.Mode = "prod"
	cfg.DevKEKPath = "dev.kek"
	cfg.StorePath = "store.json"
	err := cfg.ValidateForServe()
	if err == nil || !strings.Contains(err.Error(), "CONFIDANT_MODE") {
		t.Fatalf("unknown mode error = %v, want CONFIDANT_MODE validation", err)
	}
}

// enclaveConfig returns a fully-configured, valid enclave config so individual
// tests can knock out one field at a time.
func enclaveConfig() Config {
	cfg := Default()
	cfg.Mode = ModeEnclave
	cfg.Listen = "100.100.0.1:8443" // tailnet IP (not a wildcard)
	cfg.StorePath = "store.json"
	cfg.TLSCertPath = "broker.crt"
	cfg.TLSKeyPath = "broker.key"
	cfg.ClientCAPath = "agent-ca.pem"
	cfg.EgressAllow = []string{"api.openai.com"}
	cfg.KMSKeyName = "projects/p/locations/global/keyRings/r/cryptoKeys/k"
	cfg.WIFAudience = "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool/providers/prov"
	cfg.KMSServiceAccount = "confidant-broker@p.iam.gserviceaccount.com"
	return cfg
}

func TestValidateForServeEnclaveHappyPath(t *testing.T) {
	if err := enclaveConfig().ValidateForServe(); err != nil {
		t.Fatalf("fully-configured enclave mode failed validation: %v", err)
	}
}

func TestValidateForServeEnclaveRejectsDevSeamsAndMissingGates(t *testing.T) {
	cfg := Default()
	cfg.Mode = ModeEnclave
	cfg.DevKEKPath = "dev.kek"
	cfg.StorePath = "store.json"

	err := cfg.ValidateForServe()
	if err == nil {
		t.Fatal("enclave mode should reject a dev-shaped config")
	}
	msg := err.Error()
	for _, want := range []string{
		"TLS_CERT is required",
		"TLS_KEY is required",
		"CLIENT_CA is required",
		"EGRESS_ALLOW must be non-empty",
		"DEV_KEK is forbidden",
		"KMS_KEY is required",
		"WIF_AUDIENCE is required",
		"KMS_SERVICE_ACCOUNT is required",
		"BROKER_LISTEN must bind the tailnet",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("enclave validation error %q missing %q", msg, want)
		}
	}
}

func TestValidateForServeEnclaveRejectsGCPEndpointOverrides(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{
			name: "sts",
			mut:  func(c *Config) { c.GCPSTSEndpoint = "http://127.0.0.1:8080/v1/token" },
			want: "GCP_STS_ENDPOINT is forbidden",
		},
		{
			name: "kms",
			mut:  func(c *Config) { c.GCPKMSEndpoint = "http://127.0.0.1:8081" },
			want: "GCP_KMS_ENDPOINT is forbidden",
		},
		{
			name: "iam",
			mut:  func(c *Config) { c.GCPIAMCredentialsEndpoint = "http://127.0.0.1:8082" },
			want: "GCP_IAMCREDENTIALS_ENDPOINT is forbidden",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := enclaveConfig()
			tc.mut(&cfg)
			err := cfg.ValidateForServe()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestValidateForServeEnclaveRequiresServiceAccountImpersonation(t *testing.T) {
	cfg := enclaveConfig()
	cfg.KMSServiceAccount = ""
	err := cfg.ValidateForServe()
	if err == nil || !strings.Contains(err.Error(), "KMS_SERVICE_ACCOUNT is required") {
		t.Fatalf("error = %v, want KMS_SERVICE_ACCOUNT requirement", err)
	}
}

func TestValidateForServeEnclaveRejectsMalformedServiceAccount(t *testing.T) {
	cfg := enclaveConfig()
	cfg.KMSServiceAccount = "not-a-service-account"
	err := cfg.ValidateForServe()
	if err == nil || !strings.Contains(err.Error(), "KMS_SERVICE_ACCOUNT must be a service account email") {
		t.Fatalf("error = %v, want service-account format error", err)
	}
}

func TestValidateForServeEnclaveRejectsMalformedKMSKey(t *testing.T) {
	cfg := enclaveConfig()
	cfg.KMSKeyName = "not-a-kms-key"
	err := cfg.ValidateForServe()
	if err == nil || !strings.Contains(err.Error(), "KMS_KEY must be a Cloud KMS cryptoKey resource name") {
		t.Fatalf("error = %v, want KMS key format error", err)
	}
}

func TestValidateForServeEnclaveRejectsMalformedWIFAudience(t *testing.T) {
	cfg := enclaveConfig()
	cfg.WIFAudience = "https://example.com/provider"
	err := cfg.ValidateForServe()
	if err == nil || !strings.Contains(err.Error(), "WIF_AUDIENCE must be a workload identity provider resource name") {
		t.Fatalf("error = %v, want WIF audience format error", err)
	}
}

func TestValidateForServeEnclaveRejectsWildcardListen(t *testing.T) {
	for _, listen := range []string{":8443", "0.0.0.0:8443", "[::]:8443"} {
		cfg := enclaveConfig()
		cfg.Listen = listen
		if err := cfg.ValidateForServe(); err == nil {
			t.Errorf("listen %q should be rejected as a public bind", listen)
		}
	}
}

func TestValidateForServeEnclaveRejectsUnknownKMSProvider(t *testing.T) {
	cfg := enclaveConfig()
	cfg.KMSProvider = "hashivault"
	err := cfg.ValidateForServe()
	if err == nil || !strings.Contains(err.Error(), "unknown KMS_PROVIDER") {
		t.Fatalf("error = %v, want unknown KMS_PROVIDER", err)
	}
}

func TestFromEnvParsesKMSConfig(t *testing.T) {
	t.Setenv("CONFIDANT_MODE", "enclave")
	t.Setenv("KMS_KEY", "projects/p/locations/global/keyRings/r/cryptoKeys/k")
	t.Setenv("WIF_AUDIENCE", "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool/providers/prov")
	t.Setenv("KMS_SERVICE_ACCOUNT", "broker@p.iam.gserviceaccount.com")

	cfg, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeEnclave {
		t.Errorf("mode = %q", cfg.Mode)
	}
	if cfg.KMSProvider != KMSProviderGCP {
		t.Errorf("default KMS provider = %q, want %q", cfg.KMSProvider, KMSProviderGCP)
	}
	if cfg.KMSKeyName == "" || cfg.WIFAudience == "" || cfg.KMSServiceAccount == "" {
		t.Errorf("KMS fields not parsed: %+v", cfg)
	}
}

func TestDefaultKeepsPlaintextCacheDisabled(t *testing.T) {
	if got := Default().SecretCacheTTL; got != 0 {
		t.Fatalf("SecretCacheTTL default = %s, want disabled until cache zeroization exists", got)
	}
}
