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

func TestValidateForServeEnclaveFailsClosedUntilProductionGatesExist(t *testing.T) {
	cfg := Default()
	cfg.Mode = ModeEnclave
	cfg.DevKEKPath = "dev.kek"
	cfg.StorePath = "store.json"

	err := cfg.ValidateForServe()
	if err == nil {
		t.Fatal("enclave mode should not run with dev-only implementation")
	}
	msg := err.Error()
	for _, want := range []string{
		"TLS_CERT is required",
		"TLS_KEY is required",
		"CLIENT_CA is required",
		"EGRESS_ALLOW must be non-empty",
		"DEV_KEK is forbidden",
		"Cloud KMS/WIF unwrapper is not implemented",
		"tailnet-only tsnet listener is not implemented",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("enclave validation error %q missing %q", msg, want)
		}
	}
}

func TestDefaultKeepsPlaintextCacheDisabled(t *testing.T) {
	if got := Default().SecretCacheTTL; got != 0 {
		t.Fatalf("SecretCacheTTL default = %s, want disabled until cache zeroization exists", got)
	}
}
