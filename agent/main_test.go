// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	"github.com/surybala/confidant/agent/internal/config"
	"github.com/surybala/confidant/agent/internal/wire"
)

// TestFailClosedBroker validates the no-broker wiring: relays error out so
// intercepted hosts fail closed (I-A5).
func TestFailClosedBroker(t *testing.T) {
	if _, err := (failClosedBroker{}).Relay(context.Background(), wire.Request{Ref: "cfdt:x"}); err == nil {
		t.Error("failClosedBroker.Relay must return an error")
	}
}

// TestBuildBrokerNoEndpoint validates that omitting a broker endpoint yields the
// fail-closed client rather than a nil or a permissive one.
func TestBuildBrokerNoEndpoint(t *testing.T) {
	log := newLogger("error")
	bc := buildBroker(config.Default(), log) // no endpoint
	if _, err := bc.Relay(context.Background(), wire.Request{Ref: "cfdt:x"}); err == nil {
		t.Error("expected fail-closed broker when no endpoint is configured")
	}
}

// TestBuildBrokerWithEndpoint validates a real client is constructed when an
// endpoint is present.
func TestBuildBrokerWithEndpoint(t *testing.T) {
	log := newLogger("error")
	cfg := config.Default()
	cfg.BrokerEndpoint = "https://broker.example.ts.net:8443"
	cfg.ServerSPKIPin = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	bc := buildBroker(cfg, log)
	if _, ok := bc.(failClosedBroker); ok {
		t.Error("expected a real broker client, got fail-closed")
	}
}

// TestBuildCAEphemeral validates the ephemeral CA path (no cert/key paths set).
func TestBuildCAEphemeral(t *testing.T) {
	log := newLogger("error")
	cfg := config.Config{Intercept: []string{"api.openai.com"}}
	authority, err := buildCA(cfg, log)
	if err != nil {
		t.Fatalf("buildCA: %v", err)
	}
	if _, err := authority.LeafFor("api.openai.com"); err != nil {
		t.Errorf("ephemeral CA failed to mint leaf: %v", err)
	}
}

func TestNewLoggerLevels(t *testing.T) {
	for _, lvl := range []string{"debug", "info", "warn", "error", "bogus"} {
		if newLogger(lvl) == nil {
			t.Errorf("newLogger(%q) returned nil", lvl)
		}
	}
}
