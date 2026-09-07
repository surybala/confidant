// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/surybala/confidant/agent/internal/wire"
)

// TestPinnedMTLS validates invariant I-A9: the broker's server certificate is
// pinned by SPKI. A correct pin connects; a wrong pin aborts the connection.
func TestPinnedMTLS(t *testing.T) {
	var received wire.Request
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&received)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer ts.Close()

	goodPin := SPKIPin(ts.Certificate())

	t.Run("correct pin relays", func(t *testing.T) {
		c, err := New(Options{Endpoint: ts.URL, SPKIPin: goodPin})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Relay(context.Background(), wire.Request{Ref: "cfdt:openai/personal"})
		if err != nil {
			t.Fatalf("relay: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		if received.Ref != "cfdt:openai/personal" {
			t.Errorf("broker received ref %q", received.Ref)
		}
	})

	t.Run("wrong pin aborts", func(t *testing.T) {
		// A valid-format but non-matching pin (sha256 of 32 zero bytes).
		wrongPin := "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		c, err := New(Options{Endpoint: ts.URL, SPKIPin: wrongPin})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Relay(context.Background(), wire.Request{Ref: "cfdt:x"}); err == nil {
			t.Error("expected relay to fail on pin mismatch — I-A9 VIOLATED")
		}
	})
}

// TestRelayUnreachableFailsClosed validates that an unreachable broker surfaces
// as an error, which the proxy turns into a fail-closed response (I-A5/I-A12).
func TestRelayUnreachableFailsClosed(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	pin := SPKIPin(ts.Certificate())
	url := ts.URL
	ts.Close() // now unreachable

	c, err := New(Options{Endpoint: url, SPKIPin: pin})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Relay(context.Background(), wire.Request{Ref: "cfdt:x"}); err == nil {
		t.Error("expected error relaying to a closed broker")
	}
}
