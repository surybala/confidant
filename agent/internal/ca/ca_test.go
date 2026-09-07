// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"path/filepath"
	"testing"
)

// TestNameConstraintsEnforced validates invariant I-A6: the local CA is
// name-constrained to the intercept domains and cannot mint a certificate a
// conforming verifier will accept for any other domain — even though it can
// technically sign one.
func TestNameConstraintsEnforced(t *testing.T) {
	authority, err := New([]string{"api.openai.com", "amazonaws.com"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(authority.CertPEM()) {
		t.Fatal("could not add CA to pool")
	}

	verify := func(host string) error {
		lc, err := authority.LeafFor(host) // signing always succeeds
		if err != nil {
			t.Fatalf("LeafFor(%q): %v", host, err)
		}
		_, err = lc.Leaf.Verify(x509.VerifyOptions{
			Roots:     roots,
			DNSName:   host,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		return err
	}

	// Permitted domains verify cleanly.
	if err := verify("api.openai.com"); err != nil {
		t.Errorf("api.openai.com should verify, got %v", err)
	}
	if err := verify("s3.amazonaws.com"); err != nil {
		t.Errorf("s3.amazonaws.com should verify (subdomain of amazonaws.com), got %v", err)
	}

	// Out-of-list domain must FAIL verification due to name constraints.
	if err := verify("evil.com"); err == nil {
		t.Error("evil.com verified against a name-constrained CA — I-A6 VIOLATED")
	}
}

// TestLoadOrCreateRoundTrip validates the CA persists and reloads with the same
// key, so a restarted agent keeps a trust store install valid.
func TestLoadOrCreateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")

	a, err := LoadOrCreate(certPath, keyPath, []string{"api.openai.com"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	b, err := LoadOrCreate(certPath, keyPath, []string{"api.openai.com"})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if string(a.CertPEM()) != string(b.CertPEM()) {
		t.Error("reloaded CA cert differs from persisted one")
	}
	// Reloaded CA can still sign a usable leaf.
	if _, err := b.LeafFor("api.openai.com"); err != nil {
		t.Errorf("reloaded CA failed to mint leaf: %v", err)
	}
}

func TestLeafCaching(t *testing.T) {
	authority, err := New([]string{"api.openai.com"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a, err := authority.LeafFor("api.openai.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := authority.LeafFor("api.openai.com")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Error("expected cached leaf to be reused")
	}
	if !authority.HasLeaf("api.openai.com") {
		t.Error("HasLeaf should report true after minting")
	}
	if authority.HasLeaf("never.minted") {
		t.Error("HasLeaf should be false for un-minted host")
	}
}
