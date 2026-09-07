// SPDX-License-Identifier: Apache-2.0

// Package ca manages the agent's local MITM certificate authority.
//
// The CA is name-constrained to the intercept domains (invariant I-A6): even if
// its private key leaks, a conforming TLS client will reject a leaf it signs for
// any other domain. The CA mints (and caches) short-lived leaf certificates for
// intercepted hosts on demand.
//
// This key material is sensitive-ish but is NOT a routable secret to any API; it
// only lets the holder MITM the already-brokered hosts (whose secrets are not
// local). It is stored 0600 and, in production, ideally in the OS keychain.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	"crypto/tls"
)

// CA is a name-constrained local certificate authority with a leaf cache.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte // CA cert DER, for pooling/export

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// New generates a fresh name-constrained CA permitting only the given DNS
// domains. Pass the output of config.PermittedCADomains().
func New(permittedDomains []string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Confidant Local MITM CA", Organization: []string{"confidant-agent"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		// Name constraints: the whole point (I-A6). Critical so clients enforce.
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         permittedDomains,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	return &CA{cert: cert, key: key, der: der, leaves: map[string]*tls.Certificate{}}, nil
}

// LoadOrCreate loads a CA from certPath/keyPath, or creates and persists one if
// either file is missing. The permitted domains are only applied on creation.
func LoadOrCreate(certPath, keyPath string, permittedDomains []string) (*CA, error) {
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		return load(certPEM, keyPEM)
	}
	c, err := New(permittedDomains)
	if err != nil {
		return nil, err
	}
	if err := c.persist(certPath, keyPath); err != nil {
		return nil, err
	}
	return c, nil
}

func load(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid CA cert PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("invalid CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	return &CA{cert: cert, key: key, der: cb.Bytes, leaves: map[string]*tls.Certificate{}}, nil
}

func (c *CA) persist(certPath, keyPath string) error {
	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
	if err := os.WriteFile(certPath, certOut, 0o600); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(c.key)
	if err != nil {
		return err
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyOut, 0o600); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}
	return nil
}

// CertPEM returns the CA certificate in PEM form, for installing into a trust
// store or building a client RootCAs pool in tests.
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
}

// LeafFor returns a cached or freshly-minted leaf certificate for host, signed
// by the CA. Used as the MITM server certificate presented to the tool.
func (c *CA) LeafFor(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if lc, ok := c.leaves[host]; ok {
		return lc, nil
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().AddDate(0, 0, 90),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &leafKey.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf for %s: %w", host, err)
	}
	lc := &tls.Certificate{
		Certificate: [][]byte{der, c.der},
		PrivateKey:  leafKey,
		Leaf:        mustParse(der),
	}
	c.leaves[host] = lc
	return lc, nil
}

// HasLeaf reports whether a leaf for host has been minted. Test helper for
// asserting that blind-tunnelled hosts are never MITM'd (invariant I-A3).
func (c *CA) HasLeaf(host string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.leaves[host]
	return ok
}

func mustParse(der []byte) *x509.Certificate {
	crt, _ := x509.ParseCertificate(der)
	return crt
}

func randSerial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	return n, nil
}
