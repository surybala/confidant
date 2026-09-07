// SPDX-License-Identifier: Apache-2.0

// Package kms abstracts secret unwrapping.
//
// In production this is Cloud KMS with attestation-gated release: the enclave
// presents its Confidential Space attestation token, KMS decrypts the wrapped
// DEK, and the DEK decrypts the secret. In the Phase-1 local build a "dev KEK" —
// a 32-byte AES key on disk — stands in for that whole chain, so the pipeline can
// run and be tested without GCP. The Unwrapper interface is the seam that swaps
// one for the other (invariant I-B6 lives behind it).
package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

// Envelope is a sealed secret. JSON-marshals byte slices as base64.
type Envelope struct {
	Alg        string `json:"alg"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

const algDevGCM = "AES-256-GCM-DEV"

// Unwrapper decrypts an Envelope, returning the plaintext secret. Callers MUST
// zeroize the returned bytes after use.
type Unwrapper interface {
	Unwrap(ctx context.Context, env Envelope) ([]byte, error)
}

// DevKEK is a local symmetric key standing in for KMS + attestation.
type DevKEK struct {
	aead cipher.AEAD
}

// NewDevKEK builds a dev KEK from a 32-byte key.
func NewDevKEK(key []byte) (*DevKEK, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("dev KEK must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &DevKEK{aead: aead}, nil
}

// GenerateDevKEK returns a new dev KEK and its raw 32-byte key.
func GenerateDevKEK() (*DevKEK, []byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, err
	}
	k, err := NewDevKEK(key)
	if err != nil {
		return nil, nil, err
	}
	return k, key, nil
}

// LoadDevKEK reads a base64-encoded 32-byte key from path.
func LoadDevKEK(path string) (*DevKEK, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read dev KEK: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(trimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("decode dev KEK: %w", err)
	}
	return NewDevKEK(key)
}

// SaveDevKEKKey writes a raw key to path as base64 (0600).
func SaveDevKEKKey(path string, key []byte) error {
	enc := base64.StdEncoding.EncodeToString(key)
	return os.WriteFile(path, []byte(enc+"\n"), 0o600)
}

// Seal encrypts plaintext into an Envelope. Enrollment-time helper.
func (k *DevKEK) Seal(plaintext []byte) (Envelope, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, err
	}
	ct := k.aead.Seal(nil, nonce, plaintext, nil)
	return Envelope{Alg: algDevGCM, Nonce: nonce, Ciphertext: ct}, nil
}

// Unwrap decrypts an Envelope. Implements Unwrapper.
func (k *DevKEK) Unwrap(_ context.Context, env Envelope) ([]byte, error) {
	if env.Alg != algDevGCM {
		return nil, fmt.Errorf("unsupported envelope alg %q", env.Alg)
	}
	if len(env.Nonce) != k.aead.NonceSize() {
		return nil, fmt.Errorf("bad nonce length")
	}
	pt, err := k.aead.Open(nil, env.Nonce, env.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("unwrap: %w", err)
	}
	return pt, nil
}

// Zero best-effort wipes a secret buffer. Go strings can't be wiped, so callers
// should keep secrets in []byte and Zero them promptly after use.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func trimSpace(s string) string {
	// avoid importing strings for one call in this small package
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\n' || s[start] == '\r' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\n' || s[end-1] == '\r' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
