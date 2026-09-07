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
//
// Two shapes share this struct:
//
//   - Dev seam (Alg == AlgDevGCM): the secret is sealed directly under the local
//     dev KEK; WrappedDEK is empty.
//   - Enclave/KMS (Alg == AlgKMSGCM): the secret is sealed under a per-secret data
//     encryption key (DEK); that DEK is itself wrapped by a cloud KMS key-encryption
//     key (KEK) and stored in WrappedDEK. At rest the DEK is only recoverable by a
//     workload the KMS releases it to (attestation-gated), so a stolen store is inert.
type Envelope struct {
	Alg        string `json:"alg"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
	// AADVersion identifies the associated-data schema used when sealing.
	// Version 1 binds the envelope to its store record id, policy, alg, and KMS key.
	AADVersion int `json:"aad_version"`
	// KMSKeyName is the KEK resource used to wrap the DEK. Present only for AlgKMSGCM.
	KMSKeyName string `json:"kms_key,omitempty"`
	// WrappedDEK is the KMS-wrapped data encryption key. Present only for AlgKMSGCM.
	WrappedDEK []byte `json:"wrapped_dek,omitempty"`
}

// AlgDevGCM marks the local-development envelope shape. It is exported so the
// store can build the same associated data before enrollment has an Envelope.
const AlgDevGCM = "AES-256-GCM-DEV"

// AlgKMSGCM marks an envelope-encrypted secret: a per-secret DEK seals the secret
// with AES-256-GCM, and the DEK is wrapped by a cloud KMS KEK (see kms/gcp).
const AlgKMSGCM = "KMS+AES-256-GCM"

// EnvelopeAADVersion is the only accepted associated-data schema for new stores.
const EnvelopeAADVersion = 1

// dekSize is the byte length of a data encryption key (AES-256).
const dekSize = 32

// Unwrapper decrypts an Envelope, returning the plaintext secret. Callers MUST
// zeroize the returned bytes after use.
type Unwrapper interface {
	Unwrap(ctx context.Context, env Envelope, aad []byte) ([]byte, error)
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

// Seal encrypts plaintext into an Envelope. Enrollment-time helper. The aad must
// be the canonical store-associated data for this record.
func (k *DevKEK) Seal(plaintext, aad []byte) (Envelope, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, err
	}
	ct := k.aead.Seal(nil, nonce, plaintext, aad)
	return Envelope{Alg: AlgDevGCM, Nonce: nonce, Ciphertext: ct, AADVersion: EnvelopeAADVersion}, nil
}

// Unwrap decrypts an Envelope. Implements Unwrapper.
func (k *DevKEK) Unwrap(_ context.Context, env Envelope, aad []byte) ([]byte, error) {
	if env.Alg != AlgDevGCM {
		return nil, fmt.Errorf("unsupported envelope alg %q", env.Alg)
	}
	if err := requireAADVersion(env); err != nil {
		return nil, err
	}
	if len(env.Nonce) != k.aead.NonceSize() {
		return nil, fmt.Errorf("bad nonce length")
	}
	pt, err := k.aead.Open(nil, env.Nonce, env.Ciphertext, aad)
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

// WrapFunc wraps (encrypts) a DEK with a cloud KMS KEK and returns the wrapped
// bytes. It is the seam a provider (kms/gcp) supplies at enrollment time.
type WrapFunc func(ctx context.Context, dek []byte) (wrapped []byte, err error)

// SealKMS produces an AlgKMSGCM envelope: it mints a fresh 32-byte DEK, seals the
// plaintext under it with AES-256-GCM, then wraps the DEK via wrap (a cloud KMS
// KEK). The DEK is zeroized before returning; only its wrapped form persists.
//
// This is the enrollment-time counterpart to EnvelopeUnwrapper.Unwrap, and is
// provider-agnostic: any KeyDecryptor whose provider can also wrap works here.
func SealKMS(ctx context.Context, wrap WrapFunc, plaintext, aad []byte, kmsKeyName string) (Envelope, error) {
	if kmsKeyName == "" {
		return Envelope{}, fmt.Errorf("KMS key name is required")
	}
	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return Envelope{}, fmt.Errorf("generate DEK: %w", err)
	}
	defer Zero(dek)

	nonce, ct, err := sealGCM(dek, plaintext, aad)
	if err != nil {
		return Envelope{}, err
	}
	wrapped, err := wrap(ctx, dek)
	if err != nil {
		return Envelope{}, fmt.Errorf("wrap DEK: %w", err)
	}
	if len(wrapped) == 0 {
		return Envelope{}, fmt.Errorf("wrap DEK: empty wrapped key")
	}
	return Envelope{
		Alg:        AlgKMSGCM,
		Nonce:      nonce,
		Ciphertext: ct,
		AADVersion: EnvelopeAADVersion,
		KMSKeyName: kmsKeyName,
		WrappedDEK: wrapped,
	}, nil
}

// sealGCM encrypts plaintext under a 32-byte key with AES-256-GCM, returning the
// random nonce and ciphertext.
func sealGCM(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

// openGCM decrypts ciphertext under a 32-byte key with AES-256-GCM.
func openGCM(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("bad nonce length")
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

func requireAADVersion(env Envelope) error {
	if env.AADVersion != EnvelopeAADVersion {
		return fmt.Errorf("unsupported envelope AAD version %d", env.AADVersion)
	}
	return nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != dekSize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", dekSize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
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
