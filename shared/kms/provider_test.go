// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"
)

// fakeDecryptor stands in for a cloud KMS: it "wraps" a DEK by XORing with a
// fixed pad and reverses it on decrypt, so the round trip is exercised without
// any network. Deterministic and secret-free.
type fakeDecryptor struct {
	pad     byte
	calls   int
	failErr error
}

func (f *fakeDecryptor) Name() string { return "fake" }

func (f *fakeDecryptor) DecryptDEK(_ context.Context, wrapped []byte) ([]byte, error) {
	f.calls++
	if f.failErr != nil {
		return nil, f.failErr
	}
	dek := make([]byte, len(wrapped))
	for i, b := range wrapped {
		dek[i] = b ^ f.pad
	}
	return dek, nil
}

func (f *fakeDecryptor) wrap(_ context.Context, dek []byte) ([]byte, error) {
	wrapped := make([]byte, len(dek))
	for i, b := range dek {
		wrapped[i] = b ^ f.pad
	}
	return wrapped, nil
}

func TestSealKMSUnwrapRoundTrip(t *testing.T) {
	dec := &fakeDecryptor{pad: 0x5a}
	plain := []byte("sk-live-super-secret-value")
	aad := []byte("record=openai/personal")

	env, err := SealKMS(context.Background(), dec.wrap, plain, aad, "projects/p/locations/global/keyRings/r/cryptoKeys/k")
	if err != nil {
		t.Fatal(err)
	}
	if env.Alg != AlgKMSGCM {
		t.Errorf("alg = %q, want %q", env.Alg, AlgKMSGCM)
	}
	if len(env.WrappedDEK) == 0 {
		t.Fatal("wrapped DEK is empty")
	}
	if env.AADVersion != EnvelopeAADVersion {
		t.Errorf("AADVersion = %d, want %d", env.AADVersion, EnvelopeAADVersion)
	}
	if env.KMSKeyName == "" {
		t.Fatal("KMS key name is empty")
	}
	if bytes.Contains(env.Ciphertext, plain) {
		t.Error("ciphertext contains plaintext")
	}
	if bytes.Contains(env.WrappedDEK, plain) {
		t.Error("wrapped DEK contains plaintext")
	}

	u, err := NewEnvelopeUnwrapper(dec, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := u.Unwrap(context.Background(), env, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("round trip = %q, want %q", got, plain)
	}
	if dec.calls != 1 {
		t.Errorf("DecryptDEK calls = %d, want 1", dec.calls)
	}
}

func TestEnvelopeUnwrapperWrongAlg(t *testing.T) {
	u, _ := NewEnvelopeUnwrapper(&fakeDecryptor{}, nil)
	_, err := u.Unwrap(context.Background(), Envelope{Alg: AlgDevGCM, AADVersion: EnvelopeAADVersion, WrappedDEK: []byte("x")}, []byte("aad"))
	if err == nil {
		t.Fatal("expected error for non-KMS alg")
	}
}

func TestEnvelopeUnwrapperMissingWrappedDEK(t *testing.T) {
	u, _ := NewEnvelopeUnwrapper(&fakeDecryptor{}, nil)
	_, err := u.Unwrap(context.Background(), Envelope{Alg: AlgKMSGCM, AADVersion: EnvelopeAADVersion}, []byte("aad"))
	if err == nil {
		t.Fatal("expected error for missing wrapped DEK")
	}
}

func TestEnvelopeUnwrapperDecryptorFailsClosed(t *testing.T) {
	dec := &fakeDecryptor{pad: 0x11, failErr: errors.New("kms unavailable")}
	u, _ := NewEnvelopeUnwrapper(dec, nil)
	// A wrapped DEK is present, but the provider errors → Unwrap must fail closed.
	_, err := u.Unwrap(context.Background(), Envelope{Alg: AlgKMSGCM, AADVersion: EnvelopeAADVersion, WrappedDEK: []byte("wrapped"), Nonce: make([]byte, 12)}, []byte("aad"))
	if err == nil {
		t.Fatal("expected fail-closed error when provider errors")
	}
}

func TestEnvelopeUnwrapperTamperedCiphertext(t *testing.T) {
	dec := &fakeDecryptor{pad: 0x7e}
	env, err := SealKMS(context.Background(), dec.wrap, []byte("secret"), []byte("aad"), "projects/p/locations/global/keyRings/r/cryptoKeys/k")
	if err != nil {
		t.Fatal(err)
	}
	env.Ciphertext[0] ^= 0xff // tamper

	u, _ := NewEnvelopeUnwrapper(dec, nil)
	if _, err := u.Unwrap(context.Background(), env, []byte("aad")); err == nil {
		t.Fatal("expected GCM auth failure on tampered ciphertext")
	}
}

func TestEnvelopeUnwrapperTamperedAAD(t *testing.T) {
	dec := &fakeDecryptor{pad: 0x21}
	env, err := SealKMS(context.Background(), dec.wrap, []byte("secret"), []byte("original aad"), "projects/p/locations/global/keyRings/r/cryptoKeys/k")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := NewEnvelopeUnwrapper(dec, nil)
	if _, err := u.Unwrap(context.Background(), env, []byte("tampered aad")); err == nil {
		t.Fatal("expected GCM auth failure on tampered associated data")
	}
}

func TestSealKMSRequiresKeyName(t *testing.T) {
	dec := &fakeDecryptor{pad: 0x5a}
	if _, err := SealKMS(context.Background(), dec.wrap, []byte("secret"), []byte("aad"), ""); err == nil {
		t.Fatal("expected missing KMS key name error")
	}
}

func TestNewEnvelopeUnwrapperNilDecryptor(t *testing.T) {
	if _, err := NewEnvelopeUnwrapper(nil, nil); err == nil {
		t.Fatal("expected error for nil decryptor")
	}
}

// TestOpenGCMBadKey guards the AES-256 key-length requirement.
func TestOpenGCMBadKey(t *testing.T) {
	if _, err := openGCM([]byte("short"), make([]byte, 12), []byte("x"), []byte("aad")); err == nil {
		t.Fatal("expected error for short key")
	}
}

// sanity: the shared GCM helpers interoperate with a hand-rolled AEAD, i.e. the
// wire format is standard AES-256-GCM and not something bespoke.
func TestSealGCMIsStandardAEAD(t *testing.T) {
	key := make([]byte, dekSize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	aad := []byte("standard aad")
	nonce, ct, err := sealGCM(key, []byte("hello"), aad)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello" {
		t.Errorf("decrypt = %q", pt)
	}
}
