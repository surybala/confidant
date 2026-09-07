// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

func TestSealUnwrapRoundTrip(t *testing.T) {
	kek, _, err := GenerateDevKEK()
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("sk-secret-value")
	env, err := kek.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(env.Ciphertext, plain) {
		t.Error("ciphertext contains plaintext")
	}
	got, err := kek.Unwrap(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("round trip = %q, want %q", got, plain)
	}
}

func TestUnwrapTamperFails(t *testing.T) {
	kek, _, _ := GenerateDevKEK()
	env, _ := kek.Seal([]byte("secret"))
	env.Ciphertext[0] ^= 0xff // tamper
	if _, err := kek.Unwrap(context.Background(), env); err == nil {
		t.Error("expected auth failure on tampered ciphertext")
	}
}

func TestUnwrapWrongAlg(t *testing.T) {
	kek, _, _ := GenerateDevKEK()
	env, _ := kek.Seal([]byte("secret"))
	env.Alg = "bogus"
	if _, err := kek.Unwrap(context.Background(), env); err == nil {
		t.Error("expected error for unknown alg")
	}
}

func TestKEKSaveLoad(t *testing.T) {
	kek, raw, _ := GenerateDevKEK()
	path := filepath.Join(t.TempDir(), "dev.kek")
	if err := SaveDevKEKKey(path, raw); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadDevKEK(path)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := kek.Seal([]byte("x"))
	if _, err := loaded.Unwrap(context.Background(), env); err != nil {
		t.Errorf("loaded KEK could not unwrap: %v", err)
	}
}

func TestNewDevKEKBadLength(t *testing.T) {
	if _, err := NewDevKEK([]byte("short")); err == nil {
		t.Error("expected error for non-32-byte key")
	}
}

func TestZero(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	Zero(b)
	for _, x := range b {
		if x != 0 {
			t.Fatal("Zero did not wipe buffer")
		}
	}
}
