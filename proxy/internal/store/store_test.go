// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/surybala/confidant/proxy/internal/kms"
	"github.com/surybala/confidant/proxy/internal/policy"
)

func TestMemStoreGet(t *testing.T) {
	m := NewMemStore()
	if _, err := m.Get("missing"); err != ErrNotFound {
		t.Errorf("Get(missing) err = %v, want ErrNotFound", err)
	}
	m.Put(&Record{ID: "openai/personal"})
	if _, err := m.Get("openai/personal"); err != nil {
		t.Errorf("Get existing: %v", err)
	}
}

func TestFileRoundTrip(t *testing.T) {
	kek, _, _ := kms.GenerateDevKEK()
	env, _ := kek.Seal([]byte("sk-secret"))
	pol := policy.Policy{
		Credential:   policy.Credential{Kind: "static", Inject: policy.Inject{Type: "header", Name: "Authorization", Template: "Bearer {secret}"}},
		AllowHosts:   []string{"api.openai.com"},
		AllowMethods: []string{"GET"},
	}
	m := NewMemStore()
	m.Put(&Record{ID: "openai/personal", Envelope: env, Policy: pol})

	path := filepath.Join(t.TempDir(), "store.json")
	if err := SaveFile(path, m); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := loaded.Get("openai/personal")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Policy.Credential.Kind != "static" || len(rec.Policy.AllowHosts) != 1 {
		t.Errorf("policy round trip wrong: %+v", rec.Policy)
	}
	// Envelope survives round trip and still decrypts.
	if _, err := kek.Unwrap(context.Background(), rec.Envelope); err != nil {
		t.Errorf("envelope did not survive round trip: %v", err)
	}
}
