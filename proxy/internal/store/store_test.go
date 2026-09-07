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
	pol := policy.Policy{
		Credential:   policy.Credential{Kind: "static", Inject: policy.Inject{Type: "header", Name: "Authorization", Template: "Bearer {secret}"}},
		AllowHosts:   []string{"api.openai.com"},
		AllowMethods: []string{"GET"},
	}
	aad, err := EnvelopeAADFor("openai/personal", kms.AlgDevGCM, "", pol)
	if err != nil {
		t.Fatal(err)
	}
	env, err := kek.Seal([]byte("sk-secret"), aad)
	if err != nil {
		t.Fatal(err)
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
	gotAAD, err := EnvelopeAAD("openai/personal", rec.Envelope, rec.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kek.Unwrap(context.Background(), rec.Envelope, gotAAD); err != nil {
		t.Errorf("envelope did not survive round trip: %v", err)
	}
}

func TestEnvelopeAADBindsRecordPolicyAndKey(t *testing.T) {
	pol := policy.Policy{
		Credential:   policy.Credential{Kind: "static", Inject: policy.Inject{Type: "header", Name: "Authorization"}},
		AllowHosts:   []string{"api.openai.com"},
		AllowMethods: []string{"GET"},
	}
	base, err := EnvelopeAADFor("openai/personal", kms.AlgKMSGCM, "projects/p/locations/global/keyRings/r/cryptoKeys/k", pol)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		id  string
		alg string
		key string
		pol policy.Policy
	}{
		"id":     {id: "openai/other", alg: kms.AlgKMSGCM, key: "projects/p/locations/global/keyRings/r/cryptoKeys/k", pol: pol},
		"alg":    {id: "openai/personal", alg: kms.AlgDevGCM, key: "projects/p/locations/global/keyRings/r/cryptoKeys/k", pol: pol},
		"kmsKey": {id: "openai/personal", alg: kms.AlgKMSGCM, key: "projects/p/locations/global/keyRings/r/cryptoKeys/other", pol: pol},
		"policy": {
			id:  "openai/personal",
			alg: kms.AlgKMSGCM,
			key: "projects/p/locations/global/keyRings/r/cryptoKeys/k",
			pol: policy.Policy{
				Credential:   pol.Credential,
				AllowHosts:   []string{"evil.example"},
				AllowMethods: pol.AllowMethods,
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := EnvelopeAADFor(tc.id, tc.alg, tc.key, tc.pol)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) == string(base) {
				t.Fatalf("AAD did not change when %s changed", name)
			}
		})
	}
}
