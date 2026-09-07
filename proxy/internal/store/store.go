// SPDX-License-Identifier: Apache-2.0

// Package store holds sealed secrets and their policies.
//
// Each record is a KMS-envelope-encrypted secret plus its spend policy. At rest
// the secret is only ciphertext (invariant: bucket compromise yields nothing
// usable). In the Phase-1 local build the store is a JSON file; in production it
// is GCS / Secret Manager behind the same interface.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/surybala/confidant/proxy/internal/kms"
	"github.com/surybala/confidant/proxy/internal/policy"
)

// ErrNotFound is returned when a secret id is unknown.
var ErrNotFound = fmt.Errorf("secret not found")

// Record is a stored secret: its id, sealed envelope, and spend policy.
type Record struct {
	ID       string        `json:"id"`
	Envelope kms.Envelope  `json:"envelope"`
	Policy   policy.Policy `json:"policy"`
}

// Store resolves a secret id to its record.
type Store interface {
	Get(id string) (*Record, error)
}

// MemStore is an in-memory store, used directly in tests and as the backing for
// FileStore.
type MemStore struct {
	mu   sync.RWMutex
	recs map[string]*Record
}

// NewMemStore creates an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{recs: map[string]*Record{}}
}

// Put adds or replaces a record.
func (m *MemStore) Put(r *Record) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recs[r.ID] = r
}

// Get implements Store.
func (m *MemStore) Get(id string) (*Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.recs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return r, nil
}

// All returns a snapshot of all records (for persistence).
func (m *MemStore) All() []*Record {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Record, 0, len(m.recs))
	for _, r := range m.recs {
		out = append(out, r)
	}
	return out
}

type fileDoc struct {
	Records []*Record `json:"records"`
}

// LoadFile reads a JSON store file into a MemStore.
func LoadFile(path string) (*MemStore, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read store: %w", err)
	}
	var doc fileDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse store: %w", err)
	}
	m := NewMemStore()
	for _, r := range doc.Records {
		m.Put(r)
	}
	return m, nil
}

// SaveFile writes a MemStore to a JSON file (0600 — it holds ciphertext only,
// but treat it as sensitive).
func SaveFile(path string, m *MemStore) error {
	doc := fileDoc{Records: m.All()}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
