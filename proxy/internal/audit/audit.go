// SPDX-License-Identifier: Apache-2.0

// Package audit records one entry per proxied request (allowed or denied) in a
// hash-chained, append-only log (broker-core.md §9 / invariant I-B10).
//
// Records never contain secret material, bodies, or auth header values
// (invariant I-B4). The hash chain lets a verifier detect tampering or gaps.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// Record is one audited request. Hash/PrevHash form the tamper-evident chain.
type Record struct {
	TS       int64  `json:"ts"`
	Ref      string `json:"ref"`
	Host     string `json:"host"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Decision string `json:"decision"` // "allowed" | "denied"
	Reason   string `json:"reason,omitempty"`
	Status   int    `json:"status"`
	BytesOut int    `json:"bytes_out"`
	Kind     string `json:"kind,omitempty"` // credential kind
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// Auditor writes audit records.
type Auditor interface {
	Write(r Record) error
}

// ChainWriter writes hash-chained JSON lines to an io.Writer.
type ChainWriter struct {
	mu   sync.Mutex
	w    io.Writer
	last string
}

// NewChainWriter creates a ChainWriter with an optional seed hash (genesis).
func NewChainWriter(w io.Writer) *ChainWriter {
	return &ChainWriter{w: w, last: "genesis"}
}

// Write links r into the chain and appends it as one JSON line.
func (c *ChainWriter) Write(r Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	r.PrevHash = c.last
	r.Hash = hashRecord(r)
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := c.w.Write(append(line, '\n')); err != nil {
		return err
	}
	c.last = r.Hash
	return nil
}

// hashRecord computes the chain hash over the record with Hash cleared.
func hashRecord(r Record) string {
	r.Hash = ""
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// VerifyChain reads JSON-line records and validates the hash chain, returning
// the number of records verified.
func VerifyChain(r io.Reader) (int, error) {
	dec := json.NewDecoder(r)
	prev := "genesis"
	n := 0
	for {
		var rec Record
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				return n, nil
			}
			return n, err
		}
		if rec.PrevHash != prev {
			return n, fmt.Errorf("record %d: prev_hash mismatch", n)
		}
		want := hashRecord(rec)
		if rec.Hash != want {
			return n, fmt.Errorf("record %d: hash mismatch", n)
		}
		prev = rec.Hash
		n++
	}
}

// MemAuditor captures records in memory (tests).
type MemAuditor struct {
	mu      sync.Mutex
	Records []Record
}

// Write implements Auditor.
func (m *MemAuditor) Write(r Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.TS = time.Now().Unix()
	m.Records = append(m.Records, r)
	return nil
}

// Snapshot returns a copy of captured records.
func (m *MemAuditor) Snapshot() []Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Record, len(m.Records))
	copy(out, m.Records)
	return out
}
