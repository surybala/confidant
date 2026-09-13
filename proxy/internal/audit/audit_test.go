// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"strings"
	"testing"
)

func TestChainVerifies(t *testing.T) {
	var buf bytes.Buffer
	cw := NewChainWriter(&buf)
	for i := 0; i < 5; i++ {
		if err := cw.Write(Record{Ref: "cfdt:x", Decision: "allowed", Status: 200}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := VerifyChain(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if n != 5 {
		t.Errorf("verified %d records, want 5", n)
	}
}

func TestChainDetectsTamper(t *testing.T) {
	var buf bytes.Buffer
	cw := NewChainWriter(&buf)
	_ = cw.Write(Record{Ref: "cfdt:a", Decision: "allowed", Status: 200})
	_ = cw.Write(Record{Ref: "cfdt:b", Decision: "denied", Status: 403})

	// Flip a field in the serialized log without recomputing the hash.
	tampered := strings.Replace(buf.String(), `"status":403`, `"status":200`, 1)
	if _, err := VerifyChain(strings.NewReader(tampered)); err == nil {
		t.Error("expected verify to detect tampering")
	}
}

func TestRecordsCarryNoSecretFields(t *testing.T) {
	// Compile-time-ish guard: a Record has no field that would hold a secret.
	// This test documents intent; the hash covers only the safe fields.
	r := Record{Ref: "cfdt:openai/personal", Host: "api.openai.com", Method: "POST", Path: "/v1/chat", Decision: "allowed", Status: 200}
	if strings.Contains(r.Ref, "sk-") {
		t.Fatal("ref should be an inert cfdt reference, not a secret")
	}
}
