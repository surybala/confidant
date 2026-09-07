// SPDX-License-Identifier: Apache-2.0

package refs

import (
	"net/http/httptest"
	"testing"

	"github.com/surybala/confidant/agent/internal/config"
)

func TestParseRef(t *testing.T) {
	cases := []struct {
		raw     string
		wantRef string
		wantOK  bool
	}{
		{"cfdt:openai/personal", "cfdt:openai/personal", true},
		{"cfdt:openai/personal#sk-live", "cfdt:openai/personal", true}, // hint stripped
		{"  cfdt:aws/dev  ", "cfdt:aws/dev", true},
		{"sk-realsecret", "", false}, // a real key is not a ref (I-A8)
		{"", "", false},
		{"cfdt:", "", false}, // no id
	}
	for _, c := range cases {
		ref, ok := ParseRef(c.raw)
		if ref != c.wantRef || ok != c.wantOK {
			t.Errorf("ParseRef(%q) = (%q,%v), want (%q,%v)", c.raw, ref, ok, c.wantRef, c.wantOK)
		}
		if c.wantOK && containsHint(ref) {
			t.Errorf("ParseRef(%q) leaked a hint: %q", c.raw, ref)
		}
	}
}

func TestDetectHeader(t *testing.T) {
	rule := config.DetectRule{Mode: config.ModeHeader, Name: "Authorization", StripPrefix: "Bearer "}

	req := httptest.NewRequest("GET", "https://api.openai.com/v1/x", nil)
	req.Header.Set("Authorization", "Bearer cfdt:openai/personal#sk-live")
	ref, ok := Detect(rule, req)
	if !ok || ref != "cfdt:openai/personal" {
		t.Fatalf("Detect header = (%q,%v)", ref, ok)
	}

	// A real key (no cfdt:) must be rejected — fail closed (I-A8).
	req2 := httptest.NewRequest("GET", "https://api.openai.com/v1/x", nil)
	req2.Header.Set("Authorization", "Bearer sk-realsecret")
	if _, ok := Detect(rule, req2); ok {
		t.Error("Detect accepted a non-ref value; must fail closed")
	}

	// No header at all.
	req3 := httptest.NewRequest("GET", "https://api.openai.com/v1/x", nil)
	if _, ok := Detect(rule, req3); ok {
		t.Error("Detect accepted a missing header")
	}
}

func TestDetectQuery(t *testing.T) {
	rule := config.DetectRule{Mode: config.ModeQuery, Name: "api_key"}
	req := httptest.NewRequest("GET", "https://legacy.example/v1?api_key=cfdt:legacy/key", nil)
	ref, ok := Detect(rule, req)
	if !ok || ref != "cfdt:legacy/key" {
		t.Fatalf("Detect query = (%q,%v)", ref, ok)
	}
}

func TestDetectAWSSDKDummy(t *testing.T) {
	rule := config.DetectRule{
		Mode:                config.ModeAWSSDKDummy,
		SentinelAccessKeyID: "AKIACONFIDANTDEV", // dummy AKID; must be slash-free
		Ref:                 "cfdt:aws/dev",
	}
	req := httptest.NewRequest("PUT", "https://s3.amazonaws.com/bucket/key", nil)
	req.Header.Set("Authorization",
		"AWS4-HMAC-SHA256 Credential=AKIACONFIDANTDEV/20260101/us-east-1/s3/aws4_request, "+
			"SignedHeaders=host;x-amz-date, Signature=deadbeef")
	ref, ok := Detect(rule, req)
	if !ok || ref != "cfdt:aws/dev" {
		t.Fatalf("Detect aws = (%q,%v)", ref, ok)
	}

	// Wrong sentinel -> not our request.
	req2 := httptest.NewRequest("PUT", "https://s3.amazonaws.com/bucket/key", nil)
	req2.Header.Set("Authorization",
		"AWS4-HMAC-SHA256 Credential=AKIAREAL/20260101/us-east-1/s3/aws4_request, Signature=x")
	if _, ok := Detect(rule, req2); ok {
		t.Error("Detect matched a non-sentinel access key id")
	}
}

func containsHint(ref string) bool {
	for i := 0; i < len(ref); i++ {
		if ref[i] == '#' {
			return true
		}
	}
	return false
}
