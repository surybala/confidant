// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestIsLoopback(t *testing.T) {
	cases := []struct {
		listen string
		want   bool
	}{
		{"127.0.0.1:8317", true},
		{"127.5.5.5:80", true},
		{"localhost:8317", true},
		{"[::1]:8317", true},
		{"0.0.0.0:8317", false}, // I-A2: must refuse to bind this
		{"192.168.1.10:8317", false},
		{"10.0.0.1:443", false},
	}
	for _, c := range cases {
		got := Config{Listen: c.listen}.IsLoopback()
		if got != c.want {
			t.Errorf("IsLoopback(%q) = %v, want %v", c.listen, got, c.want)
		}
	}
}

func TestPermittedCADomains(t *testing.T) {
	c := Config{Intercept: []string{"api.openai.com", "*.amazonaws.com", "api.github.com", "*.amazonaws.com"}}
	got := c.PermittedCADomains()
	want := []string{"api.openai.com", "amazonaws.com", "api.github.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PermittedCADomains() = %v, want %v", got, want)
	}
}

func TestMatchHost(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"api.openai.com", "api.openai.com", true},
		{"api.openai.com", "API.OpenAI.com", true}, // case-insensitive
		{"api.openai.com", "evil.com", false},
		{"*.amazonaws.com", "s3.amazonaws.com", true},
		{"*.amazonaws.com", "amazonaws.com", false}, // bare apex not matched by *.
		{"*.amazonaws.com", "s3.amazonaws.com.evil.com", false},
	}
	for _, c := range cases {
		if got := MatchHost(c.pattern, c.host); got != c.want {
			t.Errorf("MatchHost(%q,%q) = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestIsIntercepted(t *testing.T) {
	c := Config{Intercept: []string{"api.openai.com", "*.amazonaws.com"}}
	if !c.IsIntercepted("api.openai.com") {
		t.Error("expected api.openai.com intercepted")
	}
	if !c.IsIntercepted("s3.amazonaws.com") {
		t.Error("expected s3.amazonaws.com intercepted")
	}
	if c.IsIntercepted("example.com") {
		t.Error("example.com should not be intercepted")
	}
}

func TestDetectForDefault(t *testing.T) {
	c := Default()
	r := c.DetectFor("api.openai.com")
	if r.Mode != ModeHeader || r.Name != "Authorization" || r.StripPrefix != "Bearer " {
		t.Errorf("default DetectFor = %+v, want header/Authorization/'Bearer '", r)
	}
}

func TestLoadJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	const doc = `{
		"listen": "127.0.0.1:9999",
		"broker_endpoint": "https://broker.ts.net:8443",
		"intercept": ["api.openai.com", "*.amazonaws.com"],
		"refs": {"cfdt:openai/personal": "openai/personal"},
		"detect": {"*.amazonaws.com": {"mode": "aws-sdk-dummy", "sentinel_access_key_id": "AKIACONFIDANTDEV", "ref": "cfdt:aws/dev"}}
	}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Listen != "127.0.0.1:9999" || c.BrokerEndpoint != "https://broker.ts.net:8443" {
		t.Errorf("scalar fields wrong: %+v", c)
	}
	if len(c.Intercept) != 2 || c.Refs["cfdt:openai/personal"] != "openai/personal" {
		t.Errorf("list/map fields wrong: %+v", c)
	}
	r := c.DetectFor("s3.amazonaws.com")
	if r.Mode != ModeAWSSDKDummy || r.SentinelAccessKeyID != "AKIACONFIDANTDEV" {
		t.Errorf("detect rule wrong: %+v", r)
	}
	// MaxBodyBytes defaulted since not in the file.
	if c.MaxBodyBytes != 16<<20 {
		t.Errorf("MaxBodyBytes default = %d", c.MaxBodyBytes)
	}
}

func TestValidate(t *testing.T) {
	ok := Config{Listen: "127.0.0.1:8317", BrokerEndpoint: "https://b.ts.net:8443", MaxBodyBytes: 1}
	if err := ok.Validate(); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
	bad := []Config{
		{Listen: "0.0.0.0:8317", BrokerEndpoint: "https://b", MaxBodyBytes: 1}, // not loopback
		{Listen: "127.0.0.1:8317", MaxBodyBytes: 1},                            // no broker
		{Listen: "127.0.0.1:8317", BrokerEndpoint: "https://b"},                // no body cap
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("bad config %d passed Validate", i)
		}
	}
}

func TestDetectForConfigured(t *testing.T) {
	c := Config{Detect: map[string]DetectRule{
		"*.amazonaws.com": {Mode: ModeAWSSDKDummy, SentinelAccessKeyID: "AKIACONFIDANTDEV", Ref: "cfdt:aws/dev"},
	}}
	r := c.DetectFor("s3.amazonaws.com")
	if r.Mode != ModeAWSSDKDummy || r.SentinelAccessKeyID != "AKIACONFIDANTDEV" {
		t.Errorf("configured DetectFor = %+v", r)
	}
}
