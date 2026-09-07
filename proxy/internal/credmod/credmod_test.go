// SPDX-License-Identifier: Apache-2.0

package credmod

import (
	"net/http"
	"testing"

	"github.com/surybala/confidant/proxy/internal/policy"
)

func newReq(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", "https://api.example/v1/x?a=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestStaticHeaderInjection(t *testing.T) {
	req := newReq(t)
	cred := policy.Credential{Kind: "static", Inject: policy.Inject{Type: "header", Name: "Authorization", Template: "Bearer {secret}"}}
	scrub, err := Static{}.Apply(req, cred, []byte("SECRET"))
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer SECRET" {
		t.Errorf("header = %q", got)
	}
	if scrub != "Authorization" {
		t.Errorf("scrub header = %q, want Authorization", scrub)
	}
}

func TestStaticQueryInjection(t *testing.T) {
	req := newReq(t)
	cred := policy.Credential{Kind: "static", Inject: policy.Inject{Type: "query", Name: "api_key"}}
	scrub, err := Static{}.Apply(req, cred, []byte("SECRET"))
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.Query().Get("api_key") != "SECRET" {
		t.Errorf("query = %q", req.URL.RawQuery)
	}
	if scrub != "" {
		t.Errorf("query injection should have no response header to scrub, got %q", scrub)
	}
}

func TestStaticBasicInjection(t *testing.T) {
	req := newReq(t)
	cred := policy.Credential{Kind: "static", Inject: policy.Inject{Type: "basic"}}
	if _, err := (Static{}).Apply(req, cred, []byte("user:pass")); err != nil {
		t.Fatal(err)
	}
	// base64("user:pass") == dXNlcjpwYXNz
	if got := req.Header.Get("Authorization"); got != "Basic dXNlcjpwYXNz" {
		t.Errorf("basic header = %q", got)
	}
}

func TestRegistryDispatch(t *testing.T) {
	reg := Default()
	if _, ok := reg.Get("static"); !ok {
		t.Error("static module missing")
	}
	m, ok := reg.Get("sigv4")
	if !ok {
		t.Fatal("sigv4 should be registered")
	}
	if _, err := m.Apply(newReq(t), policy.Credential{Kind: "sigv4"}, []byte("x")); err != ErrNotImplemented {
		t.Errorf("sigv4 Apply err = %v, want ErrNotImplemented", err)
	}
	if _, ok := reg.Get("nope"); ok {
		t.Error("unknown kind should not resolve")
	}
}
