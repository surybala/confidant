// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/surybala/confidant/proxy/internal/audit"
	"github.com/surybala/confidant/proxy/internal/kms"
	"github.com/surybala/confidant/proxy/internal/policy"
	"github.com/surybala/confidant/proxy/internal/store"
	"github.com/surybala/confidant/proxy/internal/wire"
)

const testSecret = "sk-REAL-SECRET-VALUE"

func sealedRecord(t *testing.T, kek *kms.DevKEK, id string, pol policy.Policy) *store.Record {
	t.Helper()
	aad, err := store.EnvelopeAADFor(id, kms.AlgDevGCM, "", pol)
	if err != nil {
		t.Fatal(err)
	}
	env, err := kek.Seal([]byte(testSecret), aad)
	if err != nil {
		t.Fatal(err)
	}
	return &store.Record{ID: id, Envelope: env, Policy: pol}
}

func staticPolicy(hosts []string, methods []string) policy.Policy {
	return policy.Policy{
		Credential: policy.Credential{
			Kind:   "static",
			Inject: policy.Inject{Type: "header", Name: "Authorization", Template: "Bearer {secret}"},
		},
		AllowHosts:   hosts,
		AllowMethods: methods,
		Audit:        true,
	}
}

func doProxy(t *testing.T, h *Handler, wreq wire.Request) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(wreq)
	req := httptest.NewRequest(http.MethodPost, "/v1/proxy", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.Handle(rr, req)
	return rr
}

func hostOfT(t *testing.T, rawURL string) string {
	t.Helper()
	return hostOf(rawURL)
}

// TestHappyPathInjectsAndScrubs validates I-B1/I-B2/I-B3/I-B10: the real secret
// is injected into the upstream call, the response is scrubbed, and one allowed
// audit record is written.
func TestHappyPathInjectsAndScrubs(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Authorization", "reflected-should-be-scrubbed")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	defer upstream.Close()

	kek, _, _ := kms.GenerateDevKEK()
	host := hostOfT(t, upstream.URL)
	st := store.NewMemStore()
	st.Put(sealedRecord(t, kek, "openai/personal", staticPolicy([]string{host}, []string{"GET"})))

	aud := &audit.MemAuditor{}
	h := New(Deps{Store: st, Unwrapper: kek, Audit: aud, Egress: []string{host}, Upstream: upstream.Client()})

	rr := doProxy(t, h, wire.Request{
		Ref:      "cfdt:openai/personal",
		Upstream: wire.Upstream{Method: "GET", URL: upstream.URL, Headers: map[string]string{}},
	})

	if rr.Code != 200 {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if gotAuth != "Bearer "+testSecret {
		t.Errorf("upstream Authorization = %q, want injected secret", gotAuth)
	}
	if rr.Body.String() != "upstream-ok" {
		t.Errorf("body = %q", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), testSecret) {
		t.Error("secret leaked into response body (I-B3)")
	}
	if got := rr.Header().Get("Authorization"); got != "" {
		t.Errorf("Authorization not scrubbed from response: %q (I-B3)", got)
	}
	recs := aud.Snapshot()
	if len(recs) != 1 || recs[0].Decision != "allowed" {
		t.Errorf("audit = %+v, want 1 allowed", recs)
	}
}

// spyUnwrap records whether Unwrap was called.
type spyUnwrap struct {
	inner  kms.Unwrapper
	called int32
}

func (s *spyUnwrap) Unwrap(ctx context.Context, env kms.Envelope, aad []byte) ([]byte, error) {
	atomic.AddInt32(&s.called, 1)
	return s.inner.Unwrap(ctx, env, aad)
}

// TestAuthorizeBeforeUnwrap validates I-B5: a policy denial happens before any
// secret is unwrapped.
func TestAuthorizeBeforeUnwrap(t *testing.T) {
	kek, _, _ := kms.GenerateDevKEK()
	spy := &spyUnwrap{inner: kek}
	st := store.NewMemStore()
	// Policy only allows a different host than the request targets.
	st.Put(sealedRecord(t, kek, "openai/personal", staticPolicy([]string{"allowed.example"}, []string{"GET"})))

	aud := &audit.MemAuditor{}
	h := New(Deps{Store: st, Unwrapper: spy, Audit: aud})

	rr := doProxy(t, h, wire.Request{
		Ref:      "cfdt:openai/personal",
		Upstream: wire.Upstream{Method: "GET", URL: "https://denied.example/x"},
	})

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if atomic.LoadInt32(&spy.called) != 0 {
		t.Error("Unwrap was called on a denied request — I-B5 VIOLATED")
	}
	if recs := aud.Snapshot(); len(recs) != 1 || recs[0].Decision != "denied" {
		t.Errorf("expected 1 denied audit, got %+v", recs)
	}
}

func TestPolicyTamperFailsAtAuthenticatedUnwrap(t *testing.T) {
	var upstreamCalled int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&upstreamCalled, 1)
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	kek, _, _ := kms.GenerateDevKEK()
	host := hostOfT(t, upstream.URL)
	originalPolicy := staticPolicy([]string{"original-only.example"}, []string{"GET"})
	rec := sealedRecord(t, kek, "openai/personal", originalPolicy)
	// Simulate mutable-store tampering: broaden the readable policy after sealing.
	rec.Policy = staticPolicy([]string{host}, []string{"GET"})
	st := store.NewMemStore()
	st.Put(rec)

	aud := &audit.MemAuditor{}
	h := New(Deps{Store: st, Unwrapper: kek, Audit: aud, Egress: []string{host}, Upstream: upstream.Client()})
	rr := doProxy(t, h, wire.Request{
		Ref:      "cfdt:openai/personal",
		Upstream: wire.Upstream{Method: "GET", URL: upstream.URL},
	})

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	if atomic.LoadInt32(&upstreamCalled) != 0 {
		t.Fatal("upstream was called after policy tampering")
	}
	if recs := aud.Snapshot(); len(recs) != 1 || recs[0].Decision != "denied" {
		t.Errorf("expected 1 denied audit after tamper, got %+v", recs)
	}
}

func TestUnsafeUpstreamURLsRejectedBeforeUnwrap(t *testing.T) {
	kek, _, _ := kms.GenerateDevKEK()
	spy := &spyUnwrap{inner: kek}
	st := store.NewMemStore()
	st.Put(sealedRecord(t, kek, "openai/personal", staticPolicy([]string{"api.example"}, []string{"GET"})))
	h := New(Deps{Store: st, Unwrapper: spy, Egress: []string{"api.example"}})

	cases := []string{
		"http://api.example/v1/x",
		"https://user:pass@api.example/v1/x",
		"https://api.example/v1/x#token",
		"/relative/path",
	}
	for _, rawURL := range cases {
		t.Run(rawURL, func(t *testing.T) {
			rr := doProxy(t, h, wire.Request{
				Ref:      "cfdt:openai/personal",
				Upstream: wire.Upstream{Method: "GET", URL: rawURL},
			})
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
			}
			if atomic.LoadInt32(&spy.called) != 0 {
				t.Fatal("Unwrap was called for an unsafe upstream URL")
			}
		})
	}
}

func TestInvalidBodyRejectedBeforeUnwrap(t *testing.T) {
	kek, _, _ := kms.GenerateDevKEK()
	spy := &spyUnwrap{inner: kek}
	st := store.NewMemStore()
	st.Put(sealedRecord(t, kek, "openai/personal", staticPolicy([]string{"api.example"}, []string{"POST"})))
	h := New(Deps{Store: st, Unwrapper: spy, Egress: []string{"api.example"}})

	rr := doProxy(t, h, wire.Request{
		Ref:      "cfdt:openai/personal",
		Upstream: wire.Upstream{Method: "POST", URL: "https://api.example/v1/x", BodyB64: "%%%not-base64%%%"},
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if atomic.LoadInt32(&spy.called) != 0 {
		t.Fatal("Unwrap was called for an invalid body encoding")
	}
}

func TestOversizeBodyRejectedBeforeUnwrap(t *testing.T) {
	kek, _, _ := kms.GenerateDevKEK()
	spy := &spyUnwrap{inner: kek}
	st := store.NewMemStore()
	st.Put(sealedRecord(t, kek, "openai/personal", staticPolicy([]string{"api.example"}, []string{"POST"})))
	h := New(Deps{Store: st, Unwrapper: spy, Egress: []string{"api.example"}, MaxBody: 3})

	rr := doProxy(t, h, wire.Request{
		Ref: "cfdt:openai/personal",
		Upstream: wire.Upstream{
			Method:  "POST",
			URL:     "https://api.example/v1/x",
			BodyB64: base64.StdEncoding.EncodeToString([]byte("four")),
		},
	})
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", rr.Code, rr.Body.String())
	}
	if atomic.LoadInt32(&spy.called) != 0 {
		t.Fatal("Unwrap was called for an oversized body")
	}
}

// TestUnknownRef validates a missing secret id → 404.
func TestUnknownRef(t *testing.T) {
	kek, _, _ := kms.GenerateDevKEK()
	h := New(Deps{Store: store.NewMemStore(), Unwrapper: kek})
	rr := doProxy(t, h, wire.Request{Ref: "cfdt:nope", Upstream: wire.Upstream{Method: "GET", URL: "https://x.example/"}})
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

// errUnwrap always fails, simulating a KMS/attestation failure.
type errUnwrap struct{}

func (errUnwrap) Unwrap(context.Context, kms.Envelope, []byte) ([]byte, error) {
	return nil, context.DeadlineExceeded
}

// TestFailClosedOnUnwrapError validates I-B8: unwrap failure denies (503), never
// sends an unauthenticated upstream call.
func TestFailClosedOnUnwrapError(t *testing.T) {
	kek, _, _ := kms.GenerateDevKEK()
	st := store.NewMemStore()
	st.Put(sealedRecord(t, kek, "openai/personal", staticPolicy([]string{"x.example"}, []string{"GET"})))
	h := New(Deps{Store: st, Unwrapper: errUnwrap{}})
	rr := doProxy(t, h, wire.Request{
		Ref:      "cfdt:openai/personal",
		Upstream: wire.Upstream{Method: "GET", URL: "https://x.example/"},
	})
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

// TestEgressAllowlist validates I-B7: a host allowed by policy but absent from
// the network egress allowlist is denied.
func TestEgressAllowlist(t *testing.T) {
	kek, _, _ := kms.GenerateDevKEK()
	st := store.NewMemStore()
	st.Put(sealedRecord(t, kek, "openai/personal", staticPolicy([]string{"api.example"}, []string{"GET"})))
	// Egress allowlist does NOT include api.example.
	h := New(Deps{Store: st, Unwrapper: kek, Egress: []string{"other.example"}})
	rr := doProxy(t, h, wire.Request{
		Ref:      "cfdt:openai/personal",
		Upstream: wire.Upstream{Method: "GET", URL: "https://api.example/"},
	})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
}

// TestRateLimit validates the rpm cap → 429.
func TestRateLimit(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer upstream.Close()
	kek, _, _ := kms.GenerateDevKEK()
	host := hostOfT(t, upstream.URL)
	pol := staticPolicy([]string{host}, []string{"GET"})
	pol.Rate.RPM = 1
	st := store.NewMemStore()
	st.Put(sealedRecord(t, kek, "openai/personal", pol))
	h := New(Deps{Store: st, Unwrapper: kek, Egress: []string{host}, Upstream: upstream.Client()})

	req := wire.Request{Ref: "cfdt:openai/personal", Upstream: wire.Upstream{Method: "GET", URL: upstream.URL}}
	if rr := doProxy(t, h, req); rr.Code != 200 {
		t.Fatalf("first call status = %d, want 200", rr.Code)
	}
	if rr := doProxy(t, h, req); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second call status = %d, want 429", rr.Code)
	}
}

// TestUnsupportedCredentialFailsClosed validates that a not-yet-implemented
// credential kind (sigv4/oauth2) fails closed rather than sending unauth'd.
func TestUnsupportedCredentialFailsClosed(t *testing.T) {
	kek, _, _ := kms.GenerateDevKEK()
	spy := &spyUnwrap{inner: kek}
	pol := staticPolicy([]string{"x.example"}, []string{"GET"})
	pol.Credential.Kind = "sigv4"
	st := store.NewMemStore()
	st.Put(sealedRecord(t, kek, "aws/dev", pol))
	h := New(Deps{Store: st, Unwrapper: spy, Egress: []string{"x.example"}})
	rr := doProxy(t, h, wire.Request{Ref: "cfdt:aws/dev", Upstream: wire.Upstream{Method: "GET", URL: "https://x.example/"}})
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rr.Code)
	}
	if atomic.LoadInt32(&spy.called) != 0 {
		t.Fatal("Unwrap was called for an unimplemented credential module")
	}
}
