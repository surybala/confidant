// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/surybala/confidant/agent/internal/ca"
	"github.com/surybala/confidant/agent/internal/config"
	"github.com/surybala/confidant/agent/internal/wire"
)

// --- mock broker ---

type mockBroker struct {
	mu      sync.Mutex
	calls   int
	lastReq wire.Request
	relay   func(wire.Request) (*http.Response, error)
}

func (m *mockBroker) Relay(_ context.Context, req wire.Request) (*http.Response, error) {
	m.mu.Lock()
	m.calls++
	m.lastReq = req
	f := m.relay
	m.mu.Unlock()
	if f != nil {
		return f(req)
	}
	return textResp(http.StatusOK, "brokered-ok"), nil
}

func (m *mockBroker) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func (m *mockBroker) last() wire.Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastReq
}

func textResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"text/plain"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

// --- harness ---

func newProxy(t *testing.T, cfg config.Config, b BrokerClient, logw io.Writer) (*httptest.Server, *ca.CA) {
	t.Helper()
	if logw == nil {
		logw = io.Discard
	}
	authority, err := ca.New(cfg.PermittedCADomains())
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}
	log := slog.New(slog.NewJSONHandler(logw, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := New(cfg, authority, b, log)
	ps := httptest.NewServer(h)
	t.Cleanup(ps.Close)
	return ps, authority
}

// proxyClient builds an HTTP client that routes through the agent proxy and
// trusts the given cert pool. Keep-alives are disabled so hijacked tunnels close
// promptly between requests.
func proxyClient(t *testing.T, proxyURL string, pool *x509.CertPool) *http.Client {
	t.Helper()
	pu, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(pu),
			TLSClientConfig:   &tls.Config{RootCAs: pool},
			DisableKeepAlives: true,
		},
	}
}

func caPool(t *testing.T, authority *ca.CA) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(authority.CertPEM()) {
		t.Fatal("append CA")
	}
	return pool
}

func happyConfig() config.Config {
	return config.Config{
		Intercept:    []string{"api.example.test"},
		Refs:         map[string]string{"cfdt:openai/personal": "openai/personal"},
		MaxBodyBytes: 16 << 20,
	}
}

// TestHappyPath validates the intercept → relay path: the agent forwards a ref
// (never a secret), never calls the upstream itself, and strips the credential
// (I-A1, I-A4, I-A7).
func TestHappyPath(t *testing.T) {
	mb := &mockBroker{}
	ps, authority := newProxy(t, happyConfig(), mb, nil)
	client := proxyClient(t, ps.URL, caPool(t, authority))

	req, _ := http.NewRequest("GET", "https://api.example.test/v1/chat", nil)
	req.Header.Set("Authorization", "Bearer cfdt:openai/personal#sk-live")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if string(body) != "brokered-ok" {
		t.Errorf("body = %q", body)
	}

	got := mb.last()
	if got.Ref != "cfdt:openai/personal" {
		t.Errorf("ref = %q", got.Ref)
	}
	if got.Upstream.Method != "GET" {
		t.Errorf("method = %q", got.Upstream.Method)
	}
	if got.Upstream.URL != "https://api.example.test/v1/chat" {
		t.Errorf("url = %q", got.Upstream.URL)
	}
	if _, present := got.Upstream.Headers["Authorization"]; present {
		t.Error("Authorization was forwarded to the broker — credential not stripped (I-A1)")
	}
	if mb.count() != 1 {
		t.Errorf("broker calls = %d, want 1", mb.count())
	}
}

// TestBlindTunnel validates that a non-intercepted host is tunnelled end-to-end
// without decryption: no leaf is minted and the broker is never called (I-A3).
func TestBlindTunnel(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello-direct")
	}))
	defer backend.Close()

	mb := &mockBroker{}
	ps, authority := newProxy(t, happyConfig(), mb, nil) // intercept only api.example.test

	pool := x509.NewCertPool()
	pool.AddCert(backend.Certificate())
	client := proxyClient(t, ps.URL, pool)

	resp, err := client.Get(backend.URL) // e.g. https://127.0.0.1:port
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello-direct" {
		t.Errorf("body = %q", body)
	}

	backendHost := mustHost(t, backend.URL)
	if authority.HasLeaf(backendHost) {
		t.Errorf("agent minted a leaf for a blind-tunnelled host %q (I-A3 VIOLATED)", backendHost)
	}
	if mb.count() != 0 {
		t.Errorf("broker was called for a blind-tunnelled host (calls=%d)", mb.count())
	}
}

// TestFailClosedBrokerUnreachable validates I-A5: an unreachable broker yields a
// fail-closed error to the tool, never a forwarded/upstream request.
func TestFailClosedBrokerUnreachable(t *testing.T) {
	mb := &mockBroker{relay: func(wire.Request) (*http.Response, error) {
		return nil, errors.New("broker down (tailnet unreachable)")
	}}
	ps, authority := newProxy(t, happyConfig(), mb, nil)
	client := proxyClient(t, ps.URL, caPool(t, authority))

	req, _ := http.NewRequest("GET", "https://api.example.test/v1/x", nil)
	req.Header.Set("Authorization", "Bearer cfdt:openai/personal")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	assertErrCode(t, resp, "broker_unreachable")
}

// TestNoRefRejected validates I-A8: an intercepted request with no cfdt: ref
// (e.g. a real key placed here by mistake) is rejected and forwarded nowhere.
func TestNoRefRejected(t *testing.T) {
	mb := &mockBroker{}
	ps, authority := newProxy(t, happyConfig(), mb, nil)
	client := proxyClient(t, ps.URL, caPool(t, authority))

	req, _ := http.NewRequest("GET", "https://api.example.test/v1/x", nil)
	req.Header.Set("Authorization", "Bearer sk-a-real-secret-key")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	assertErrCode(t, resp, "no_ref")
	if mb.count() != 0 {
		t.Errorf("broker was called despite no ref (calls=%d) — I-A8 VIOLATED", mb.count())
	}
}

// TestUnknownRefRejected validates that a cfdt: ref not in the allowlist is
// rejected before any relay.
func TestUnknownRefRejected(t *testing.T) {
	mb := &mockBroker{}
	ps, authority := newProxy(t, happyConfig(), mb, nil)
	client := proxyClient(t, ps.URL, caPool(t, authority))

	req, _ := http.NewRequest("GET", "https://api.example.test/v1/x", nil)
	req.Header.Set("Authorization", "Bearer cfdt:unknown/secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	assertErrCode(t, resp, "unknown_ref")
	if mb.count() != 0 {
		t.Errorf("broker called for unknown ref (calls=%d)", mb.count())
	}
}

// TestAWSSDKDummy validates the aws-sdk-dummy detection path: the bogus SigV4
// Authorization is stripped and the mapped ref is relayed (local-agent.md §6).
func TestAWSSDKDummy(t *testing.T) {
	cfg := config.Config{
		Intercept: []string{"s3.example.test"},
		Refs:      map[string]string{"cfdt:aws/dev": "aws/dev"},
		Detect: map[string]config.DetectRule{
			"s3.example.test": {Mode: config.ModeAWSSDKDummy, SentinelAccessKeyID: "AKIACONFIDANTDEV", Ref: "cfdt:aws/dev"},
		},
		MaxBodyBytes: 16 << 20,
	}
	mb := &mockBroker{}
	ps, authority := newProxy(t, cfg, mb, nil)
	client := proxyClient(t, ps.URL, caPool(t, authority))

	req, _ := http.NewRequest("PUT", "https://s3.example.test/bucket/key", strings.NewReader("payload"))
	req.Header.Set("Authorization",
		"AWS4-HMAC-SHA256 Credential=AKIACONFIDANTDEV/20260101/us-east-1/s3/aws4_request, "+
			"SignedHeaders=host, Signature=deadbeef")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	got := mb.last()
	if got.Ref != "cfdt:aws/dev" {
		t.Errorf("ref = %q", got.Ref)
	}
	if _, present := got.Upstream.Headers["Authorization"]; present {
		t.Error("bogus SigV4 Authorization was forwarded — not stripped")
	}
}

// TestLogHygiene validates I-A11: request bodies and ref hints never reach logs.
func TestLogHygiene(t *testing.T) {
	var logbuf bytes.Buffer
	mb := &mockBroker{}
	ps, authority := newProxy(t, happyConfig(), mb, &logbuf)
	client := proxyClient(t, ps.URL, caPool(t, authority))

	const secretBody = "PLAINTEXT-BODY-SHOULD-NOT-BE-LOGGED"
	const hint = "sk-supersecret-hint"
	req, _ := http.NewRequest("POST", "https://api.example.test/v1/chat", strings.NewReader(secretBody))
	req.Header.Set("Authorization", "Bearer cfdt:openai/personal#"+hint)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	logs := logbuf.String()
	if strings.Contains(logs, secretBody) {
		t.Error("request body appeared in logs (I-A11 VIOLATED)")
	}
	if strings.Contains(logs, hint) {
		t.Error("ref hint appeared in logs (I-A11 VIOLATED)")
	}
}

// TestConcurrentNoCrosstalk validates that many parallel requests are relayed
// independently, with responses matching their own request.
func TestConcurrentNoCrosstalk(t *testing.T) {
	mb := &mockBroker{relay: func(req wire.Request) (*http.Response, error) {
		return textResp(http.StatusOK, req.Upstream.Headers["X-Req-Id"]), nil
	}}
	ps, authority := newProxy(t, happyConfig(), mb, nil)
	pool := caPool(t, authority)

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			client := proxyClient(t, ps.URL, pool)
			id := "id-" + strconv.Itoa(i)
			req, _ := http.NewRequest("GET", "https://api.example.test/v1/x", nil)
			req.Header.Set("Authorization", "Bearer cfdt:openai/personal")
			req.Header.Set("X-Req-Id", id)
			resp, err := client.Do(req)
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if string(body) != id {
				errs <- errors.New("crosstalk: got " + string(body) + " want " + id)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// --- helpers ---

func assertErrCode(t *testing.T, resp *http.Response, wantCode string) {
	t.Helper()
	var eb wire.ErrorBody
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &eb); err != nil {
		t.Fatalf("decode error body %q: %v", body, err)
	}
	if eb.Code != wantCode {
		t.Errorf("error code = %q, want %q", eb.Code, wantCode)
	}
}

func mustHost(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname()
}
