// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// realSecret is the value that must NEVER appear on the tool side or in logs —
// it lives only inside the broker (sealed) and is injected into the upstream.
const realSecret = "sk-REAL-E2E-SECRET-do-not-leak"

// TestEndToEnd wires the real confidant-agent and confidant-proxy binaries plus a
// mock upstream, then drives a tool through the agent. It proves the core thesis:
// the tool holds only a ref, the broker injects the real secret, the upstream
// receives it, and it never leaks back to the tool or into the audit log.
func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e builds binaries; skipped in -short")
	}
	tmp := t.TempDir()

	// 1. Build both binaries.
	proxyBin := filepath.Join(tmp, "confidant-proxy")
	agentBin := filepath.Join(tmp, "confidant-agent")
	buildBinary(t, absDir(t, "../proxy"), proxyBin)
	buildBinary(t, absDir(t, "../agent"), agentBin)

	// 2. Certs: one test CA signs the broker server cert, the agent client cert,
	// and the mock upstream cert.
	ca := newTestCA(t)
	caPath := writeFile(t, tmp, "ca.pem", ca.certPEM)

	brokerCrt, brokerKey, brokerLeaf := ca.issue(t, "confidant-broker", []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, true)
	brokerCrtPath := writeFile(t, tmp, "broker.crt", brokerCrt)
	brokerKeyPath := writeFile(t, tmp, "broker.key", brokerKey)
	brokerPin := spkiPin(brokerLeaf)

	agentCrt, agentKey, _ := ca.issue(t, "confidant-agent-device", nil, nil, false)
	agentCrtPath := writeFile(t, tmp, "agent-client.crt", agentCrt)
	agentKeyPath := writeFile(t, tmp, "agent-client.key", agentKey)

	mockCrt, mockKey, _ := ca.issue(t, "localhost", []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, true)

	// 3. Enroll the secret into the store with a policy (via the real binary).
	storePath := filepath.Join(tmp, "store.json")
	kekPath := filepath.Join(tmp, "dev.kek")
	enroll := exec.Command(proxyBin, "enroll",
		"-id", "openai/personal", "-kek", kekPath, "-store", storePath,
		"-host", "localhost", "-methods", "GET,POST")
	enroll.Stdin = strings.NewReader(realSecret)
	if out, err := enroll.CombinedOutput(); err != nil {
		t.Fatalf("enroll: %v\n%s", err, out)
	}

	// 4. Mock upstream: TLS server that records the injected Authorization.
	var upstreamCalls int32
	var lastAuth atomic.Value
	lastAuth.Store("")
	mockPort := startMockUpstream(t, mockCrt, mockKey, &upstreamCalls, &lastAuth)

	// 5. Start the broker.
	brokerPort := freePort(t)
	auditPath := filepath.Join(tmp, "audit.log")
	brokerEnv := []string{
		"SECRET_STORE=" + storePath,
		"DEV_KEK=" + kekPath,
		"TLS_CERT=" + brokerCrtPath,
		"TLS_KEY=" + brokerKeyPath,
		"CLIENT_CA=" + caPath,
		"UPSTREAM_CA=" + caPath,
		"EGRESS_ALLOW=localhost",
		"AUDIT_SINK=" + auditPath,
	}
	startProcess(t, proxyBin, []string{"serve", "-listen", fmt.Sprintf("127.0.0.1:%d", brokerPort), "-log-level", "warn"}, brokerEnv, "broker")
	waitForPort(t, fmt.Sprintf("127.0.0.1:%d", brokerPort), 10*time.Second)

	// 6. Start the agent.
	agentPort := freePort(t)
	agentMITMCert := filepath.Join(tmp, "agent-mitm.crt")
	agentCfg := fmt.Sprintf(`{
	  "listen": "127.0.0.1:%d",
	  "broker_endpoint": "https://127.0.0.1:%d",
	  "client_cert_path": %q,
	  "client_key_path": %q,
	  "server_spki_pin": %q,
	  "ca_cert_path": %q,
	  "ca_key_path": %q,
	  "max_body_bytes": 1048576,
	  "intercept": ["localhost"],
	  "refs": {"cfdt:openai/personal": "openai/personal"}
	}`, agentPort, brokerPort, agentCrtPath, agentKeyPath, brokerPin, agentMITMCert, filepath.Join(tmp, "agent-mitm.key"))
	agentCfgPath := writeFile(t, tmp, "agent.json", []byte(agentCfg))
	startProcess(t, agentBin, []string{"-config", agentCfgPath, "-log-level", "warn"}, nil, "agent")
	waitForPort(t, fmt.Sprintf("127.0.0.1:%d", agentPort), 10*time.Second)

	// The agent mints its MITM CA at startup; the tool must trust it.
	mitmPEM := readWhenReady(t, agentMITMCert, 5*time.Second)
	toolPool := x509.NewCertPool()
	if !toolPool.AppendCertsFromPEM(mitmPEM) {
		t.Fatal("could not load agent MITM CA")
	}
	tool := toolClient(t, agentPort, toolPool)
	upstreamURL := fmt.Sprintf("https://localhost:%d/hello", mockPort)

	// 7. POSITIVE: the tool sends only a ref; the broker injects the real secret.
	resp, body := doWithRetry(t, tool, "GET", upstreamURL, "Bearer cfdt:openai/personal", 3*time.Second)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	if body != "upstream-says-hi" {
		t.Errorf("body = %q", body)
	}
	if got := lastAuth.Load().(string); got != "Bearer "+realSecret {
		t.Errorf("upstream saw Authorization %q, want the injected real secret", got)
	}
	if strings.Contains(body, realSecret) {
		t.Error("real secret leaked into the tool-visible response body")
	}
	if resp.Header.Get("Authorization") != "" {
		t.Error("Authorization not scrubbed from response toward the tool")
	}
	if atomic.LoadInt32(&upstreamCalls) != 1 {
		t.Errorf("upstream calls = %d, want 1", atomic.LoadInt32(&upstreamCalls))
	}

	// 8. NEGATIVE: DELETE is not in the policy's allowed methods -> broker denies,
	// nothing reaches the upstream.
	dresp, dbody := doWithRetry(t, tool, "DELETE", upstreamURL, "Bearer cfdt:openai/personal", 3*time.Second)
	if dresp.StatusCode != http.StatusForbidden {
		t.Fatalf("DELETE status = %d, want 403; body=%s", dresp.StatusCode, dbody)
	}
	if !strings.Contains(dbody, "policy_denied") {
		t.Errorf("DELETE body = %q, want policy_denied", dbody)
	}
	if atomic.LoadInt32(&upstreamCalls) != 1 {
		t.Errorf("upstream was called on a denied request (calls=%d)", atomic.LoadInt32(&upstreamCalls))
	}

	// 9. Audit + no-leak checks on the broker's own log.
	auditData, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	audit := string(auditData)
	if !strings.Contains(audit, `"decision":"allowed"`) || !strings.Contains(audit, `"decision":"denied"`) {
		t.Errorf("audit log missing expected decisions:\n%s", audit)
	}
	if !strings.Contains(audit, "cfdt:openai/personal") {
		t.Error("audit log should reference the inert ref")
	}
	if strings.Contains(audit, realSecret) {
		t.Error("real secret leaked into the audit log (I-B4)")
	}

	// 10. The secret must not be present in anything on the tool side. The agent
	// config is the tool-side source of truth; assert the secret isn't in it.
	if bytes.Contains([]byte(agentCfg), []byte(realSecret)) {
		t.Error("real secret present in agent config — it should only be a ref")
	}
}

// startMockUpstream starts a TLS server on 127.0.0.1 that records the injected
// Authorization header and returns a fixed body. Returns its port.
func startMockUpstream(t *testing.T, certPEM, keyPEM []byte, calls *int32, lastAuth *atomic.Value) int {
	t.Helper()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(calls, 1)
			lastAuth.Store(r.Header.Get("Authorization"))
			w.Header().Set("Authorization", "reflected-should-be-scrubbed")
			_, _ = io.WriteString(w, "upstream-says-hi")
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// startProcess starts a subprocess, streams its output to a buffer, and logs the
// output if the test fails.
func startProcess(t *testing.T, bin string, args, extraEnv []string, name string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	var buf syncBuffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("=== %s output ===\n%s", name, buf.String())
		}
	})
}

func toolClient(t *testing.T, agentPort int, pool *x509.CertPool) *http.Client {
	t.Helper()
	pu, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", agentPort))
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

// doWithRetry issues a request, retrying transient startup failures until the
// deadline, then returns the final response and body.
func doWithRetry(t *testing.T, c *http.Client, method, url, auth string, within time.Duration) (*http.Response, string) {
	t.Helper()
	deadline := time.Now().Add(within)
	var lastErr error
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(method, url, nil)
		req.Header.Set("Authorization", auth)
		resp, err := c.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, string(b)
	}
	t.Fatalf("request %s %s failed within %s: %v", method, url, within, lastErr)
	return nil, ""
}

func readWhenReady(t *testing.T, path string, within time.Duration) []byte {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
			return b
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("file %s not ready within %s", path, within)
	return nil
}

func absDir(t *testing.T, rel string) string {
	t.Helper()
	p, err := filepath.Abs(rel)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
