// SPDX-License-Identifier: Apache-2.0

// Package proxy implements the agent's loopback forward proxy.
//
// Behaviour (local-agent.md §5):
//
//   - Non-intercepted hosts  -> BLIND CONNECT tunnel; the agent never decrypts
//     and never mints a leaf (invariant I-A3). It reads no plaintext it isn't
//     configured to route.
//   - Intercepted hosts      -> MITM-terminate with a leaf from the local CA,
//     detect the inert "cfdt:" ref, strip the credential, and relay the request
//     to the broker over pinned mTLS. The agent NEVER calls the upstream API on
//     this path (invariant I-A4) and holds no secret (I-A1).
//
// Everything on the intercepted path fails closed (I-A5/I-A8/I-A12): a missing
// ref, an unknown ref, an oversize body, or an unreachable broker all result in
// an error to the tool, never a forwarded or upstream-bound request.
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/surybala/confidant/agent/internal/ca"
	"github.com/surybala/confidant/agent/internal/caller"
	"github.com/surybala/confidant/agent/internal/config"
	"github.com/surybala/confidant/agent/internal/refs"
	"github.com/surybala/confidant/agent/internal/wire"
)

// BrokerClient relays a wire request to the broker. Abstracted so tests can
// inject a mock in place of the real pinned-mTLS client.
type BrokerClient interface {
	Relay(ctx context.Context, req wire.Request) (*http.Response, error)
}

// Handler is the forward-proxy HTTP handler.
type Handler struct {
	cfg     config.Config
	ca      *ca.CA
	broker  BrokerClient
	log     *slog.Logger
	maxBody int64
}

// New constructs a proxy handler.
func New(cfg config.Config, authority *ca.CA, broker BrokerClient, log *slog.Logger) *Handler {
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = 16 << 20
	}
	return &Handler{cfg: cfg, ca: authority, broker: broker, log: log, maxBody: maxBody}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
		return
	}
	// Plain-HTTP proxying is out of scope for Phase 1 (APIs use HTTPS).
	http.Error(w, "confidant-agent: only HTTPS (CONNECT) is proxied", http.StatusNotImplemented)
}

func (h *Handler) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := hostOnly(r.Host)

	clientConn, buf, err := hijack(w)
	if err != nil {
		http.Error(w, "confidant-agent: hijack unsupported", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}

	if h.cfg.IsIntercepted(host) {
		h.interceptAndRelay(clientConn, buf, r.Host, host)
		return
	}
	h.blindTunnel(clientConn, buf, r.Host)
}

// blindTunnel splices a raw TCP tunnel to the target without decrypting it.
// The agent never sees plaintext and never mints a leaf for this host (I-A3).
func (h *Handler) blindTunnel(clientConn net.Conn, buf *bufio.ReadWriter, authority string) {
	h.log.Info("blind tunnel", slog.String("host", hostOnly(authority)))

	upstream, err := net.DialTimeout("tcp", withDefaultPort(authority), 15*time.Second)
	if err != nil {
		h.log.Warn("blind tunnel dial failed", slog.String("host", hostOnly(authority)))
		return
	}
	defer upstream.Close()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, buf.Reader); done <- struct{}{} }()
	go func() { _, _ = io.Copy(clientConn, upstream); done <- struct{}{} }()
	<-done
}

// interceptAndRelay MITM-terminates the client TLS and relays each request to
// the broker. Forces HTTP/1.1 (no h2) for a simple, correct relay loop.
func (h *Handler) interceptAndRelay(clientConn net.Conn, buf *bufio.ReadWriter, authority, host string) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := chi.ServerName
			if name == "" {
				name = host
			}
			return h.ca.LeafFor(name)
		},
	}

	// Read handshake+data from the (possibly buffered) client reader; write to
	// the raw client connection.
	srv := tls.Server(rwConn{Conn: clientConn, r: buf.Reader}, tlsCfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.HandshakeContext(ctx); err != nil {
		h.log.Warn("MITM handshake failed", slog.String("host", host))
		return
	}
	defer srv.Close()

	remote := clientConn.RemoteAddr().String()
	br := bufio.NewReader(srv)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return // client closed or protocol error; done
		}
		keepAlive := h.serveOne(ctx, srv, authority, host, remote, req)
		if !keepAlive {
			return
		}
	}
}

// serveOne processes a single MITM'd request and writes the response. It returns
// whether the connection may be kept alive for another request.
func (h *Handler) serveOne(ctx context.Context, w io.Writer, authority, host, remote string, req *http.Request) bool {
	// Bound the body (fail closed on oversize).
	body, err := io.ReadAll(io.LimitReader(req.Body, h.maxBody+1))
	_ = req.Body.Close()
	if err != nil {
		writeError(w, http.StatusBadGateway, "read_error", "could not read request body")
		return false
	}
	if int64(len(body)) > h.maxBody {
		writeError(w, http.StatusRequestEntityTooLarge, "cap_exceeded", "request body exceeds limit")
		return false
	}

	rule := h.cfg.DetectFor(host)

	ref, ok := refs.Detect(rule, req)
	if !ok {
		// I-A8: no recognizable ref -> reject; forward nowhere (protects a real
		// key a caller may have placed here). Never log the offending value.
		h.log.Warn("rejecting intercepted request: no confidant reference",
			slog.String("host", host), slog.String("method", req.Method))
		writeError(w, http.StatusBadGateway, "no_ref", "no confidant reference for intercepted host")
		return false
	}
	if len(h.cfg.Refs) > 0 {
		if _, known := h.cfg.Refs[ref]; !known {
			h.log.Warn("rejecting intercepted request: unknown reference",
				slog.String("host", host), slog.String("ref", ref))
			writeError(w, http.StatusBadGateway, "unknown_ref", "unknown confidant reference")
			return false
		}
	}

	wreq := wire.Request{
		Ref:      ref,
		Upstream: h.buildUpstream(host, authority, rule, req, body),
		Caller:   caller.Lookup(remote),
	}

	h.log.Info("relaying to broker",
		slog.String("host", host), slog.String("method", req.Method), slog.String("ref", ref))

	resp, err := h.broker.Relay(ctx, wreq)
	if err != nil {
		// I-A5/I-A12: broker unreachable (or tailnet down) -> fail closed.
		h.log.Warn("broker relay failed — failing closed",
			slog.String("host", host), slog.String("err", err.Error()))
		writeError(w, http.StatusBadGateway, "broker_unreachable", "broker relay failed")
		return false
	}
	defer resp.Body.Close()

	// Relay the broker's response verbatim (the broker has already scrubbed it).
	if err := resp.Write(w); err != nil {
		return false
	}
	return !req.Close && resp.Close == false
}

// buildUpstream constructs the wire.Upstream with the credential removed
// (invariant I-A1: the agent forwards a ref, never a secret).
func (h *Handler) buildUpstream(host, authority string, rule config.DetectRule, req *http.Request, body []byte) wire.Upstream {
	u := &url.URL{
		Scheme:   "https",
		Host:     urlHost(authority),
		Path:     req.URL.Path,
		RawQuery: req.URL.RawQuery,
	}
	// Strip the credential from wherever it lived.
	if rule.Mode == config.ModeQuery && rule.Name != "" {
		q := u.Query()
		q.Del(rule.Name)
		u.RawQuery = q.Encode()
	}

	headers := flattenHeaders(req.Header)
	switch rule.Mode {
	case config.ModeAWSSDKDummy:
		delete(headers, "Authorization") // broker re-signs SigV4
	case config.ModeQuery:
		// credential removed from the URL above
	default: // header mode
		if rule.Name != "" {
			delete(headers, http.CanonicalHeaderKey(rule.Name))
		}
	}

	return wire.Upstream{
		Method:  req.Method,
		URL:     u.String(),
		Headers: headers,
		BodyB64: base64.StdEncoding.EncodeToString(body),
	}
}

// --- helpers ---

// rwConn reads from r (the buffered client reader) and writes/closes via Conn.
type rwConn struct {
	net.Conn
	r io.Reader
}

func (c rwConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func hijack(w http.ResponseWriter) (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, nil, errNotHijackable
	}
	return hj.Hijack()
}

var errNotHijackable = &proxyError{"response writer does not support hijacking"}

type proxyError struct{ msg string }

func (e *proxyError) Error() string { return e.msg }

// hopByHop headers are not forwarded to the broker.
var hopByHop = map[string]bool{
	"Connection":        true,
	"Proxy-Connection":  true,
	"Keep-Alive":        true,
	"Te":                true,
	"Trailer":           true,
	"Transfer-Encoding": true,
	"Upgrade":           true,
	"Host":              true, // carried by the URL; broker sets it
	"Content-Length":    true, // recomputed by the broker from the body
}

func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		out[k] = strings.Join(vs, ", ")
	}
	return out
}

func writeError(w io.Writer, status int, code, msg string) {
	body, _ := json.Marshal(wire.ErrorBody{Code: code, Message: msg})
	// Minimal, correct HTTP/1.1 response with Connection: close.
	_, _ = io.WriteString(w, "HTTP/1.1 "+strconv.Itoa(status)+" "+http.StatusText(status)+"\r\n")
	_, _ = io.WriteString(w, "Content-Type: application/json\r\n")
	_, _ = io.WriteString(w, "Content-Length: "+strconv.Itoa(len(body))+"\r\n")
	_, _ = io.WriteString(w, "Connection: close\r\n\r\n")
	_, _ = w.Write(body)
}

// hostOnly returns the host without the port.
func hostOnly(authority string) string {
	if h, _, err := net.SplitHostPort(authority); err == nil {
		return h
	}
	return authority
}

// urlHost returns the host for URL construction, dropping an explicit :443.
func urlHost(authority string) string {
	h, p, err := net.SplitHostPort(authority)
	if err != nil {
		return authority
	}
	if p == "443" || p == "" {
		return h
	}
	return net.JoinHostPort(h, p)
}

// withDefaultPort ensures an authority has a port for dialing.
func withDefaultPort(authority string) string {
	if _, _, err := net.SplitHostPort(authority); err == nil {
		return authority
	}
	return net.JoinHostPort(authority, "443")
}
