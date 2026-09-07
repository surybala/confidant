// SPDX-License-Identifier: Apache-2.0

// Package pipeline is the broker's /v1/proxy credential-injection pipeline.
//
// Ordering is load-bearing (broker-core.md §6/§8):
//
//  1. decode request (body-capped)
//  2. validate upstream URL + body      (before any unwrap)
//  3. resolve ref -> record            (broker is authoritative)
//  4. AUTHORIZE against policy          (I-B5: before any unwrap)
//  5. egress allowlist                  (I-B7)
//  6. verify credential module exists   (before any unwrap)
//  7. unwrap secret via KMS             (I-B6)
//  8. apply credential module           (I-B2: scheme from policy only)
//  9. call upstream
//
// 10. scrub response                    (I-B3)
// 11. audit exactly once                (I-B10)
//
// Any failure denies and fails closed (I-B8). Mutable secret buffers are wiped
// after use; transient header/TLS/runtime copies stay inside enclave memory.
package pipeline

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/surybala/confidant/proxy/internal/audit"
	"github.com/surybala/confidant/proxy/internal/credmod"
	"github.com/surybala/confidant/proxy/internal/kms"
	"github.com/surybala/confidant/proxy/internal/policy"
	"github.com/surybala/confidant/proxy/internal/store"
	"github.com/surybala/confidant/proxy/internal/wire"
)

// Deps are the pipeline's collaborators.
type Deps struct {
	Store     store.Store
	Unwrapper kms.Unwrapper
	Modules   credmod.Registry
	Limiter   *policy.Limiter
	Egress    []string // network allowlist (empty => policy hosts are the only gate)
	Upstream  *http.Client
	Audit     audit.Auditor
	Log       *slog.Logger
	MaxBody   int64
}

// Handler serves POST /v1/proxy.
type Handler struct {
	d Deps
}

// New builds a Handler, filling in sane defaults.
func New(d Deps) *Handler {
	if d.Modules == nil {
		d.Modules = credmod.Default()
	}
	if d.Limiter == nil {
		d.Limiter = policy.NewLimiter()
	}
	if d.Upstream == nil {
		d.Upstream = &http.Client{}
	}
	if d.MaxBody <= 0 {
		d.MaxBody = 16 << 20
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	return &Handler{d: d}
}

// scrub headers always removed from the response toward the agent.
var scrubDenylist = []string{"Authorization", "Proxy-Authorization", "X-Amz-Security-Token"}

// Handle is the pipeline entrypoint.
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) {
	// 1. decode (body-capped).
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, h.d.MaxBody*2+4096))
	var req wire.Request
	if err := dec.Decode(&req); err != nil {
		h.deny(w, req, http.StatusBadRequest, "bad_request", "invalid request body")
		return
	}
	upstreamURL, host, status, code, reason := validateUpstreamURL(req.Upstream.URL)
	if status != 0 {
		h.deny(w, req, status, code, reason)
		return
	}
	body, err := decodeBody(req.Upstream.BodyB64, h.d.MaxBody)
	if err != nil {
		h.deny(w, req, errStatus(err), errCode(err), err.Error())
		return
	}

	// 3. resolve ref -> record.
	id := resolveRef(req.Ref)
	rec, err := h.d.Store.Get(id)
	if err != nil {
		h.deny(w, req, http.StatusNotFound, wire.CodeUnknownRef, "unknown ref")
		return
	}

	// 4. AUTHORIZE — before any unwrap (I-B5).
	if d := policy.Authorize(rec.Policy, req.Upstream.Method, host, h.d.Limiter, id); !d.Allowed {
		h.deny(w, req, d.Status, d.Code, d.Reason)
		return
	}

	// 5. egress allowlist (network layer; I-B7). Checked before unwrap so a
	// disallowed destination never triggers a decrypt.
	if !h.egressAllowed(host) {
		h.deny(w, req, http.StatusForbidden, wire.CodePolicyDenied, "egress not allowed: "+host)
		return
	}

	// 6. verify credential module exists before any unwrap.
	mod, ok := h.d.Modules.Get(rec.Policy.Credential.Kind)
	if !ok {
		h.deny(w, req, http.StatusInternalServerError, "unsupported_credential", "no module for kind "+rec.Policy.Credential.Kind)
		return
	}
	if !credmod.IsImplemented(mod) {
		h.deny(w, req, http.StatusNotImplemented, wire.CodeNotImplemented, "credential module not implemented")
		return
	}

	// 7. unwrap secret via KMS (I-B6). Zeroized immediately after use (I-B1).
	secret, err := h.d.Unwrapper.Unwrap(r.Context(), rec.Envelope)
	if err != nil {
		h.deny(w, req, http.StatusServiceUnavailable, wire.CodeUnavailable, "secret unwrap failed")
		return
	}
	defer kms.Zero(secret)

	// build outbound request.
	out, err := http.NewRequestWithContext(r.Context(), req.Upstream.Method, upstreamURL.String(), bytes.NewReader(body))
	if err != nil {
		h.deny(w, req, http.StatusBadRequest, "bad_request", "invalid upstream request")
		return
	}
	for k, v := range req.Upstream.Headers {
		out.Header.Set(k, v)
	}

	// 8. apply credential module (scheme from policy only; I-B2).
	scrubHeader, err := mod.Apply(out, rec.Policy.Credential, secret)
	if err != nil {
		h.deny(w, req, http.StatusNotImplemented, wire.CodeNotImplemented, "credential module error")
		return
	}

	// 9. call upstream.
	resp, err := h.d.Upstream.Do(out)
	if err != nil {
		h.deny(w, req, http.StatusBadGateway, wire.CodeUpstreamError, "upstream call failed")
		return
	}
	defer resp.Body.Close()

	// 10. scrub response (I-B3).
	scrubResponse(resp.Header, scrubHeader)

	// write response toward the agent.
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, resp.Body)

	// 11. audit allowed, exactly once (I-B10).
	h.audit(req, "allowed", "", resp.StatusCode, int(n), rec.Policy.Credential.Kind)
}

type bodyValidationError struct {
	status int
	code   string
	msg    string
}

func (e bodyValidationError) Error() string { return e.msg }

func decodeBody(encoded string, maxBody int64) ([]byte, error) {
	body, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, bodyValidationError{status: http.StatusBadRequest, code: "bad_request", msg: "invalid body encoding"}
	}
	if int64(len(body)) > maxBody {
		return nil, bodyValidationError{status: http.StatusRequestEntityTooLarge, code: wire.CodeCapExceeded, msg: "body too large"}
	}
	return body, nil
}

func errStatus(err error) int {
	if e, ok := err.(bodyValidationError); ok {
		return e.status
	}
	return http.StatusBadRequest
}

func errCode(err error) string {
	if e, ok := err.(bodyValidationError); ok {
		return e.code
	}
	return "bad_request"
}

func validateUpstreamURL(raw string) (*url.URL, string, int, string, string) {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return nil, "", http.StatusBadRequest, "bad_request", "invalid upstream URL"
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, "", http.StatusBadRequest, "bad_request", "upstream URL must use https"
	}
	if u.User != nil {
		return nil, "", http.StatusBadRequest, "bad_request", "upstream URL must not contain userinfo"
	}
	if u.Fragment != "" {
		return nil, "", http.StatusBadRequest, "bad_request", "upstream URL must not contain a fragment"
	}
	host := u.Hostname()
	if host == "" {
		return nil, "", http.StatusBadRequest, "bad_request", "upstream URL must contain a host"
	}
	return u, strings.TrimSuffix(strings.ToLower(host), "."), 0, "", ""
}

func (h *Handler) egressAllowed(host string) bool {
	if len(h.d.Egress) == 0 {
		return true // dev: policy AllowHosts is the only gate (prod MUST set this)
	}
	for _, p := range h.d.Egress {
		if policy.MatchHost(p, host) {
			return true
		}
	}
	return false
}

// deny writes a structured error and audits the denial exactly once.
func (h *Handler) deny(w http.ResponseWriter, req wire.Request, status int, code, reason string) {
	writeErr(w, status, code, reason)
	h.audit(req, "denied", reason, status, 0, "")
}

func (h *Handler) audit(req wire.Request, decision, reason string, status, bytesOut int, kind string) {
	if h.d.Audit == nil {
		return
	}
	_ = h.d.Audit.Write(audit.Record{
		Ref:      req.Ref,
		Host:     hostOf(req.Upstream.URL),
		Method:   req.Upstream.Method,
		Path:     pathOf(req.Upstream.URL),
		Decision: decision,
		Reason:   reason,
		Status:   status,
		BytesOut: bytesOut,
		Kind:     kind,
	})
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(wire.ErrorBody{Code: code, Message: msg})
}

func scrubResponse(h http.Header, injected string) {
	for _, name := range scrubDenylist {
		h.Del(name)
	}
	if injected != "" {
		h.Del(injected)
	}
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// resolveRef strips the "cfdt:" prefix to yield the store id.
func resolveRef(ref string) string {
	const p = "cfdt:"
	if len(ref) >= len(p) && ref[:len(p)] == p {
		return ref[len(p):]
	}
	return ref
}

func hostOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.Hostname()
	}
	return ""
}

func pathOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.Path
	}
	return ""
}
