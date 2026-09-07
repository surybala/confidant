// SPDX-License-Identifier: Apache-2.0

// Package wire defines the request/response contract on /v1/proxy between
// confidant-agent and confidant-proxy (the broker).
//
// The body is carried base64-encoded so the exact upstream bytes survive the
// hop unchanged — important for signed (SigV4) credentials, where the broker
// hashes the body it will actually send.
//
// See ../../docs/broker-core.md §6.
package wire

// Request is what the agent sends to POST /v1/proxy.
type Request struct {
	// Ref selects the secret + policy. It is authoritative: the broker resolves
	// policy from Ref and never trusts the caller to describe how the credential
	// is attached (invariant I-B2).
	Ref string `json:"ref"`

	Upstream Upstream `json:"upstream"`

	// Caller is advisory metadata for the audit log only. It MUST NOT influence
	// any authorization decision (invariant I-B11).
	Caller Caller `json:"caller"`
}

// Upstream is the outbound request minus the credential. The broker adds or
// overwrites only what the credential module dictates.
type Upstream struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	BodyB64 string            `json:"body_b64"`
}

// Caller identifies the local process, best-effort. Advisory only.
type Caller struct {
	PID int    `json:"pid"`
	Exe string `json:"exe"`
	TS  int64  `json:"ts"`
}

// ErrorBody is returned on any non-2xx. It never contains secret material or the
// offending header value (invariant I-B4).
type ErrorBody struct {
	Code    string `json:"confidant_error"`
	Message string `json:"message"`
}

// Error codes returned by the broker (see broker-core.md §6). The HTTP status is
// paired with a stable machine-readable code.
const (
	CodeIdentity       = "identity"        // 401: mTLS / unenrolled client
	CodePolicyDenied   = "policy_denied"   // 403: host/method/scope/require_confirm
	CodeUnknownRef     = "unknown_ref"     // 404: ref not found
	CodeRotationFailed = "rotation_failed" // 409: OAuth write-back failed; old token retained
	CodeCapExceeded    = "cap_exceeded"    // 429: rate or daily-cost cap
	CodeUpstreamError  = "upstream_error"  // 502: upstream failed/unreachable
	CodeUnavailable    = "unavailable"     // 503: attestation/KMS/store down — fail closed
	CodeNotImplemented = "not_implemented" // 501: skeleton stub
)
