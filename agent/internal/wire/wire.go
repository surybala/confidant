// SPDX-License-Identifier: Apache-2.0

// Package wire defines the request/response contract on /v1/proxy between
// confidant-agent and the broker. It mirrors proxy/internal/wire/wire.go; the
// two are kept byte-compatible by hand until extracted into a shared module.
//
// The body is carried base64-encoded so the exact upstream bytes survive the
// hop unchanged — important for signed (SigV4) credentials.
//
// See ../../../docs/broker-core.md §6.
package wire

// Request is what the agent sends to POST /v1/proxy.
type Request struct {
	// Ref selects the secret + policy. It is the inert "cfdt:…" reference, never
	// a secret value. The broker is authoritative for resolving it.
	Ref string `json:"ref"`

	Upstream Upstream `json:"upstream"`

	// Caller is advisory metadata for the broker's audit log only. It MUST NOT
	// influence any authorization decision (invariant I-A10 / I-B11).
	Caller Caller `json:"caller"`
}

// Upstream is the outbound request with the credential removed. The broker adds
// or overwrites only what the credential module dictates.
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

// ErrorBody is returned by the broker on any non-2xx and echoed toward the tool.
// It never contains secret material.
type ErrorBody struct {
	Code    string `json:"confidant_error"`
	Message string `json:"message"`
}
