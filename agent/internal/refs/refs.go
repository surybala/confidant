// SPDX-License-Identifier: Apache-2.0

// Package refs detects and parses inert credential references ("cfdt:…") in
// outbound requests. A ref names a secret; it is never a secret itself.
//
// Detection is deterministic per host (local-agent.md §6). If no recognizable
// ref is found on an intercepted host, the caller MUST fail closed — never
// forward — which also protects a user who accidentally placed a REAL key where
// a ref belongs (invariant I-A8).
//
// The optional "#hint" suffix is display-only and is stripped here; it is never
// returned to callers and must never be logged (invariant I-A11).
package refs

import (
	"net/http"
	"strings"

	"github.com/surybala/confidant/agent/internal/config"
)

// Prefix marks an inert Confidant reference.
const Prefix = "cfdt:"

// ParseRef splits a raw value into its ref (hint removed) and reports whether it
// is a well-formed Confidant reference. The hint is intentionally discarded.
func ParseRef(raw string) (ref string, ok bool) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, Prefix) {
		return "", false
	}
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw = raw[:i] // drop the display hint
	}
	if raw == Prefix {
		return "", false // "cfdt:" with no id
	}
	return raw, true
}

// Detect locates the ref in req according to rule. It returns the ref (hint
// stripped) and whether a valid ref was found. A false result means "fail
// closed" — either no value was present, or the value present was not a ref
// (e.g. a real secret). The distinction is deliberately not surfaced, so a real
// secret is never echoed or logged.
func Detect(rule config.DetectRule, req *http.Request) (ref string, ok bool) {
	switch rule.Mode {
	case config.ModeQuery:
		return ParseRef(req.URL.Query().Get(rule.Name))

	case config.ModeAWSSDKDummy:
		akid, found := awsAccessKeyID(req.Header.Get("Authorization"))
		if !found || akid != rule.SentinelAccessKeyID {
			return "", false
		}
		// The ref is configured, not carried in the request.
		return ParseRef(rule.Ref)

	default: // ModeHeader
		v := req.Header.Get(rule.Name)
		if v == "" {
			return "", false
		}
		v = strings.TrimPrefix(v, rule.StripPrefix)
		return ParseRef(v)
	}
}

// awsAccessKeyID extracts the access-key-id from a SigV4 Authorization header:
//
//	AWS4-HMAC-SHA256 Credential=<akid>/<date>/<region>/<service>/aws4_request, ...
func awsAccessKeyID(auth string) (string, bool) {
	const marker = "Credential="
	i := strings.Index(auth, marker)
	if i < 0 {
		return "", false
	}
	rest := auth[i+len(marker):]
	j := strings.IndexByte(rest, '/')
	if j < 0 {
		return "", false
	}
	akid := strings.TrimSpace(rest[:j])
	if akid == "" {
		return "", false
	}
	return akid, true
}
