// SPDX-License-Identifier: Apache-2.0

// Package policy defines a secret's spend policy and the authorization decision.
//
// The policy is stored with the secret and is the ONLY source of truth for how a
// credential may be used (invariant I-B2): the caller never dictates injection
// scheme, hosts, or methods. Authorization runs BEFORE any unwrap (I-B5).
package policy

import (
	"strings"
	"sync"
	"time"
)

// Policy is the stored spend policy for a secret (broker-core.md §5 / phase1 §05).
type Policy struct {
	Credential     Credential `json:"credential"`
	AllowHosts     []string   `json:"allow_hosts"`
	AllowMethods   []string   `json:"allow_methods"`
	Rate           Rate       `json:"rate"`
	RequireConfirm bool       `json:"require_confirm"`
	Audit          bool       `json:"audit"`
}

// Credential says how the secret is attached (§04a). Kind selects the module.
type Credential struct {
	Kind   string `json:"kind"` // "static" | "sigv4" | "oauth2"
	Inject Inject `json:"inject,omitempty"`

	// sigv4
	Service    string `json:"service,omitempty"`
	RegionFrom string `json:"region_from,omitempty"`

	// oauth2
	TokenURL       string   `json:"token_url,omitempty"`
	ClientID       string   `json:"client_id,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
	RotatesRefresh bool     `json:"rotates_refresh,omitempty"`
}

// Inject describes static injection.
type Inject struct {
	Type     string `json:"type"`     // "header" | "query" | "basic"
	Name     string `json:"name"`     // header/query name
	Template string `json:"template"` // e.g. "Bearer {secret}"; "" => "{secret}"
}

// Rate bounds spend. RPM<=0 means unlimited; DailyUSDCap is not enforced in
// Phase 1 (needs per-request cost accounting) and is carried for forward-compat.
type Rate struct {
	RPM         int     `json:"rpm"`
	DailyUSDCap float64 `json:"daily_usd_cap"`
}

// Decision is the outcome of Authorize. Code/Status map to the wire response.
type Decision struct {
	Allowed bool
	Code    string // "policy_denied" | "cap_exceeded"
	Status  int    // 403 | 429
	Reason  string
}

var allowed = Decision{Allowed: true}

// Authorize checks method + host against the policy and applies the rate limit.
// It performs no I/O and touches no secret material.
func Authorize(p Policy, method, host string, lim *Limiter, id string) Decision {
	if len(p.AllowMethods) > 0 && !containsFold(p.AllowMethods, method) {
		return Decision{Code: "policy_denied", Status: 403, Reason: "method not allowed: " + method}
	}
	if !hostAllowed(p.AllowHosts, host) {
		return Decision{Code: "policy_denied", Status: 403, Reason: "host not allowed: " + host}
	}
	if p.Rate.RPM > 0 && lim != nil && !lim.Allow(id, p.Rate.RPM) {
		return Decision{Code: "cap_exceeded", Status: 429, Reason: "rate limit exceeded"}
	}
	return allowed
}

func hostAllowed(patterns []string, host string) bool {
	for _, p := range patterns {
		if MatchHost(p, host) {
			return true
		}
	}
	return false
}

// MatchHost matches host against a pattern supporting a leading "*." wildcard.
func MatchHost(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}
	return pattern == host
}

func containsFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

// Limiter is a fixed-window per-id request-rate limiter.
type Limiter struct {
	mu      sync.Mutex
	windows map[string]*window
	now     func() time.Time
}

type window struct {
	start time.Time
	count int
}

// NewLimiter creates a limiter.
func NewLimiter() *Limiter {
	return &Limiter{windows: map[string]*window{}, now: time.Now}
}

// Allow reports whether a request for id is within rpm this minute.
func (l *Limiter) Allow(id string, rpm int) bool {
	if rpm <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	w := l.windows[id]
	if w == nil || now.Sub(w.start) >= time.Minute {
		l.windows[id] = &window{start: now, count: 1}
		return true
	}
	if w.count >= rpm {
		return false
	}
	w.count++
	return true
}
