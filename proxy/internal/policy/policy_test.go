// SPDX-License-Identifier: Apache-2.0

package policy

import "testing"

func base() Policy {
	return Policy{
		AllowHosts:   []string{"api.openai.com", "*.amazonaws.com"},
		AllowMethods: []string{"GET", "POST"},
	}
}

func TestAuthorizeMatrix(t *testing.T) {
	p := base()
	cases := []struct {
		method, host string
		wantAllowed  bool
		wantStatus   int
	}{
		{"GET", "api.openai.com", true, 0},
		{"post", "api.openai.com", true, 0},      // method case-insensitive
		{"GET", "s3.amazonaws.com", true, 0},     // wildcard
		{"DELETE", "api.openai.com", false, 403}, // method denied
		{"GET", "evil.com", false, 403},          // host denied
		{"GET", "amazonaws.com", false, 403},     // apex not matched by *.
	}
	for _, c := range cases {
		d := Authorize(p, c.method, c.host, nil, "id")
		if d.Allowed != c.wantAllowed {
			t.Errorf("Authorize(%s,%s) allowed=%v, want %v (%s)", c.method, c.host, d.Allowed, c.wantAllowed, d.Reason)
		}
		if !c.wantAllowed && d.Status != c.wantStatus {
			t.Errorf("Authorize(%s,%s) status=%d, want %d", c.method, c.host, d.Status, c.wantStatus)
		}
	}
}

func TestAuthorizeEmptyMethodsAllowsAny(t *testing.T) {
	p := Policy{AllowHosts: []string{"api.openai.com"}}
	if d := Authorize(p, "PATCH", "api.openai.com", nil, "id"); !d.Allowed {
		t.Error("empty AllowMethods should allow any method")
	}
}

func TestRateLimit(t *testing.T) {
	p := base()
	p.Rate.RPM = 2
	lim := NewLimiter()
	got := 0
	for i := 0; i < 5; i++ {
		if Authorize(p, "GET", "api.openai.com", lim, "id").Allowed {
			got++
		}
	}
	if got != 2 {
		t.Errorf("allowed %d requests, want 2 (rpm cap)", got)
	}
}

func TestLimiterUnlimitedWhenRPMZero(t *testing.T) {
	lim := NewLimiter()
	for i := 0; i < 100; i++ {
		if !lim.Allow("id", 0) {
			t.Fatal("rpm<=0 should be unlimited")
		}
	}
}
