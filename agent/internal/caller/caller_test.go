// SPDX-License-Identifier: Apache-2.0

package caller

import "testing"

// TestLookupAdvisory validates I-A10: caller lookup is cheap, never errors, and
// carries only advisory metadata (it must not gate anything).
func TestLookupAdvisory(t *testing.T) {
	c := Lookup("127.0.0.1:54321")
	if c.TS <= 0 {
		t.Errorf("expected a timestamp, got %d", c.TS)
	}
	// pid/exe are best-effort; zero is acceptable and must not block.
	if c.PID != 0 && c.Exe == "" {
		t.Log("pid resolved without exe; acceptable (advisory only)")
	}
}
