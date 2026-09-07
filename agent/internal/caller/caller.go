// SPDX-License-Identifier: Apache-2.0

// Package caller captures best-effort, advisory metadata about the local process
// that issued a request, for the broker's audit log.
//
// This is ADVISORY ONLY (invariant I-A10): it must never block a request or
// influence any decision, and it must be cheap and non-fatal. Reliable local
// port -> pid -> exe attribution is OS-specific and racy; Phase 1 records the
// timestamp and leaves pid/exe best-effort (zero when unknown).
package caller

import (
	"time"

	"github.com/surybala/confidant/agent/internal/wire"
)

// Lookup returns advisory caller metadata for a connection from remoteAddr.
// It never errors and never blocks meaningfully.
func Lookup(remoteAddr string) wire.Caller {
	// TODO(phase-1+): resolve remoteAddr's local port to a pid/exe via the OS
	// (lsof/proc), guarded by a tight timeout. Kept minimal and non-fatal now.
	_ = remoteAddr
	return wire.Caller{TS: time.Now().Unix()}
}
