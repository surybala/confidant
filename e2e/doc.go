// SPDX-License-Identifier: Apache-2.0

// Package e2e holds Confidant's end-to-end integration tests.
//
// The tests build and run the real confidant-agent and confidant-proxy binaries,
// wire them together with generated certs, a dev KEK, and an enrolled secret, and
// drive a "tool" HTTP client through the agent — asserting that the real secret
// only ever exists inside the broker and reaches the upstream, never the tool.
//
// Run: go test ./... -v   (requires the Go toolchain, since it builds the binaries)
package e2e
