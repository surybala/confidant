// End-to-end integration tests for Confidant.
//
// This is a test-only module that builds and drives the real confidant-agent and
// confidant-proxy binaries over sockets. It depends on the two binary modules via
// local replace directives so it can build them, but imports no code from them
// (their pipelines live in internal/ packages) — it treats them as black boxes,
// which is what makes this a true end-to-end test.
module github.com/surybala/confidant/e2e

go 1.22
