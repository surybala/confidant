// confidant-proxy — the broker core.
//
// Runs inside a GCP Confidential Space enclave. It is the only place a plaintext
// secret ever exists: it terminates mTLS from confidant-agent, authorizes each
// request against stored policy, unwraps the secret via attestation-gated KMS,
// attaches it to the outbound call, scrubs the response, and audits the operation.
//
// This is a separate Go module so its dependency tree — its trusted computing
// base — stays small and isolated from the local agent. Keep it stdlib-first.
//
// See ../docs/broker-core.md
module github.com/surybala/confidant/proxy

go 1.22
