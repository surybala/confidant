// confidant-shared — small, stdlib-first library shared across enclave components.
//
// Holds the trusted-computing-base primitives that both confidant-proxy and the
// (forthcoming) confidant-runner need: envelope sealing / MAC, attestation-gated
// KMS unwrap, and the Confidential Space attestation token source. Kept dependency-
// free (stdlib plus Google REST endpoints over net/http) so importing it does not
// grow any component's TCB.
module github.com/surybala/confidant/shared

go 1.22
