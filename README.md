# Confidant

Keep secrets off the laptop. Confidant routes credentialed API calls through an
**attested GCP enclave** so that untrusted local code — a malicious dependency or
MCP tool — can't steal what was never there.

## Layout

Two standalone Go binaries, each in its own module so their dependency trees stay
isolated (the broker's tree is part of its trusted computing base):

| Path | Binary | Role | Runs |
|---|---|---|---|
| [`proxy/`](proxy/) | `confidant-proxy` | **Broker core** — the credential-injecting egress proxy. The only place a plaintext secret exists. | GCP Confidential Space enclave |
| [`agent/`](agent/) | `confidant-agent` | **Local agent** — loopback forward proxy; secretless; relays intercepted calls to the broker. | Your machine |

> **Naming:** `confidant-proxy` is the enclave-side broker ([broker-core.md](docs/broker-core.md));
> `confidant-agent` is the local side ([local-agent.md](docs/local-agent.md)).

## Specs

- [docs/phase1-secrets-broker.md](docs/phase1-secrets-broker.md) — the Phase-1 architecture, threat model, and milestones.
- [docs/broker-core.md](docs/broker-core.md) — `confidant-proxy`: security/config decisions, auth scheme, invariants (I-B*), tests.
- [docs/local-agent.md](docs/local-agent.md) — `confidant-agent`: security/config decisions, auth scheme, invariants (I-A*), tests.

## Status

Phase-1 **local/dev functional**, stdlib-only (builds offline, no dependencies).
The current code proves the static-token broker path locally; `CONFIDANT_MODE=enclave`
currently fails closed until the production Cloud KMS/WIF unwrapper and tailnet-only
`tsnet` listener are implemented.

- **`confidant-agent`** — a real loopback CONNECT proxy: blind-tunnels
  non-intercepted hosts, and for intercepted hosts MITM-terminates with a
  name-constrained local CA, detects the inert `cfdt:` ref, strips the credential,
  and relays to the broker over SPKI-pinned mTLS. Fails closed throughout.
- **`confidant-proxy`** — the real `/v1/proxy` pipeline: resolve ref → authorize
  (before unwrap) → unwrap via a dev KEK (stands in for Cloud KMS + attestation)
  → apply the static credential module → HTTPS-only egress-allowlisted upstream
  call → scrub → hash-chained audit. mTLS with `TLS_CERT`/`TLS_KEY`/`CLIENT_CA`.
  SigV4 and OAuth2 modules are registered but fail closed before secret unwrap
  until implemented.
- **`e2e/`** — a test-only module that builds both binaries and drives the whole
  flow (enroll → agent → broker → mock upstream), asserting the real secret only
  ever lives in the broker and reaches the upstream, never the tool or the log.

The local/dev invariants implemented so far have regression tests; enclave-only
invariants are documented and fail closed until their production implementations
land.

## Build & run

Requires Go 1.22+.

```bash
make build          # build both binaries into ./bin
make test           # unit tests (proxy + agent) and the end-to-end test
make cover          # unit tests with coverage
```

### End-to-end test

`make test-e2e` runs the full flow (enroll → agent → broker → mock upstream) and
asserts the real secret only ever lives in the broker, never leaking to the tool
or the audit log. The test builds both binaries itself, so Go is the only
prerequisite — no `make build` or running services needed:

```bash
make test-e2e                       # via the Makefile
cd e2e && go test ./...             # or directly
cd e2e && go test -v -run TestEndToEnd ./...   # verbose, single test
```

It is skipped under `go test -short` (it compiles both binaries). See
[e2e/e2e_test.go](e2e/e2e_test.go).

Run it locally end to end:

```bash
# 1. enroll a secret into the store (reads the secret value from stdin)
printf 'sk-live-example' | ./bin/confidant-proxy enroll \
    -id openai/personal -kek dev.kek -store store.json \
    -host api.openai.com -methods GET,POST

# 2. run the broker (dev plaintext; set TLS_CERT/TLS_KEY/CLIENT_CA for mTLS)
SECRET_STORE=store.json DEV_KEK=dev.kek AUDIT_SINK=audit.log \
    ./bin/confidant-proxy serve -listen :8443

# 3. run the agent, pointed at the broker
CONFIDANT_INTERCEPT="api.openai.com" CONFIDANT_BROKER="https://127.0.0.1:8443" \
    ./bin/confidant-agent -ca-export ./agent-ca.pem
```

The `e2e` test wires all of this together automatically — see
[e2e/e2e_test.go](e2e/e2e_test.go).

## Security note

Never commit key material. `.gitignore` excludes certs/keys (`*.pem`, `*.key`, …),
secret envelopes, dev KEK material, `.env` files, and audit output. Agent config
contains **no secrets** by design; `agent/agent.example.toml` is a safe template.

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE). Each Go
source file carries an `SPDX-License-Identifier: Apache-2.0` header.
