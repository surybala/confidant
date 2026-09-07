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

Phase-1 **functional**, stdlib-only (builds offline, no dependencies). Both the
local **dev** path and the GCP **enclave** unwrap path are implemented; see the
[GCP enclave setup guide](#setting-up-the-gcp-enclave-broker) to run it for real.

- **`confidant-agent`** — a real loopback CONNECT proxy: blind-tunnels
  non-intercepted hosts, and for intercepted hosts MITM-terminates with a
  name-constrained local CA, detects the inert `cfdt:` ref, strips the credential,
  and relays to the broker over SPKI-pinned mTLS. Fails closed throughout.
- **`confidant-proxy`** — the real `/v1/proxy` pipeline: resolve ref → authorize
  (before unwrap) → unwrap the secret → apply the static credential module →
  HTTPS-only egress-allowlisted upstream call → scrub → hash-chained audit. mTLS
  with `TLS_CERT`/`TLS_KEY`/`CLIENT_CA`. SigV4 and OAuth2 modules are registered
  but fail closed before secret unwrap until implemented.
  - **`dev` mode** unwraps with a local dev KEK (a 32-byte AES key on disk) —
    for local development and the e2e test, no GCP needed.
  - **`enclave` mode** unwraps via a cloud provider behind an abstraction
    (`internal/kms`): the default GCP provider (`internal/kms/gcp`) presents a
    Confidential Space attestation token to Workload Identity Federation, gets a
    short-lived federated token, and calls Cloud KMS `decrypt` on the wrapped DEK.
    The KEK never leaves KMS; a stolen store or a tampered image decrypts nothing.
    Adding AWS KMS / Azure Key Vault is a new `kms.KeyDecryptor` implementation and
    nothing else changes.
- **`e2e/`** — a test-only module that builds both binaries and drives the whole
  flow (enroll → agent → broker → mock upstream), asserting the real secret only
  ever lives in the broker and reaches the upstream, never the tool or the log.

Every implemented invariant (I-A*, I-B*) has a regression test. The one production
gate still stubbed is **attestation-gated delivery of the tailnet auth key**
(I-B15): the setup guide passes `TS_AUTHKEY` as enclave metadata and notes how to
harden it.

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

## Running for real: agent on your laptop, broker in a GCP enclave

This is the full credential-free setup. When you finish, a tool on your laptop
makes an authenticated API call while the real key exists **only** inside an
attested GCP enclave — never on your machine, never in your app's environment.

```
your app ──HTTPS_PROXY──▶ confidant-agent ──mTLS over Tailscale──▶ confidant-proxy
 (holds a "cfdt:" ref)      (your laptop)                          (GCP Confidential Space)
                                                                     │ attest → Cloud KMS
                                                                     │ unwrap secret, inject
                                                                     ▼ call the real upstream
```

Two gates protect the agent→broker channel (invariant I-B14): the **Tailscale
ACL** (network identity) and **mTLS** (device identity). The secret is unwrapped
only under a live Confidential Space attestation that matches the pinned image
digest (I-B6); a stolen envelope or a tampered image decrypts nothing.

### Prerequisites

- A GCP project with billing (`PROJECT_ID`, and its numeric `PROJECT_NUMBER`).
- `gcloud` authenticated (`gcloud auth login`), `docker`, `openssl`, Go 1.22+.
- A [Tailscale](https://tailscale.com) tailnet you administer.
- APIs enabled:
  ```bash
  gcloud services enable cloudkms.googleapis.com iamcredentials.googleapis.com \
      sts.googleapis.com artifactregistry.googleapis.com compute.googleapis.com \
      confidentialcomputing.googleapis.com
  ```

Throughout, replace `PROJECT_ID`, `PROJECT_NUMBER`, `REGION`, `ZONE`, and
`TAILNET` (your tailnet's name, e.g. `example.ts.net`) with your values.

### Part 1 — Enrollment CA and device identity (the mTLS trust root)

The broker trusts agents whose client certs are signed by an enrollment CA; the
agent pins the broker's server-cert public key. Create them once:

```bash
# Enrollment CA — signs agent device certs; the broker trusts it via CLIENT_CA.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout enroll-ca.key -out enroll-ca.pem -days 3650 -subj "/CN=Confidant Enrollment CA"

# A device cert for this laptop, signed by the enrollment CA.
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout agent-device.key -out agent-device.csr -subj "/CN=my-laptop"
openssl x509 -req -in agent-device.csr -CA enroll-ca.pem -CAkey enroll-ca.key \
    -CAcreateserial -out agent-device.crt -days 825

# The broker's own server cert (self-signed: the agent pins its SPKI, not a chain).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout broker.key -out broker.crt -days 825 -subj "/CN=confidant-broker"
```

Compute the broker's **SPKI pin** — the agent will refuse any other key:

```bash
printf 'sha256/'; openssl x509 -in broker.crt -pubkey -noout \
    | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary | base64
```

Save that `sha256/…` string; it becomes the agent's `server_spki_pin`.

### Part 2 — Cloud KMS + Workload Identity Federation

Create the key-encryption key (the KEK never leaves KMS):

```bash
gcloud kms keyrings create confidant --location=global
gcloud kms keys create broker-kek --keyring=confidant --location=global --purpose=encryption
```

Create a service account the broker impersonates, and let it decrypt with the KEK:

```bash
gcloud iam service-accounts create confidant-broker --display-name="Confidant broker"
BROKER_SA="confidant-broker@PROJECT_ID.iam.gserviceaccount.com"
KMS_KEY_RESOURCE="projects/PROJECT_ID/locations/global/keyRings/confidant/cryptoKeys/broker-kek"
WIF_AUDIENCE="//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/confidant-pool/providers/confidant-provider"

gcloud kms keys add-iam-policy-binding broker-kek \
    --keyring=confidant --location=global \
    --member="serviceAccount:${BROKER_SA}" \
    --role=roles/cloudkms.cryptoKeyDecrypter
```

Create the WIF pool + provider. You don't have the image digest yet, so create
the provider in a deny-all state and tighten the condition with the real digest
in Part 4. The **attribute condition** is the security gate: KMS releases the key
only to a genuine Confidential Space enclave running the expected image, in the
expected project, under the expected workload service account, with the expected
security-critical env values.

```bash
gcloud iam workload-identity-pools create confidant-pool --location=global

gcloud iam workload-identity-pools providers create-oidc confidant-provider \
    --location=global --workload-identity-pool=confidant-pool \
    --issuer-uri="https://confidentialcomputing.googleapis.com/" \
    --attribute-mapping="google.subject=assertion.sub,attribute.image_digest=assertion.submods.container.image_digest" \
    --attribute-condition="false"
```

The service-account impersonation grant is added in Part 4 after the digest is
known, scoped to that digest instead of the whole pool.

Three values feed the broker's config:
- `KMS_KEY` = `${KMS_KEY_RESOURCE}`
- `WIF_AUDIENCE` = `${WIF_AUDIENCE}`
- `KMS_SERVICE_ACCOUNT` = `${BROKER_SA}`

### Part 3 — Enroll your secrets (sealed to KMS)

Enrollment seals each secret under a fresh per-secret DEK and wraps that DEK with
the KEK. It authenticates to KMS with **your** operator identity — grant yourself
encrypt, then pass a short-lived token:

```bash
gcloud kms keys add-iam-policy-binding broker-kek --keyring=confidant --location=global \
    --member="user:$(gcloud config get-value account)" --role=roles/cloudkms.cryptoKeyEncrypter

make build
printf 'sk-live-your-real-openai-key' | GOOGLE_ACCESS_TOKEN="$(gcloud auth print-access-token)" \
    ./bin/confidant-proxy enroll \
        -id openai/personal \
        -kms-key "${KMS_KEY_RESOURCE}" \
        -store store.json -host api.openai.com -methods GET,POST
```

`store.json` now holds only ciphertext (`alg=KMS+AES-256-GCM`). Copy it into the
build context so it ships in the image (safe — it is inert without a live
attestation): `cp store.json proxy/deploy/store.json`.

### Part 4 — Build, push, and deploy the broker to Confidential Space

A [`Dockerfile`](proxy/Dockerfile) and [entrypoint](proxy/deploy/entrypoint.sh)
are included. The entrypoint runs Tailscale in userspace mode (Confidential Space
has no TUN device) and forwards inbound tailnet TCP to the broker's loopback
listener, so the broker has **no public listener** (I-B13).

```bash
gcloud artifacts repositories create confidant --repository-format=docker --location=REGION
gcloud auth configure-docker REGION-docker.pkg.dev

IMAGE="REGION-docker.pkg.dev/PROJECT_ID/confidant/confidant-proxy"
docker build -t "$IMAGE:v1" proxy/
docker push "$IMAGE:v1"

# Get the immutable digest and pin it in the WIF condition from Part 2.
docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE:v1"
```

Pin that digest into the WIF condition so only this exact workload can decrypt.
The policy binds the image digest, image reference, GCP project, workload service
account, and the security-critical `tee-env` values. That way the enclave has to
be the right code running in the right place with the expected KMS configuration,
not merely any VM that can run the same container digest:

```bash
IMAGE_REF="${IMAGE}@sha256:IMAGE_DIGEST"

gcloud iam workload-identity-pools providers update-oidc confidant-provider \
    --location=global --workload-identity-pool=confidant-pool \
    --attribute-condition="assertion.swname=='CONFIDENTIAL_SPACE' && 'STABLE' in assertion.submods.confidential_space.support_attributes && assertion.submods.container.image_digest=='sha256:IMAGE_DIGEST' && assertion.submods.container.image_reference=='${IMAGE_REF}' && assertion.submods.gce.project_number=='PROJECT_NUMBER' && '${BROKER_SA}' in assertion.google_service_accounts && assertion.submods.container.env['KMS_KEY']=='${KMS_KEY_RESOURCE}' && assertion.submods.container.env['WIF_AUDIENCE']=='${WIF_AUDIENCE}' && assertion.submods.container.env['KMS_SERVICE_ACCOUNT']=='${BROKER_SA}'"

gcloud iam service-accounts add-iam-policy-binding "${BROKER_SA}" \
    --role=roles/iam.workloadIdentityUser \
    --member="principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/confidant-pool/attribute.image_digest/sha256:IMAGE_DIGEST"
```

Mint an **ephemeral, tagged** Tailscale auth key in
the Tailscale admin console (Settings → Keys: reusable off, ephemeral on, tag
`tag:confidant-broker`), then deploy:

```bash
gcloud compute instances create confidant-broker --zone=ZONE \
    --confidential-compute-type=SEV --shielded-secure-boot --maintenance-policy=TERMINATE \
    --image-project=confidential-space-images --image-family=confidential-space \
    --service-account="${BROKER_SA}" --scopes=cloud-platform \
    --metadata="^~^tee-image-reference=${IMAGE}@sha256:IMAGE_DIGEST~tee-container-log-redirect=true~tee-env-KMS_KEY=${KMS_KEY_RESOURCE}~tee-env-WIF_AUDIENCE=${WIF_AUDIENCE}~tee-env-KMS_SERVICE_ACCOUNT=${BROKER_SA}~tee-env-EGRESS_ALLOW=api.openai.com~tee-env-SECRET_STORE=/deploy/store.json~tee-env-TLS_CERT=/deploy/broker.crt~tee-env-TLS_KEY=/deploy/broker.key~tee-env-CLIENT_CA=/deploy/enroll-ca.pem~tee-env-TS_AUTHKEY=tskey-auth-xxxx"
```

> Put `broker.crt`, `broker.key`, and `enroll-ca.pem` into `proxy/deploy/` before
> the build so they land at `/deploy/…`. `broker.key` and `TS_AUTHKEY` are
> sensitive — see the hardening note below.

Configure the Tailscale **ACL** so only agents can reach the broker (Access
Controls in the admin console):

```jsonc
{
  "tagOwners": { "tag:confidant-agent": ["autogroup:admin"], "tag:confidant-broker": ["autogroup:admin"] },
  "acls": [
    { "action": "accept", "src": ["tag:confidant-agent"], "dst": ["tag:confidant-broker:8443"] }
  ]
}
```

### Part 5 — Run the local agent

Join your laptop to the tailnet tagged as an agent, then run the agent pointed at
the broker's MagicDNS name. Write the agent config (no secrets — see
[agent/agent.example.toml](agent/agent.example.toml)):

```bash
tailscale up --advertise-tags=tag:confidant-agent

cat > agent.json <<JSON
{
  "listen": "127.0.0.1:8317",
  "broker_endpoint": "https://confidant-broker.TAILNET.ts.net:8443",
  "client_cert_path": "agent-device.crt",
  "client_key_path": "agent-device.key",
  "server_spki_pin": "sha256/PASTE_THE_PIN_FROM_PART_1",
  "ca_cert_path": "agent-mitm-ca.crt",
  "ca_key_path": "agent-mitm-ca.key",
  "intercept": ["api.openai.com"],
  "refs": { "cfdt:openai/personal": "openai/personal" }
}
JSON

./bin/confidant-agent -config agent.json -ca-export ./agent-mitm-ca.pem -log-level info
```

The agent mints its local MITM CA on first run and exports it to
`agent-mitm-ca.pem`. Trust that CA for your tool (it signs the localhost TLS the
tool sees; it is unrelated to the broker's identity).

### Part 6 — Run your app credential-free

Point the tool at the agent and give it the **ref**, not a key:

```bash
export HTTPS_PROXY=http://127.0.0.1:8317
export SSL_CERT_FILE="$PWD/agent-mitm-ca.pem"   # trust the agent's MITM CA
export OPENAI_API_KEY="cfdt:openai/personal"    # the inert reference, never a real key

your-app   # e.g. a script that calls api.openai.com
```

The call flows tool → agent → (Tailscale + mTLS) → broker. The broker attests,
unwraps `openai/personal` from KMS, injects the real bearer, calls OpenAI, scrubs
the response, and audits it. Your laptop and your app's environment never hold the
secret. Verify with `gcloud compute instances get-serial-port-output confidant-broker`
(logs are secret-free) — you'll see the request audited, with no key material.

### Hardening notes (known gaps)

- **`TS_AUTHKEY` is passed as enclave metadata.** The spec calls for it to be
  attestation-gated (unwrapped at boot via the same KMS/WIF flow, I-B15); that
  delivery is not yet implemented. Use a short-lived ephemeral key and rotate it.
- **`broker.key` is baked into the image.** For production, generate the broker's
  server key inside the enclave at boot, or deliver it attestation-gated, so it
  never exists outside the TEE.
- **Secret store is baked into the image** as ciphertext; re-enrolling means a
  rebuild and a new pinned digest. A GCS-backed store behind the same `store.Store`
  interface removes that coupling.

## Security note

Never commit key material. `.gitignore` excludes certs/keys (`*.pem`, `*.key`, …),
secret envelopes, dev KEK material, `.env` files, and audit output. Agent config
contains **no secrets** by design; `agent/agent.example.toml` is a safe template.

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE). Each Go
source file carries an `SPDX-License-Identifier: Apache-2.0` header.
