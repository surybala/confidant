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
local **dev** path and the GCP **enclave** unwrap path are implemented; see
[Running for real](#running-for-real) to use the enclave broker.

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

## Running for Real

This is the full credential-free path: a tool on your laptop makes an
authenticated API call while the real key exists **only** inside an attested GCP
Confidential Space workload.

```
your app ──HTTPS_PROXY──▶ confidant-agent ──mTLS over Tailscale──▶ confidant-proxy
 (holds a "cfdt:" ref)      (your laptop)                          (GCP Confidential Space)
                                                                     │ attest → Cloud KMS
                                                                     │ unwrap secret, inject
                                                                     ▼ call the real upstream
```

Two gates protect the agent→broker channel (invariant I-B14): the **Tailscale
ACL** (network identity) and **mTLS** (device identity). Cloud KMS unwrap only
succeeds under a live Confidential Space attestation that matches the pinned
image digest (I-B6).

### Setup

Prerequisites:

- A GCP project with billing.
- `gcloud` authenticated with `gcloud auth login`.
- Docker with Buildx, `openssl`, Go 1.22+, and Tailscale.
- A Tailscale tailnet with MagicDNS enabled.

Start at the repo root and export deployment variables once. Edit only this
block; the commands below are copy-pasteable after that.

```bash
export PROJECT_ID="your-gcp-project-id"
export REGION="us-central1"
export ZONE="us-central1-a"

export KMS_LOCATION="global"
export KMS_KEYRING="confidant"
export KMS_KEY_NAME="broker-kek"
export WIF_LOCATION="global"
export WIF_POOL="confidant-pool"
export WIF_PROVIDER="confidant-provider"
export BROKER_SA_NAME="confidant-broker"
export BROKER_INSTANCE="confidant-broker"
export BROKER_TS_TAG="tag:confidant-broker"
export AGENT_TS_TAG="tag:confidant-agent"
export AR_REPOSITORY="confidant"
export IMAGE_NAME="confidant-proxy"
export EGRESS_ALLOW="api.openai.com"
export SECRET_REF_ID="openai/personal"
export SECRET_HOST="api.openai.com"
export SECRET_METHODS="GET,POST"

export TAILNET_DNS="$(tailscale status --json | python3 -c 'import json,sys; s=json.load(sys.stdin); print((s.get("CurrentTailnet") or {}).get("MagicDNSSuffix") or s.get("MagicDNSSuffix") or "")')"
if [ -z "${TAILNET_DNS}" ]; then
    echo "TAILNET_DNS is empty; enable Tailscale MagicDNS or set your tailnet DNS suffix manually" >&2
    exit 1
fi

gcloud config set project "${PROJECT_ID}"

export PROJECT_NUMBER="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')"
export OPERATOR_ACCOUNT="$(gcloud config get-value account)"
export BROKER_SA="${BROKER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
export KMS_KEY_RESOURCE="projects/${PROJECT_ID}/locations/${KMS_LOCATION}/keyRings/${KMS_KEYRING}/cryptoKeys/${KMS_KEY_NAME}"
export WIF_AUDIENCE="//iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/${WIF_LOCATION}/workloadIdentityPools/${WIF_POOL}/providers/${WIF_PROVIDER}"
export IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPOSITORY}/${IMAGE_NAME}"
```

Enable APIs:

```bash
gcloud services enable cloudkms.googleapis.com iamcredentials.googleapis.com \
    sts.googleapis.com artifactregistry.googleapis.com compute.googleapis.com \
    confidentialcomputing.googleapis.com
```

Create the enrollment CA, this laptop's mTLS device cert, and the broker server
cert. The broker trusts the enrollment CA; the local agent pins the broker
server certificate's public key.

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout enroll-ca.key -out enroll-ca.pem -days 3650 -subj "/CN=Confidant Enrollment CA"

openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout agent-device.key -out agent-device.csr -subj "/CN=my-laptop"
openssl x509 -req -in agent-device.csr -CA enroll-ca.pem -CAkey enroll-ca.key \
    -CAcreateserial -out agent-device.crt -days 825

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout broker.key -out broker.crt -days 825 -subj "/CN=${BROKER_INSTANCE}"

export BROKER_SPKI_PIN="$(printf 'sha256/'; openssl x509 -in broker.crt -pubkey -noout \
    | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary | base64)"
printf '%s\n' "${BROKER_SPKI_PIN}"
```

Create KMS, IAM, and a deny-all Workload Identity provider. The provider is
repinned after the image digest exists.

```bash
gcloud kms keyrings create "${KMS_KEYRING}" --location="${KMS_LOCATION}"
gcloud kms keys create "${KMS_KEY_NAME}" \
    --keyring="${KMS_KEYRING}" --location="${KMS_LOCATION}" --purpose=encryption

gcloud iam service-accounts create "${BROKER_SA_NAME}" --display-name="Confidant broker"

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${BROKER_SA}" \
    --role=roles/confidentialcomputing.workloadUser

gcloud kms keys add-iam-policy-binding "${KMS_KEY_NAME}" \
    --keyring="${KMS_KEYRING}" --location="${KMS_LOCATION}" \
    --member="serviceAccount:${BROKER_SA}" \
    --role=roles/cloudkms.cryptoKeyDecrypter

gcloud iam workload-identity-pools create "${WIF_POOL}" --location="${WIF_LOCATION}"

gcloud iam workload-identity-pools providers create-oidc "${WIF_PROVIDER}" \
    --location="${WIF_LOCATION}" --workload-identity-pool="${WIF_POOL}" \
    --issuer-uri="https://confidentialcomputing.googleapis.com/" \
    --attribute-mapping="google.subject=assertion.sub,attribute.image_digest=assertion.submods.container.image_digest" \
    --attribute-condition="false"
```

Enroll the secret. `store.json` contains ciphertext only, but it is baked into
the broker image and must be restaged before every image build.

```bash
gcloud kms keys add-iam-policy-binding "${KMS_KEY_NAME}" \
    --keyring="${KMS_KEYRING}" --location="${KMS_LOCATION}" \
    --member="user:${OPERATOR_ACCOUNT}" --role=roles/cloudkms.cryptoKeyEncrypter

make build
printf 'Secret value to enroll for %s: ' "${SECRET_REF_ID}"
IFS= read -r SECRET_VALUE
printf '%s' "${SECRET_VALUE}" | GOOGLE_ACCESS_TOKEN="$(gcloud auth print-access-token)" \
    ./bin/confidant-proxy enroll \
        -id "${SECRET_REF_ID}" \
        -kms-key "${KMS_KEY_RESOURCE}" \
        -store store.json -host "${SECRET_HOST}" -methods "${SECRET_METHODS}"
unset SECRET_VALUE
```

### Deploy Broker

#### Runtime IAM

Create the Artifact Registry repo and grant the VM service account the runtime
permissions it needs. The image pull grant is required; log writer is strongly
recommended because Confidential Space launcher failures are otherwise easiest
to find on the serial console.

```bash
gcloud artifacts repositories create "${AR_REPOSITORY}" \
    --repository-format=docker --location="${REGION}"
gcloud auth configure-docker "${REGION}-docker.pkg.dev"

gcloud artifacts repositories add-iam-policy-binding "${AR_REPOSITORY}" \
    --location="${REGION}" \
    --member="serviceAccount:${BROKER_SA}" \
    --role=roles/artifactregistry.reader

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${BROKER_SA}" \
    --role=roles/logging.logWriter
```

#### Build and Push Image

Build and push the broker image. The certs, key, enrollment CA, and store must
be copied into `proxy/deploy/` **before** the build, because the Dockerfile bakes
that directory into `/deploy/`. Use Buildx and `linux/amd64` for Confidential
Space, including on Apple Silicon.

```bash
cp broker.crt broker.key enroll-ca.pem store.json proxy/deploy/

for f in \
    proxy/deploy/entrypoint.sh \
    proxy/deploy/broker.crt \
    proxy/deploy/broker.key \
    proxy/deploy/enroll-ca.pem \
    proxy/deploy/store.json; do
    if [ ! -s "$f" ]; then
        echo "missing required deploy input: $f" >&2
        exit 1
    fi
done

export IMAGE_TAG="v$(date -u +%Y%m%d%H%M%S)"

docker buildx build --platform linux/amd64 --no-cache --pull --load \
    -t "${IMAGE}:${IMAGE_TAG}" proxy/

docker image inspect "${IMAGE}:${IMAGE_TAG}" --format '{{.Os}}/{{.Architecture}}'
docker image inspect "${IMAGE}:${IMAGE_TAG}" \
    --format '{{ index .Config.Labels "tee.launch_policy.allow_env_override" }}'
if ! docker run --rm --platform linux/amd64 --entrypoint /bin/sh "${IMAGE}:${IMAGE_TAG}" -c \
    'test -s /deploy/broker.crt && test -s /deploy/broker.key && test -s /deploy/enroll-ca.pem && test -s /deploy/store.json'; then
    echo "image is missing baked deploy files; rebuild before pushing" >&2
    exit 1
fi

docker push "${IMAGE}:${IMAGE_TAG}"
export IMAGE_REF="$(docker inspect --format='{{index .RepoDigests 0}}' "${IMAGE}:${IMAGE_TAG}")"
export IMAGE_DIGEST="${IMAGE_REF##*@}"
printf 'IMAGE_REF=%s\nIMAGE_DIGEST=%s\n' "${IMAGE_REF}" "${IMAGE_DIGEST}"
```

#### Pin WIF

Pin Workload Identity Federation to the immutable digest and the
security-critical KMS env values.

```bash
test -n "${IMAGE_REF}"
test -n "${IMAGE_DIGEST}"

gcloud iam workload-identity-pools providers update-oidc "${WIF_PROVIDER}" \
    --location="${WIF_LOCATION}" --workload-identity-pool="${WIF_POOL}" \
    --attribute-condition="assertion.swname=='CONFIDENTIAL_SPACE' && 'STABLE' in assertion.submods.confidential_space.support_attributes && assertion.submods.container.image_digest=='${IMAGE_DIGEST}' && assertion.submods.container.image_reference=='${IMAGE_REF}' && assertion.submods.gce.project_number=='${PROJECT_NUMBER}' && '${BROKER_SA}' in assertion.google_service_accounts && assertion.submods.container.env['KMS_KEY']=='${KMS_KEY_RESOURCE}' && assertion.submods.container.env['WIF_AUDIENCE']=='${WIF_AUDIENCE}' && assertion.submods.container.env['KMS_SERVICE_ACCOUNT']=='${BROKER_SA}'"

gcloud iam service-accounts add-iam-policy-binding "${BROKER_SA}" \
    --role=roles/iam.workloadIdentityUser \
    --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/${WIF_LOCATION}/workloadIdentityPools/${WIF_POOL}/attribute.image_digest/${IMAGE_DIGEST}"
```

#### Create VM

Mint a **single-use, ephemeral, tagged** Tailscale auth key in the Tailscale admin
console with tag `${BROKER_TS_TAG}`, then create the Confidential Space VM.

```bash
printf 'Tailscale auth key for %s: ' "${BROKER_INSTANCE}"
IFS= read -r TS_AUTHKEY
export TS_AUTHKEY

gcloud compute instances create "${BROKER_INSTANCE}" --zone="${ZONE}" \
    --confidential-compute-type=SEV --shielded-secure-boot --maintenance-policy=TERMINATE \
    --image-project=confidential-space-images --image-family=confidential-space \
    --service-account="${BROKER_SA}" --scopes=cloud-platform \
    --metadata="^~^tee-image-reference=${IMAGE_REF}~tee-container-log-redirect=true~tee-env-KMS_KEY=${KMS_KEY_RESOURCE}~tee-env-WIF_AUDIENCE=${WIF_AUDIENCE}~tee-env-KMS_SERVICE_ACCOUNT=${BROKER_SA}~tee-env-EGRESS_ALLOW=${EGRESS_ALLOW}~tee-env-SECRET_STORE=/deploy/store.json~tee-env-TLS_CERT=/deploy/broker.crt~tee-env-TLS_KEY=/deploy/broker.key~tee-env-CLIENT_CA=/deploy/enroll-ca.pem~tee-env-TS_HOSTNAME=${BROKER_INSTANCE}~tee-env-TS_TAGS=${BROKER_TS_TAG}~tee-env-TS_AUTHKEY=${TS_AUTHKEY}"
```

#### Tailscale ACL

Configure the Tailscale ACL so only tagged agents can reach the broker:

```bash
cat <<JSON
{
  "tagOwners": { "${AGENT_TS_TAG}": ["autogroup:admin"], "${BROKER_TS_TAG}": ["autogroup:admin"] },
  "acls": [
    { "action": "accept", "src": ["${AGENT_TS_TAG}"], "dst": ["${BROKER_TS_TAG}:8443"] }
  ]
}
JSON
```

### Run Agent

Join your laptop to the tailnet as an agent, write the secretless local config,
and start the loopback proxy.

```bash
tailscale up --advertise-tags="${AGENT_TS_TAG}"

cat > agent.json <<JSON
{
  "listen": "127.0.0.1:8317",
  "broker_endpoint": "https://${BROKER_INSTANCE}.${TAILNET_DNS}:8443",
  "client_cert_path": "agent-device.crt",
  "client_key_path": "agent-device.key",
  "server_spki_pin": "${BROKER_SPKI_PIN}",
  "ca_cert_path": "agent-mitm-ca.crt",
  "ca_key_path": "agent-mitm-ca.key",
  "intercept": ["${SECRET_HOST}"],
  "refs": { "cfdt:${SECRET_REF_ID}": "${SECRET_REF_ID}" }
}
JSON

./bin/confidant-agent -config agent.json -ca-export ./agent-mitm-ca.pem -log-level info
```

The agent mints a local MITM CA on first run and exports it to
`agent-mitm-ca.pem`; your tool must trust that CA. The local app environment gets
only the inert ref:

```bash
export HTTPS_PROXY=http://127.0.0.1:8317
export SSL_CERT_FILE="$PWD/agent-mitm-ca.pem"
export OPENAI_API_KEY="cfdt:${SECRET_REF_ID}"
```

### Testing

First verify the broker is reachable over Tailscale + mTLS:

```bash
tailscale ping "${BROKER_INSTANCE}.${TAILNET_DNS}"
curl -sk --cert agent-device.crt --key agent-device.key \
    "https://${BROKER_INSTANCE}.${TAILNET_DNS}:8443/healthz"
```

The health check should print `ok`.

For an OpenAI text-to-speech smoke test, send a tiny speech request through the
agent. This matches a restricted key that only has text-to-voice permission.

```bash
export HTTPS_PROXY=http://127.0.0.1:8317
export SSL_CERT_FILE="$PWD/agent-mitm-ca.pem"
export OPENAI_API_KEY="cfdt:${SECRET_REF_ID}"

curl -sS https://api.openai.com/v1/audio/speech \
    -H "Authorization: Bearer ${OPENAI_API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
      "model": "gpt-4o-mini-tts",
      "voice": "alloy",
      "input": "Confidant text to speech test succeeded.",
      "response_format": "mp3"
    }' \
    -o confidant-tts-test.mp3 \
    -w "http_code=%{http_code} content_type=%{content_type} size=%{size_download}\n"

file confidant-tts-test.mp3
ls -lh confidant-tts-test.mp3
```

A `200` response with `audio/mpeg` proves the full path: local app → agent →
Tailscale + mTLS → broker → KMS unwrap → OpenAI. If OpenAI returns a missing
scope error, Confidant still reached OpenAI; update the restricted key scopes, or
re-enroll and rebuild if you replace the key value.

To inspect broker-side audit:

```bash
gcloud compute instances get-serial-port-output "${BROKER_INSTANCE}" \
    --zone="${ZONE}" --port=1
```

Broker request/audit logs should not contain API key material, but Confidential
Space launcher diagnostics can include attestation claims with container env
values. Do not copy launcher logs that contain sensitive env values.

### Rebuild and Replace

Rebuild whenever broker code, `proxy/deploy/entrypoint.sh`, certs/keys, or
`store.json` change. Because the image digest is part of the WIF condition, every
new image must be pushed, repinned, and deployed by digest.

1. Run [Build and Push Image](#build-and-push-image) again. It restages
   `/deploy`, builds `linux/amd64`, verifies the baked files and launch-policy
   labels, pushes, and exports `IMAGE_REF` / `IMAGE_DIGEST`.
2. Run [Pin WIF](#pin-wif) again so KMS trusts the new immutable digest.
3. Mint a fresh single-use Tailscale auth key and replace the VM:

```bash
printf 'Tailscale auth key for %s: ' "${BROKER_INSTANCE}"
IFS= read -r TS_AUTHKEY
export TS_AUTHKEY

gcloud compute instances delete "${BROKER_INSTANCE}" --zone="${ZONE}" --quiet

gcloud compute instances create "${BROKER_INSTANCE}" --zone="${ZONE}" \
    --confidential-compute-type=SEV --shielded-secure-boot --maintenance-policy=TERMINATE \
    --image-project=confidential-space-images --image-family=confidential-space \
    --service-account="${BROKER_SA}" --scopes=cloud-platform \
    --metadata="^~^tee-image-reference=${IMAGE_REF}~tee-container-log-redirect=true~tee-env-KMS_KEY=${KMS_KEY_RESOURCE}~tee-env-WIF_AUDIENCE=${WIF_AUDIENCE}~tee-env-KMS_SERVICE_ACCOUNT=${BROKER_SA}~tee-env-EGRESS_ALLOW=${EGRESS_ALLOW}~tee-env-SECRET_STORE=/deploy/store.json~tee-env-TLS_CERT=/deploy/broker.crt~tee-env-TLS_KEY=/deploy/broker.key~tee-env-CLIENT_CA=/deploy/enroll-ca.pem~tee-env-TS_HOSTNAME=${BROKER_INSTANCE}~tee-env-TS_TAGS=${BROKER_TS_TAG}~tee-env-TS_AUTHKEY=${TS_AUTHKEY}"
```

Single-use ephemeral Tailscale auth keys are expected to show as invalidated
after a successful join. That does not break a currently running broker, but
this image uses `--state=mem:`, so every VM/container restart needs a fresh auth
key in metadata.

```bash
printf 'New Tailscale auth key for %s: ' "${BROKER_INSTANCE}"
IFS= read -r TS_AUTHKEY
export TS_AUTHKEY

gcloud compute instances add-metadata "${BROKER_INSTANCE}" \
    --zone="${ZONE}" \
    --metadata="tee-env-TS_AUTHKEY=${TS_AUTHKEY}"
```

### Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `failed to fetch oauth token: 403 Forbidden` while pulling the image | VM service account cannot read Artifact Registry | Grant `roles/artifactregistry.reader` on the repository to `${BROKER_SA}` |
| `confidentialcomputing.locations.list` denied | VM service account lacks Confidential Space workload permissions | Grant `roles/confidentialcomputing.workloadUser` on the project |
| `env var ... is not allowed to be overridden on this image` | Image was built without `tee.launch_policy.allow_env_override` labels | Rebuild with the current Dockerfile, push, repin WIF, and redeploy |
| `logging.logEntries.create denied` | Log redirect is enabled but the VM service account cannot write logs | Grant `roles/logging.logWriter`, or read serial-console output |
| `lookup confidant-broker.<tailnet>: no such host` | Broker did not join Tailscale, wrong `TAILNET_DNS`, or MagicDNS disabled | Check serial output, confirm `${TAILNET_DNS}`, then retry after fixing launcher errors |
| Agent returns `broker_unreachable` | Agent config points at the wrong broker endpoint, broker is down, or Tailscale ACL blocks it | Check `agent.json`, broker `/healthz`, and Tailscale ACLs |

Useful checks:

```bash
gcloud compute instances describe "${BROKER_INSTANCE}" \
    --zone="${ZONE}" \
    --format='value(status,lastStartTimestamp,lastStopTimestamp)'

gcloud compute instances get-serial-port-output "${BROKER_INSTANCE}" \
    --zone="${ZONE}" --port=1

tailscale ping "${BROKER_INSTANCE}.${TAILNET_DNS}"

curl -sk --cert agent-device.crt --key agent-device.key \
    "https://${BROKER_INSTANCE}.${TAILNET_DNS}:8443/healthz"
```

### Hardening Notes

- **`TS_AUTHKEY` is passed as enclave metadata.** The intended production shape is
  attestation-gated delivery, unwrapped at boot via the same KMS/WIF flow
  (I-B15). Until then, use single-use ephemeral keys, rotate after debugging, and
  avoid sharing serial-console or launcher logs.
- **`broker.key` is baked into the image.** For production, generate the broker's
  server key inside the enclave at boot, or deliver it attestation-gated, so it
  never exists outside the TEE.
- **`store.json` is baked into the image** as ciphertext. Re-enrolling or
  replacing a secret means restaging the store, rebuilding, pushing, and repinning
  a new image digest. A GCS-backed store behind the same `store.Store` interface
  would remove that coupling.

## Security note

Never commit key material. `.gitignore` excludes certs/keys (`*.pem`, `*.key`, …),
secret envelopes, dev KEK material, `.env` files, and audit output. Agent config
contains **no secrets** by design; `agent/agent.example.toml` is a safe template.

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE). Each Go
source file carries an `SPDX-License-Identifier: Apache-2.0` header.
