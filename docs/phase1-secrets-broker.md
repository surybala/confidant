# Confidant — Phase 1: The Confidential Secrets Broker

**Status:** Draft for build · **Version:** 0.1 · **Date:** 2026-09-06 · **Owner:** surya
**Shareable page:** https://claude.ai/code/artifact/e2a33dd5-d877-4430-9fcf-1eb98701cddf
**Component specs:** [broker-core.md](./broker-core.md) · [local-agent.md](./local-agent.md)

Take every API key and credential off the laptop. Sensitive calls are made from an
attested GCP enclave that even Google can't read into — untrusted local code can't
steal what was never there.

---

## 00 · What Phase 1 defends against

The adversary is **untrusted code running inside your own trust boundary**: a
malicious or compromised dependency, MCP tool, or CLI that a local agent invokes,
whose goal is to read a secret (`~/.aws/credentials`, `OPENAI_API_KEY`, a GitHub
token) and exfiltrate it.

The single structural defense in Phase 1 is **absence**: the plaintext secret is
never materialized on the local machine. It lives sealed in a Confidential Space
enclave and is only ever joined to an outbound request *inside* that enclave. The
Confidential Computing hardware (AMD SEV-SNP / Intel TDX) additionally removes GCP
itself from the trust boundary and makes the enclave **remotely attestable** — the
KMS key that unwraps your secrets is only released to a workload whose measurement
matches what you published.

> **Scope boundary.** The broker protects secrets from local code. It does *not*
> vet the code you deliberately run inside the enclave, and it can't stop a program
> authorized to call an API from misusing that authorization. Those are Phase 2/3
> concerns (sandboxing + egress policy on the trusted lane). Keeping Phase 1 this
> narrow is what makes it shippable and near-zero-latency.

---

## 01 · Goals & non-goals

**In scope**
- Zero plaintext long-lived secrets on the local host, at rest or in memory.
- Transparent to existing tools — they keep calling the same API endpoints.
- Attestation-gated key release: secrets decrypt only inside the expected workload.
- Added latency indistinguishable from noise on the happy path (< ~40 ms).
- A per-credential allowlist of which hosts/paths each secret may be spent on.
- Full audit log of every credential use, written from inside the enclave.

**Explicitly out (later phases)**
- Offloading arbitrary sensitive *computation* to the TEE (Phase 2).
- Local sandboxing of untrusted tools (Phase 3).
- Automatic classification of "what is sensitive" — Phase 1 is explicit config.
- Protecting against a malicious payload routed *through* the broker on purpose.
- Multi-user / team sharing of the broker.

---

## 02 · Architecture & data flow

Two processes and one hardware boundary. Locally, a **secretless proxy**
(`confidant-agent`) that tools point at. Remotely, the **broker** running in a
**Confidential Space** VM. The broker is the only place a plaintext secret ever
exists, and only for the microseconds it takes to attach it to an outbound request.

```
LOCAL MACHINE (untrusted)              GCP · CONFIDENTIAL SPACE (SEV-SNP)
┌───────────────────────┐             ┌──────────────────────────────────────┐
│  agent / tool         │             │                       ┌────────────┐ │
│  (claude code, libs)  │             │           attest →    │ Cloud KMS  │ │
│         │ HTTP_PROXY   │             │        ┌── unwrap ────│ + WIF pool │ │
│         ▼             │  mTLS/tailnet │        ▼              └────────────┘ │
│  confidant-agent  ────┼── req+ref ──▶│  Broker (enclave)                    │
│  localhost proxy      │             │   1 verify caller (mTLS)              │
│  holds NO secrets,    │◀── response ─┤   2 check spend policy    ┌─────────┐│
│  only credential refs │   (no secret │   3 unwrap secret ───────▶│ External││
│                       │    returns)  │   4 inject + call API ────│  API    ││
└───────────────────────┘             │   5 scrub & audit  ◀───────└─────────┘│
                                       │   plaintext lives ONLY here          │
                                       └──────────────────────────────────────┘
```

The secret crosses no boundary in plaintext. It is unwrapped inside the enclave
against an attestation token and scrubbed after each call.

**Private connectivity (settled).** The broker is **never exposed to the public
internet**. The agent↔broker channel runs entirely over a **Tailscale tailnet**: the
broker binds its listener tailnet-only via embedded `tsnet` (userspace WireGuard,
which fits the non-privileged enclave), and a Tailscale ACL restricts reachability to
`tag:confidant-agent` nodes. **mTLS is retained on top** as a second, independent gate
(app-level device identity), and the tailnet auth key is itself attestation-gated.
Tailscale governs *ingress to the broker* only — egress to the real upstream APIs
stays public and allowlisted. Details in [broker-core.md](./broker-core.md) §2/§7 and
[local-agent.md](./local-agent.md) §2.

---

## 03 · Components

| Component | Runs | Responsibility | Sees plaintext secret? |
|---|---|---|---|
| **confidant-agent** (Rust/Go binary) | Local | Localhost HTTP/HTTPS forward proxy (MITM with a locally-trusted CA) + SOCKS. Recognizes outbound calls to configured hosts, replaces the placeholder credential with a *ref*, forwards the request to the broker over mTLS. | **No** |
| **confidant-broker** (enclave container) | TEE | Terminates mTLS from the agent, authorizes against spend policy, unwraps the secret via KMS, injects it, performs the outbound TLS call, returns the response minus the credential, appends an audit record. | **Yes (ephemeral)** |
| **Cloud KMS + WIF** | GCP | Holds the KEK. Releases unwrap operations only to a principal proven by a Confidential Space attestation token whose image digest / hardware claims match policy. | No (holds KEK only) |
| **Secret store** (GCS or Secret Manager) | GCP | Stores each credential *KMS-envelope-encrypted* at rest, plus its spend-policy metadata. Bucket compromise yields only ciphertext. | No (ciphertext) |
| **confidant enroll** (CLI subcommand) | Local | One-time: encrypts a new secret to the KEK and uploads the envelope + policy. The *only* moment a secret is briefly handled locally. | Once, at enrollment |

---

## 04 · The proxy protocol

**Decision (settled):** M1 uses a **local CA proxy** — transparent to every tool via
`HTTPS_PROXY`, no per-tool wiring. The agent installs a locally-trusted CA so it can
inspect and rewrite outbound requests. (Per-tool base-URL shims may be offered later
as an opt-in for users who don't want to trust a local CA.)

Tools are pointed at the agent with the usual knobs —
`HTTPS_PROXY=http://127.0.0.1:8317`, or AWS/OpenAI base-URL overrides. Where a real
secret would sit, the tool carries a harmless **credential ref**, which the agent
recognizes and the broker resolves.

### Credential ref format

A ref is inert if leaked — it names a secret, it is not one.

```
# what the tool's env holds — safe to sit in a dotfile
OPENAI_API_KEY="cfdt:openai/personal#sk-live"
AWS_ACCESS_KEY_ID="cfdt:aws/dev"

# structure
cfdt:<secret-id>[#<hint>]
      └─ path in the store   └─ optional display hint only
```

### Agent → broker request

The agent forwards the reconstructed request plus the ref and request metadata over
mTLS. It never fills in the secret; it only marks *where* the broker should inject it
and *how* — declared in the secret's policy, not by the caller.

```json
POST /v1/proxy   (mTLS, agent client cert)
{
  "ref": "cfdt:openai/personal",
  "upstream": {
    "method": "POST",
    "url": "https://api.openai.com/v1/chat/completions",
    "headers": { "content-type": "application/json" },
    "body_b64": "eyJtb2RlbCI6..."
  },
  "caller": { "pid": 4821, "exe": "node", "ts": 1757000000 }
}
```

### Broker → agent response

The broker streams back status, safe headers, and body. Any header carrying the
injected credential (or a reflected token) is stripped. The response is byte-for-byte
what the tool expects — the tool has no idea a broker was involved.

**Streaming & latency.** Keep one warm HTTP/2 (or QUIC) mTLS connection from agent to
broker; multiplex all calls over it. SSE / chunked responses (token streams) pass
straight through. The broker keeps a connection pool to popular upstreams. Net added
latency on a warm path is one intra-region-ish RTT, not a cold start.

---

## 04a · Credential lifecycle & the injector interface

Not every credential is attached to a request the same way. Three lifecycles cover
essentially everything worth routing; designing the broker for all three now keeps it
from being retrofitted when the second API turns out not to be a plain bearer token.

| Lifecycle | Stored secret | Per-request work in enclave | State | Examples |
|---|---|---|---|---|
| **Static** | the token string | substitute into header / query | stateless | OpenAI, Anthropic, GitHub PAT, Stripe |
| **Signed** | key id + signing key (+ session token) | compute a signature over the *final* request | stateless | AWS SigV4, GCP HMAC, STS temp creds |
| **OAuth-minted** | refresh token + `client_secret` | ensure a fresh access token (refresh if expired), then inject as bearer | **stateful** — caches the access token; may rewrite the stored refresh token | Google, Microsoft, Slack, any OAuth2 API |

**One interface, three implementations.** The broker resolves the secret, checks
spend policy, then hands off to the credential module named by the policy's
`credential.kind`:

```
// runs inside the enclave, after policy authorization, before egress
CredentialModule.apply(request, secret, ctx) -> outbound_request

  StaticInjector   // template substitution: "Bearer {secret}"
  Sigv4Signer      // full SigV4 over the final canonical request
  OAuth2Minter     // ensure-fresh-token → delegate to StaticInjector(bearer)
```

Static and Signed are **pure per request** — same input, same output, no persistence.
OAuth is **stateful** and needs three things the others don't:

- **Access-token cache** in enclave memory, keyed by secret id, with expiry. Refresh only on miss/expiry.
- **Single-flight refresh** — one refresh at a time per secret; concurrent requests wait on it rather than each hitting the token endpoint (some providers rate-limit or invalidate on concurrent refresh).
- **Rotation write-back** — if the provider returns a *new* refresh token, atomically re-encrypt and persist the new envelope before using it, or the broker locks itself out. This is the only path where the enclave writes secret state outward; treat it as a first-class, audited operation.

Generalized policy `credential` block (replaces the flat `inject` field from §05):

```json
// static
"credential": { "kind": "static",
  "inject": { "type": "header", "name": "authorization",
              "template": "Bearer {secret}" } }

// signed
"credential": { "kind": "sigv4", "service": "s3", "region_from": "host" }

// oauth-minted
"credential": { "kind": "oauth2",
  "token_url": "https://oauth2.googleapis.com/token",
  "client_id": "…apps.googleusercontent.com",
  "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
  "rotates_refresh": true }
```

**Knock-on effects on other sections:**

- **Enrollment (§05)** gains a mode. Static/signed enroll a string via stdin. OAuth enrolls via a one-time browser consent: the local browser obtains the single-use authorization code, hands *only the code* to the broker, and the broker redeems it with `client_secret` at the token endpoint — so even the first refresh token is born inside the enclave.
- **Egress (§07)** must allow each OAuth provider's **token endpoint host** (and any STS/HMAC minting endpoint), not just the API host.
- **Spend policy (§05)** extends naturally: OAuth `scopes` and the SigV4 `service` are themselves constraints on what a driven proxy can do.

---

## 05 · Credential model & config

Each secret is stored as a KMS envelope plus a **spend policy** that constrains what
the credential may be used for — set at enrollment, enforced in the enclave,
immutable to the caller. Even if malicious local code drives the proxy, it can only
spend a credential within its declared envelope.

Policy attached to `cfdt:openai/personal` (stored server-side):

```json
{
  "id": "openai/personal",
  "credential": { "kind": "static",
    "inject": { "type": "header", "name": "authorization",
                "template": "Bearer {secret}" } },
  "allow_hosts": ["api.openai.com"],
  "allow_methods": ["POST", "GET"],
  "rate": { "rpm": 120, "daily_usd_cap": 25 },
  "require_confirm": false,
  "audit": true
}
```

Local `~/.config/confidant/agent.toml` — contains no secrets:

```toml
[broker]
endpoint    = "https://broker.confidant.internal:8443"
# agent authenticates with a device client cert enrolled once
client_cert = "~/.config/confidant/agent.pem"

[proxy]
listen = "127.0.0.1:8317"
# hosts to intercept; everything else is passed through untouched
intercept = ["api.openai.com", "*.amazonaws.com", "api.github.com"]

[refs]
# map inert refs the tools use → secret ids the broker resolves
"cfdt:openai/personal" = "openai/personal"
"cfdt:aws/dev"         = "aws/dev"
```

> **Enrollment is the one local touch.** `confidant enroll openai/personal` reads the
> secret from stdin (never argv), encrypts to the KEK's public material, uploads the
> envelope + policy, and zeroes the buffer. After that the plaintext exists only
> inside the enclave. Treat enrollment as the trust event it is — ideally from a
> clean shell.

---

## 06 · Attestation & key release — the binding

This is the mechanism that makes it "provably the right workload, not a VM I hope is
clean." Confidential Space issues an OIDC **attestation token** whose claims include
the enclave's boot measurement and the *image digest* of the broker container.
Workload Identity Federation mints a GCP principal *only* for tokens matching those
claims, and the KMS key's IAM binding grants `decrypt` *only* to that principal.

WIF attribute condition (release only to the blessed image):

```
// only a genuine Confidential Space enclave running
// exactly this broker image can assume the identity
assertion.swname == "CONFIDENTIAL_SPACE" &&
"STABLE" in assertion.submods.confidential_space.support_attributes &&
assertion.submods.container.image_digest ==
    "sha256:9f2c…<pinned broker digest>"
```

- **Stolen envelope:** useless — it only unwraps against a live attestation token.
- **Tampered broker image:** the digest claim no longer matches; KMS refuses; nothing decrypts.
- **GCP-operator snooping:** memory is hardware-encrypted (SEV-SNP); the operator sees ciphertext.
- **Rotation:** ship a new broker digest → update the WIF condition → old image loses key access automatically.

---

## 07 · Egress control

The enclave holds live credentials, so its own outbound reach is constrained
independently of the per-secret policy — belt and suspenders. The broker VM sits
behind a VPC egress firewall / Cloud NAT with an **allowlist** of upstream API
domains. A request whose `allow_hosts` somehow passed but whose destination isn't in
the network allowlist still cannot leave.

- Default-deny egress; allow only the union of every secret's `allow_hosts`.
- DNS pinned / resolved inside the enclave to defeat rebinding to an allowed name.
- No inbound except the mTLS proxy port; no SSH (Confidential Space is immutable and non-interactive by design).

---

## 08 · Security properties & residual risk

**Properties gained**
- **No local secret** — plaintext credentials never touch disk or process memory on the host after enrollment.
- **Bounded spend** — a driven proxy can only use a credential within its host / method / rate / cost envelope.
- **Provider-opaque** — SEV-SNP memory encryption keeps GCP out of the plaintext path; attestation proves the workload.

**Residual risk**
- `RESIDUAL` — **Confused-deputy within policy.** Malicious local code can still *make* allowed calls (run up your OpenAI bill, read a repo the GitHub token can read). Mitigated, not eliminated, by tight `allow_hosts`, rate/cost caps, and `require_confirm` on high-value secrets — full fix is the Phase 3 sandbox.
- `RESIDUAL` — **Response-channel exfiltration.** The response returns to untrusted local code, so a credential that can *read* sensitive data (an email API) hands that data back locally. Phase 1 protects the *key*, not necessarily the data it fetches. Route such computations wholly to the TEE in Phase 2.
- `RESIDUAL` — **Enrollment-time capture.** The one window where plaintext is local. Enroll from a clean environment; support hardware-token / OAuth-device enrollment later to close this.
- `OUT OF SCOPE` — **Compromise inside the enclave.** A bug in the broker itself runs with access to whatever secret is in flight. Keep the broker's trusted computing base tiny, dependency-pinned, and reproducible; this is why the image digest is the attestation anchor.

---

## 09 · Build milestones (~3 weeks)

- **M1 · Broker core, no TEE yet (~4 days).** Broker as a plain container: mTLS in, envelope-decrypt with a local dev KEK, inject + proxy one upstream (OpenAI), scrub + audit. Prove the request/response path end to end against a stub client.
- **M2 · The local agent (~4 days).** Forward proxy with local CA, ref recognition and rewriting, warm mTLS connection to the broker, config loading. Point real `claude code` / `curl` at it and watch a call succeed with no local key.
- **M3 · Confidential Space + attestation (~5 days).** Deploy the broker image to Confidential Space; wire WIF + KMS with the image-digest condition; move envelopes to GCS. Verify a tampered digest is refused decryption. This is the milestone that makes it real.
- **M4 · Policy, egress, ergonomics (~4 days).** Spend policy enforcement (hosts, rate, cost caps), VPC egress allowlist, `confidant enroll` (string + OAuth-consent modes), audit log surface, and the credential modules beyond static bearer — the SigV4 signer and the OAuth2 minter (§04a). Dogfood for a week on your own keys.

**Broker uptime (settled):** an **always-warm Confidential VM**. A few dollars/day
idle buys an instant path — one persistent mTLS connection, no per-call enclave boot
or attestation cost.

---

## 10 · Open questions to settle before M1

- **SigV4 & request signing.** AWS signs the whole request, so the broker must sign *after* injection — the agent must forward an unsigned canonical request. Confirm every intended upstream's auth scheme is injectable server-side.
- **Confirmation UX.** For `require_confirm` secrets, where does the prompt surface — a local notification from the agent, signed by the broker challenge?
- **Audit sink.** Keep the log inside GCP (tamper-evident, but GCP-visible metadata) or stream it back to a local append-only store?

_Resolved:_ interception method → local CA proxy (§04); broker uptime → always-warm VM (§09).

---

*Next: Phase 2 — annotate-and-offload confidential execution.*
