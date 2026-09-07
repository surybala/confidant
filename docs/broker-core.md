# Confidant — Broker Core Spec

**Component:** `confidant-broker` · **Phase:** 1 · **Version:** 0.1 · **Date:** 2026-09-06
**Parent spec:** [phase1-secrets-broker.md](./phase1-secrets-broker.md) · **Peer:** [local-agent.md](./local-agent.md)

The broker is the **only place a plaintext secret ever exists**. It runs inside a GCP
Confidential Space enclave, terminates mTLS from the local agent, authorizes each
request against stored policy, unwraps the relevant secret via attestation-gated KMS,
attaches it to the outbound call, scrubs the response, and audits the operation.

If a single sentence has to survive: **the broker fails closed, injection authority
lives only in stored policy, and no secret ever leaves the enclave in any form.**

> **Implementation status (2026-09-07).** The `/v1/proxy` pipeline, both the local
> **dev** unwrapper (dev KEK) and the **enclave** unwrapper (attestation-gated Cloud
> KMS + Workload Identity Federation, behind a cloud-provider abstraction with GCP
> as the default), enrollment sealing for both with versioned AEAD associated-data
> binding, mTLS, egress allowlist, response
> scrubbing, and the hash-chained audit are **implemented and tested**. `CONFIDANT_MODE=enclave`
> now runs. Two design points diverge from or lag this spec and are noted inline:
> the tailnet listener uses a **userspace `tailscaled` + `tailscale serve`** sidecar
> in the enclave container rather than embedded `tsnet` (§2/§4), and the tailnet
> auth key is currently passed as enclave metadata rather than being
> **attestation-gated** (I-B15, §11). Plaintext secret caching, SigV4/OAuth2
> modules, and a GCS-backed store remain unimplemented and fail closed.

---

## 1 · Responsibilities

1. **Terminate + authenticate** the mTLS connection from `confidant-agent`.
2. **Parse** the proxy request: `ref`, `upstream` (method/url/headers/body), `caller` metadata.
3. **Resolve** `ref` → stored envelope + spend policy (broker is the authority, not the agent).
4. **Authorize** the request against policy *before any secret material is touched*.
5. **Unwrap** the secret: KMS-decrypt the wrapped DEK (attestation-gated), then AES-GCM-decrypt the secret.
6. **Apply the credential module** named by `credential.kind` — static inject / SigV4 sign / OAuth2 mint.
7. **Egress** the outbound TLS call to the real upstream, subject to the network allowlist.
8. **Scrub** the response of any credential-bearing or reflected-auth headers.
9. **Stream** status/headers/body back to the agent.
10. **Audit** the operation exactly once (allowed or denied), with outcome and no secret material.
11. **Maintain OAuth state**: access-token cache, single-flight refresh, refresh-token rotation write-back.

**Not the broker's job (Phase 1):** classifying what is sensitive, sandboxing caller
code, offloading arbitrary computation, multi-tenant isolation. See parent spec §01.

---

## 2 · Security decisions

**Execution environment**
- Runs in **GCP Confidential Space** (AMD SEV-SNP), immutable and **non-interactive** — no SSH, no shell, no debug endpoint in production. Memory is hardware-encrypted; the GCP operator sees only ciphertext.
- The container image is **reproducible** and **pinned by digest**. The digest is the attestation anchor (see §5). Base image is distroless / minimal to keep the trusted computing base (TCB) small.
- **Dependencies are pinned** (lockfile committed, no floating versions) and the dependency tree is deliberately small. Every dependency is part of the TCB.
- **No dynamic code loading.** Credential modules are compiled in; there is no plugin path an attacker could populate.

**Secret handling**
- Plaintext secrets and DEKs exist only inside the enclave process. Mutable buffers are wiped as soon as practical after use, but the Go prototype cannot honestly promise that a credential never enters a `string`: static header/query injection and the TLS/runtime stack create transient in-enclave copies.
- Envelope ciphertext is authenticated against versioned associated data derived from the record id, algorithm, KMS key resource, and stored spend policy. The broker can still authorize before unwrap because policy remains plaintext, but policy/id/key tampering fails closed at decrypt time.
- **No plaintext static/signed secret cache in the current Go prototype.** Add caching only behind an explicit cache object with TTL, eviction, and best-effort wipe semantics. OAuth access tokens may later be held to their real expiry because they are operational state, not long-lived enrollment secrets.
- Secrets, DEKs, KEK handles, refresh/access tokens **never** appear in logs, audit records, metrics, error messages, stack traces, or responses. This is enforced by a redaction layer and by avoiding secret-bearing fields in observability records.
- **Authorize before unwrap.** Policy authorization completes before KMS is ever called; a denied request never triggers a decrypt. (Invariant I-B5.)

**Network**
- **Default-deny egress.** The enclave's VPC egress firewall / Cloud NAT allows only the union of every secret's `allow_hosts` plus OAuth token endpoints and any minting endpoints (STS/KMS). See §7 and parent §07.
- **DNS resolved/pinned inside the enclave** to defeat rebinding of an allowlisted name to an attacker IP.
- **Upstream TLS is verified** (real CA chain). High-value secrets may additionally **pin** the upstream cert/SPKI in policy.

**Private connectivity (no public ingress)**
- The `/v1/proxy` listener is reachable only over the **Tailscale tailnet**, never a public interface (invariant I-B13). *Implemented approach:* the broker binds a **loopback** listener (`127.0.0.1`), and a **userspace `tailscaled`** (`--tun=userspace-networking`, which fits the non-interactive Confidential Space enclave with no TUN device or privileged daemon) forwards inbound tailnet TCP to it via `tailscale serve`, preserving the broker's own mTLS end to end. Enclave config validation refuses a wildcard bind (`0.0.0.0`/`::`) so the broker can never be exposed on a public interface. Embedding **`tsnet`** directly is the originally-specced alternative and remains open (§11); the loopback-plus-sidecar form was chosen to keep the broker dependency tree (its TCB) stdlib-only.
- **Two independent gates on the agent → broker channel.** Tailscale supplies the encrypted transport and the *network* identity, governed by an **ACL** that lets only `tag:confidant-agent` nodes reach `tag:confidant-broker` on the proxy port. **mTLS is retained on top** as the *application-level* device identity, so the channel still fails closed if an ACL is ever misconfigured — **both gates must pass** (I-B14). The broker's TLS identity is its own enrolled cert (agent pins its SPKI), *not* a Tailscale-provisioned cert.
- The broker joins the tailnet as an **ephemeral, tagged** node — it auto-deregisters when the enclave stops and gets a fresh identity per deploy. The **tailnet auth key should be attestation-gated** (released to the enclave through the same KMS/WIF flow and unwrapped at boot), so a non-attested image cannot obtain a key and impersonate the broker node (I-B15). *Current status:* **not yet implemented** — the key is supplied as a short-lived, ephemeral, tagged Confidential Space metadata value (`TS_AUTHKEY`); gating it through KMS/WIF at boot is the remaining hardening step.
- The agent addresses the broker by **MagicDNS** name (e.g. `confidant-broker.<tailnet>.ts.net`), never a public IP.

**Request authority**
- The **injection/signing scheme is taken solely from stored policy**, never from the request. A request that tries to specify how its credential should be attached is ignored. (Invariant I-B2.)
- **Body-size limit** and **request timeout** on every proxied call; concurrency cap per secret; these bound resource-exhaustion from a driven proxy.

**Fail-closed everywhere**
- Any failure in attestation, KMS, policy load, module application, or egress resolution results in **denial**. The broker never falls back to sending a request without proper auth, with a stale token, or to an unverified destination. (Invariant I-B8.)

---

## 3 · Configuration

Two tiers, split by whether the value is security-relevant:

**Measured config (baked into the attested image)** — anything whose change should
invalidate trust:
- KMS key resource name (KEK) and the expected WIF provider.
- The credential-module set (compiled in).
- Default-deny egress posture.

**Operational config (env / Confidential Space metadata)** — non-security tunables:

| Key | Default | Meaning |
|---|---|---|
| `CONFIDANT_MODE` | `dev` | `dev` enables local file-store/dev-KEK seams; `enclave` uses the attestation-gated KMS unwrapper and refuses a wildcard bind. Both modes are implemented |
| `BROKER_LISTEN` | `:8443` | mTLS listener address; in `enclave` mode set to a **loopback** address (`127.0.0.1:8443`) fronted by the Tailscale sidecar. A wildcard bind is rejected in enclave mode |
| `KMS_PROVIDER` | `gcp` | cloud KMS provider for `enclave` mode (`gcp` implemented; the `kms.KeyDecryptor` seam accepts others) |
| `KMS_KEY` | — | KEK resource name, e.g. `projects/P/locations/global/keyRings/R/cryptoKeys/K` (required in enclave mode) |
| `WIF_AUDIENCE` | — | Workload Identity Federation STS audience, `//iam.googleapis.com/…/providers/PROV` (required in enclave mode) |
| `ATTESTATION_AUDIENCE` | derived | audience requested in the attestation token; defaults to the WIF provider URL |
| `KMS_SERVICE_ACCOUNT` | — | required service account to impersonate after the STS exchange; KMS `decrypt` is granted only to this SA, and WIF policy must prove the expected workload may impersonate it |
| `SECRET_STORE` | `gcs://…` | envelope + policy store location |
| `SECRET_CACHE_TTL` | `0` | plaintext cache TTL; disabled until cache wipe/eviction semantics are implemented |
| `MAX_BODY_BYTES` | `16MiB` | per-request body cap |
| `UPSTREAM_TIMEOUT` | `30s` | per-call upstream timeout |
| `PER_SECRET_CONCURRENCY` | `32` | in-flight cap per secret id |
| `LOG_LEVEL` | `info` | never `debug` in prod (redaction still applies) |
| `AUDIT_SINK` | `gcs-append` | audit destination (see §9) |
| `TS_AUTHKEY` | — | tailnet join key — an **attestation-gated secret** in prod (plain env only in dev) |
| `TS_HOSTNAME` | `confidant-broker` | node name; drives the MagicDNS address |
| `TS_TAGS` | `tag:confidant-broker` | ACL tag(s) applied to the ephemeral node |

`GCP_STS_ENDPOINT`, `GCP_KMS_ENDPOINT`, and `GCP_IAMCREDENTIALS_ENDPOINT` are
test/staging seams only and are rejected in `CONFIDANT_MODE=enclave`.

**Agent identity trust:** the broker verifies agent client certs against a pinned
enrollment CA / an allowlist of enrolled device cert fingerprints (measured config or
a signed enrollment list — see Open Questions).

---

## 4 · Auth scheme

| Hop | Mechanism | Notes |
|---|---|---|
| agent → broker | **mTLS over Tailscale** (userspace `tailscaled` + `tailscale serve` → loopback broker) | **two gates:** Tailscale ACL restricts reachability to `tag:confidant-agent` (network identity), and mTLS verifies the enrolled device client cert (app identity). Broker pins the enrollment CA / fingerprint allowlist; agent pins the broker's server-cert SPKI. No public listener exists |
| broker → KMS | **Workload Identity Federation** via Confidential Space attestation token *(implemented — `internal/kms/gcp`)* | attestation token → STS token-exchange → required SA impersonation → Cloud KMS `decrypt`. WIF condition binds the mintable principal to `swname==CONFIDENTIAL_SPACE`, `STABLE`, the pinned image digest/reference, expected project, expected workload service account, and security-critical env values; KMS `decrypt` IAM is granted only to the impersonated SA |
| broker → upstream | the **credential module** output (bearer / SigV4 / OAuth bearer) | broker verifies upstream TLS; optional SPKI pin per policy |

The mTLS client identity is the agent's *device* identity, not a user secret. It
authenticates *which enrolled machine* is talking, and is the trust root for "is this
a legitimate agent" — but it grants nothing beyond the ability to submit requests
that are then bounded by per-secret spend policy.

---

## 5 · Attestation & KMS binding

The KEK never leaves KMS. Per request:

1. Broker presents its Confidential Space **attestation token** to WIF (obtained
   from the launcher socket `/run/container_launcher/teeserver.sock`).
2. WIF mints a GCP principal **only if** the token's claims match the pinned condition:

```
assertion.swname == "CONFIDENTIAL_SPACE" &&
"STABLE" in assertion.submods.confidential_space.support_attributes &&
assertion.submods.container.image_digest == "sha256:<pinned broker digest>" &&
assertion.submods.container.image_reference == "<expected image>@sha256:<digest>" &&
assertion.submods.gce.project_number == "<expected project number>" &&
"<expected workload service account>" in assertion.google_service_accounts &&
assertion.submods.container.env["KMS_KEY"] == "<expected KMS key>" &&
assertion.submods.container.env["WIF_AUDIENCE"] == "<expected WIF provider>" &&
assertion.submods.container.env["KMS_SERVICE_ACCOUNT"] == "<expected broker SA>"
```

3. KMS `decrypt(wrapped_dek)` succeeds only for that principal → DEK in enclave memory.
4. AES-256-GCM decrypt the secret with the DEK; wipe mutable plaintext buffers promptly after use.

Consequences: a stolen envelope is inert (needs a live attestation); a tampered image
fails the digest claim and never decrypts; rotation = publish new digest → update WIF
condition → old image loses access automatically.

**Implementation.** This is the `enclave`-mode unwrapper, split across a
cloud-agnostic seam and a provider:

- `internal/kms` defines `KeyDecryptor` (unwrap a wrapped DEK — the provider seam)
  and `EnvelopeUnwrapper`, which composes a `KeyDecryptor` with AES-256-GCM to
  produce the plaintext secret. The AES half is provider-agnostic; adding AWS KMS
  or Azure Key Vault is a new `KeyDecryptor` and nothing else.
- `internal/kms/gcp` is the default provider: attestation token → STS
  token-exchange → required service-account impersonation → Cloud KMS `decrypt`.
  It is **stdlib-only** (plain `net/http` REST, no Google Cloud SDK) to keep the
  broker's TCB small, matching §2.
- Envelopes carry the alg `KMS+AES-256-GCM`: a per-secret DEK seals the secret and
  the KEK wraps that DEK (`Envelope.WrappedDEK`). Enrollment (`enroll -kms-key`)
  wraps the DEK with a matching Cloud KMS `encrypt`, authenticated by an operator
  access token — not by attestation, since enrollment runs outside the enclave.
  AES-GCM associated data binds the envelope to its record id, policy, algorithm,
  and KMS key, so a mutable store cannot broaden spend policy without making
  decrypt fail.
- The DEK is fetched per unwrap and zeroized after use; only the short-lived GCP
  access token is cached (operational state, like an OAuth token). KEK material is
  never cached (I-B6).

---

## 6 · Wire contract (`/v1/proxy`)

Request (mTLS, JSON; body base64 to preserve exact bytes):

```json
POST /v1/proxy
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

- `ref` is authoritative for secret selection; the broker resolves policy from it.
- `upstream.headers` is the caller's intended headers **minus** the credential; the broker adds/overwrites only what the credential module dictates.
- For **signed** creds, the agent forwards the *unsigned* canonical request; the broker sets `x-amz-date`, computes the payload hash over the exact body it will send, and signs. Any placeholder `Authorization` from a dummy-cred SDK is discarded.
- `caller` is advisory metadata for the audit log, **never** used for authorization in Phase 1.

Response: the broker streams upstream status, **scrubbed** headers, and body verbatim.
SSE/chunked bodies pass straight through.

**Error codes** (broker → agent; the agent maps these into something the tool sees):

| Code | Meaning | Secret unwrapped? |
|---|---|---|
| `401` | mTLS/identity failure — unenrolled or invalid client cert | no |
| `403` | policy denial — host/method/scope/`require_confirm` | no |
| `404` | unknown `ref` | no |
| `409` | OAuth rotation write-back failed — request refused, old token retained | no (fail closed) |
| `429` | rate or daily-cost cap exceeded | no |
| `502` | upstream returned an error / unreachable | yes (call was made) |
| `503` | attestation/KMS/store unavailable — **fail closed** | no |

Error bodies carry a `confidant_error` code and a human message; **never** any secret
material or the offending header value.

---

## 7 · Egress control

**Ingress and egress are separate concerns.** *Ingress* to the broker is private —
tailnet-only, no public route (§2). *Egress* to the real upstream APIs remains
**public but allowlisted** (the enclave still needs to reach `api.openai.com`, AWS,
etc.). Tailscale governs *who can reach the broker*, never *where the broker can
call out*. The two mechanisms don't overlap.

- Default-deny egress; the effective allowlist is `⋃ policy.allow_hosts ∪ oauth token endpoints ∪ minting endpoints`.
- A request must pass **both** the per-secret `allow_hosts` *and* the network-layer allowlist. Belt and suspenders. (Invariant I-B7.)
- DNS pinned inside the enclave.
- Egress denials are audited and surfaced as `403` (policy) or dropped at the firewall (network) — a network-layer drop must still fail the request closed, not hang indefinitely (enforced by `UPSTREAM_TIMEOUT`).

---

## 8 · Invariants (implemented local subset maps to tests in §10)

- **I-B1** Plaintext secrets/DEKs never leave enclave process memory; mutable buffers are wiped promptly after use, while unavoidable Go/TLS/runtime copies remain in-enclave and are not logged, audited, or returned.
- **I-B2** The injection/signing scheme for a secret is determined solely by stored policy, never by the request.
- **I-B3** No response returned to the agent contains the injected credential or any reflection of it.
- **I-B4** No secret value, DEK, or token ever appears in logs, audit records, metrics, or error messages.
- **I-B5** Policy authorization completes (and passes) *before* any KMS unwrap is attempted.
- **I-B6** KMS unwrap succeeds only under a live, matching attestation; the broker never caches KEK material, and plaintext caching remains disabled until implemented with explicit TTL/eviction semantics.
- **I-B7** An outbound request reaches an upstream only if it passes both `policy.allow_hosts` and the network egress allowlist.
- **I-B8** Any error in attestation/KMS/policy/module/egress yields denial — never an un/mis-authenticated upstream call.
- **I-B9** A refresh-token rotation is durably persisted before the new token is relied upon; on write-back failure the operation fails closed and the prior token remains authoritative.
- **I-B10** Every request is audited exactly once with its outcome (allowed/denied + reason).
- **I-B11** `caller` metadata never influences an authorization decision.
- **I-B12** Concurrent requests needing the same OAuth refresh trigger exactly one refresh (single-flight).
- **I-B13** The broker's request listener has no public-internet-facing binding on any interface: in enclave mode it binds loopback and is reachable only through the Tailscale sidecar (`tailscale serve`), and a wildcard bind is rejected at startup.
- **I-B14** Reaching the broker requires passing **both** the Tailscale ACL (agent tag) *and* mTLS (enrolled device cert); neither gate alone suffices, and both fail closed.
- **I-B15** The tailnet auth key is attestation-gated and never exists in a non-attested context; a non-blessed image cannot join the tailnet as the broker.

---

## 9 · Observability & audit

- **Audit record per request** (allowed and denied): timestamp, `ref` (id only), upstream host + method + path (no query secrets), policy decision + reason, bytes in/out, latency, credential `kind`, and for OAuth whether a refresh/rotation occurred. **No** secret, token, body, or auth header.
- Audit sink is **append-only** and **hash-chained** (each record includes the hash of the prior) so tampering is detectable. Sink location per `AUDIT_SINK` (default inside GCP; see Open Questions on GCP-visible metadata vs. local streaming).
- Metrics: request rate, denial rate by reason, KMS call rate, cache hit ratio, refresh rate, upstream latency. All secret-free.
- Health endpoint reports liveness only — never attestation internals or config secrets.

---

## 10 · Tests

> **Status.** The dev-path and enclave-KMS-path tests below are implemented and
> green: the KMS unwrap abstraction and GCP provider (`internal/kms`,
> `internal/kms/gcp`) are covered by unit tests driving mock STS/IAM/KMS through
> the real HTTP layer and a real unix-socket attestation source (fail-closed on
> STS/KMS/attestation errors, access-token caching, enroll↔unwrap round trip), and
> enclave-mode config validation is tested. Tests tied to unbuilt features (SigV4,
> OAuth2, streaming, the deployed-attestation E-B* cases) remain pending.

### Unit
- Credential modules: `StaticInjector` template substitution; `Sigv4Signer` against known AWS test vectors *(pending — module stubbed)*; `OAuth2Minter` token-exchange request shape *(pending — module stubbed)*.
- KMS unwrap: `EnvelopeUnwrapper` round-trips a sealed envelope; the GCP provider performs attestation→STS→impersonation→decrypt and **fails closed** on any step's error; the DEK is fetched per unwrap, the KEK is never cached, and policy/id/key AAD tampering fails decrypt. *(implemented)*
- Redaction/log hygiene: observability records and error paths carry no secret-bearing fields or values.
- Policy evaluator: allow/deny across host, method, rate, cost, scope, `require_confirm`.
- Zeroization: mutable plaintext buffers are wiped promptly after use; tests assert preflight denials never unwrap.

### Integration (broker + mock KMS + mock upstream + mock store)
- **T-B1 Happy path (static):** valid mTLS + allowed policy → bearer injected, mock upstream sees correct header, response returned. *(I-B1..I-B3)*
- **T-B2 Authorize-before-unwrap:** host not in `allow_hosts` → `403`, assert **KMS decrypt was never called**, audited denied. *(I-B5, I-B7, I-B10)*
- **T-B3 Method/rate/cost denials:** each returns the right code, no upstream call. *(I-B8)*
- **T-B4 Injection authority:** request supplies its own `inject` override → ignored; policy scheme used. *(I-B2)*
- **T-B5 Response scrubbing:** mock upstream reflects the `authorization` header in its response → stripped before return. *(I-B3)*
- **T-B6 No-leak scan:** capture full response + all emitted logs for T-B1; assert neither contains the secret string. *(I-B3, I-B4)*
- **T-B7 SigV4:** signed request validates against a SigV4 verifier / LocalStack S3; tamper a byte → signature rejected by upstream. *(I-B2)*
- **T-B8 OAuth refresh:** expired access token → one refresh against mock token endpoint → bearer injected. *(I-B12)*
- **T-B9 OAuth single-flight:** 50 concurrent requests on an expired token → exactly **one** token-endpoint call. *(I-B12)*
- **T-B10 OAuth rotation write-back:** provider returns a new refresh token → new envelope persisted **before** use; kill the store mid-write → request fails `409`, old token still authoritative on retry. *(I-B9)*
- **T-B11 mTLS enforcement:** no client cert → refused; untrusted client cert → refused. *(auth §4)*
- **T-B12 Fail-closed on KMS outage:** KMS returns error → `503`, no upstream call. *(I-B8)*
- **T-B13 Streaming:** SSE upstream → chunks relayed in order, no buffering-to-completion. 
- **T-B14 Caller metadata is inert:** identical requests with different `caller` values get identical authorization outcomes. *(I-B11)*
- **T-B15 Body-size / timeout:** oversize body rejected; slow upstream hits timeout and fails closed.
- **T-B16 No public listener:** after startup, assert the broker accepts connections only on the tailnet interface and that no public interface has the port open (bind-scope check). *(I-B13)*
- **T-B17 Both gates required:** a tailnet peer without `tag:confidant-agent` is denied by ACL; a correctly-tagged peer without a valid client cert is denied by mTLS. Neither reaches the pipeline. *(I-B14)*

### End-to-end (deployed to Confidential Space — M3+)
- **E-B1 Attestation gate:** deploy a broker image with a *wrong* digest → KMS refuses; nothing decrypts. Deploy the blessed digest → succeeds.
- **E-B2 Egress allowlist:** attempt an upstream not in the network allowlist → blocked at the firewall, request fails closed within `UPSTREAM_TIMEOUT`.
- **E-B3 Audit chain:** run N mixed allow/deny requests → audit log verifies as an unbroken hash chain.
- **E-B4 Unreachable from the public internet:** from a host *not* on the tailnet, attempt to reach the broker's MagicDNS name / any public IP on the proxy port → no route / connection refused. Confirm the enclave exposes nothing publicly. *(I-B13)*
- **E-B5 Attestation-gated join:** boot a non-blessed broker image → it cannot obtain the tailnet auth key (KMS refuses) and never appears on the tailnet. *(I-B15)*

---

## 11 · Open questions (broker-specific)

- **Enrollment list distribution.** Is the agent-cert allowlist part of the measured image (redeploy to enroll a device) or a signed, separately-updatable list the broker verifies? Latter is more ergonomic; needs its own signature root.
- **SigV4 streaming payloads.** Use `UNSIGNED-PAYLOAD` (safe under TLS) by default, or implement chunked `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` for large uploads?
- **Cache TTL vs. exposure.** Plaintext caching is disabled in the Go prototype. If added later, should static/signed secrets default to no cache, short per-policy TTLs, or a bounded 5-minute warm-path cache given SEV-SNP memory encryption?
- **Audit sink.** GCP-internal (tamper-evident, but metadata visible to GCP) vs. streamed to a local append-only store the user controls.
- **`require_confirm` challenge.** Broker issues a signed challenge the agent surfaces locally; define the challenge/response format and timeout.
- **Tailnet auth-key delivery & rotation.** *Currently passed as ephemeral, tagged Confidential Space metadata (`TS_AUTHKEY`) — not yet attestation-gated.* The target flow is KMS-release at boot → tailnet join with an ephemeral+tagged key, so a non-attested image cannot obtain a key (I-B15). Confirm the exact flow, how often keys rotate, and whether an ephemeral node's churn interacts badly with the ACL / MagicDNS TTLs.
- **`tsnet` vs. userspace `tailscaled` sidecar.** The implementation forwards inbound tailnet TCP to a loopback broker via `tailscale serve`, keeping the broker's dependency tree stdlib-only. Embedding `tsnet` would remove the sidecar process and the `tailscale serve` version coupling, at the cost of a large dependency in the TCB. Decide whether the TCB cost is worth it.
- **mTLS vs. Tailscale identity — keep both?** We keep both deliberately (defense in depth). Revisit only if operational cost proves high; dropping mTLS would make a single ACL misconfiguration fatal, so the bar to remove it is high.
