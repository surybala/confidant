# Confidant — Local Agent Spec

**Component:** `confidant-agent` · **Phase:** 1 · **Version:** 0.1 · **Date:** 2026-09-06
**Parent spec:** [phase1-secrets-broker.md](./phase1-secrets-broker.md) · **Peer:** [broker-core.md](./broker-core.md)

The agent is the local, **secretless** side. It runs a loopback forward proxy that
tools point at, recognizes credential *refs* in outbound requests to configured
hosts, and relays those requests to the broker over mTLS. It holds no long-lived
secret and never talks to an upstream API itself.

If a single sentence has to survive: **the agent only ever handles refs, only MITMs
the hosts it is told to, tunnels everything else blind, and fails closed rather than
leak a real key.**

---

## 1 · Responsibilities

1. Run a **loopback-only** HTTP CONNECT forward proxy (the standard `HTTPS_PROXY` target).
2. For **intercepted hosts**: MITM-terminate the tool's TLS with a leaf cert from a local CA, read the plaintext request.
3. **Recognize the credential ref** in the request (see §6), strip it, and note where it was.
4. **Relay** the reconstructed request + `ref` + `caller` metadata to the broker over a warm mTLS connection.
5. Return the broker's response to the tool **verbatim** (streaming preserved).
6. For **non-intercepted hosts**: **blind CONNECT tunnel** — never decrypt, never inspect.
7. Maintain the warm mTLS connection (reconnect/backoff, health) and the local trust material.
8. Capture best-effort `caller` metadata (pid/exe) for the audit trail.

**Not the agent's job:** holding secrets, making upstream API calls, deciding
injection scheme, authorizing spend. Those all live in the broker.

---

## 2 · Security decisions

**What the agent holds (and what it doesn't)**
- **No long-lived secrets.** Ever. The agent's world is refs. (Invariant I-A1.)
- It holds two pieces of local key material:
  - the **device client cert + key** for mTLS to the broker (its identity), and
  - the **local MITM CA cert + key** used to mint leaf certs for intercepted hosts.
- Both keys are stored `0600`, owned by the user, ideally in the OS keychain. Loss of either is meaningful (see below) but neither is a routable secret to any third-party API.

**The MITM CA is name-constrained**
- The local CA carries X.509 **name constraints** limiting it to the exact intercept list. It **cannot** mint a valid cert for any other domain. This bounds the blast radius if the CA key is stolen: an attacker gains nothing beyond MITM of the already-brokered hosts (whose secrets aren't local anyway).
- Installing the CA into the user trust store is the **one manual trust step**; it is scoped, documented, and reversible (`confidant ca uninstall`).

**Loopback only, fail closed**
- Binds `127.0.0.1` only, never `0.0.0.0`. Connections from non-loopback are refused. (Invariant I-A2.)
- If the broker is unreachable or denies, intercepted requests **fail closed** with a clear error. There is no fallback path that sends the request upstream — and there's no local credential to send anyway. Non-intercepted traffic is unaffected. (Invariant I-A5.)
- An intercepted-host request that carries **no recognizable ref** is **rejected, not forwarded** — to the broker or upstream. This protects a user who accidentally put a *real* key where a ref belongs: the agent refuses rather than shipping the raw secret anywhere. (Invariant I-A8.)

**Minimal visibility**
- Non-intercepted hosts are tunneled blind: the agent never terminates their TLS, generates no leaf cert, and sees only `CONNECT host:443`. (Invariant I-A3.) This keeps the agent out of the path of traffic it has no business reading.
- The agent **does not** connect to any upstream API. For intercepted hosts the only outbound connection it makes is the mTLS channel to the broker. (Invariant I-A4.)
- The agent logs metadata only — never request/response bodies, never the ref's optional hint suffix, never header values beyond what's needed to route.

**Broker trust & connectivity**
- **Connectivity is private, over Tailscale.** The agent reaches the broker only across the tailnet — the broker has **no public address**. The agent runs as a `tag:confidant-agent` node and addresses the broker by MagicDNS (e.g. `confidant-broker.<tailnet>.ts.net`). If the tailnet is unavailable, intercepted requests **fail closed**; there is no public fallback. (Invariant I-A12, consistent with I-A5.)
- The agent **pins the broker's server cert** (SPKI pin) *on top of* Tailscale — two independent gates (network identity + app identity). A rogue local or tailnet process cannot impersonate the broker to the agent, and a misconfigured endpoint cannot silently downgrade trust.
- The agent injects **no credential of its own**; the only auth it adds anywhere is its mTLS client identity to the broker. (Invariant I-A7.)

---

## 3 · Configuration

`~/.config/confidant/agent.toml` — **contains no secrets**:

```toml
[broker]
# Tailnet MagicDNS name — the broker has no public address. Reachable only
# over Tailscale, and only from a tag:confidant-agent node.
endpoint    = "https://confidant-broker.<tailnet>.ts.net:8443"
client_cert = "~/.config/confidant/agent.pem"   # device identity (mTLS)
server_spki_pin = "sha256/…"                     # broker cert pin (2nd gate)

[proxy]
listen = "127.0.0.1:8317"
# hosts to MITM + route; everything else is blind-tunnelled
intercept = ["api.openai.com", "*.amazonaws.com", "api.github.com"]

[refs]
# inert refs the tools use → secret ids the broker resolves
"cfdt:openai/personal" = "openai/personal"
"cfdt:aws/dev"         = "aws/dev"

[detect]
# how a ref is found per host (see §6)
"api.openai.com" = { location = "header", name = "authorization", strip_prefix = "Bearer " }
"api.github.com" = { location = "header", name = "authorization", strip_prefix = "Bearer " }
"*.amazonaws.com" = { mode = "aws-sdk-dummy", sentinel_access_key_id = "AKIACONFIDANTDEV", ref = "cfdt:aws/dev" }
```

- **Trust material paths**: `client_cert`, and CA at `~/.config/confidant/ca.pem` (+ key `0600`), generated on first run.
- **Timeouts / pool**: broker connect timeout, request timeout (must exceed broker `UPSTREAM_TIMEOUT`), max multiplexed streams.
- **Reload**: config is reloadable without dropping the warm connection (SIGHUP / file-watch).

---

## 4 · Auth scheme

| Hop | Mechanism | Notes |
|---|---|---|
| tool → agent | none (local); agent presents a **leaf cert** signed by the name-constrained local CA | the tool's TLS validates because the CA is in the user trust store |
| agent → broker | **mTLS over Tailscale** — enrolled device client cert, broker server cert **pinned**, across the tailnet | two gates: Tailscale (agent is a `tag:confidant-agent` node) + mTLS. The agent's only outbound auth; no public route to the broker |
| caller identity | best-effort OS lookup (local port → pid → exe) | advisory metadata only, not used for any decision |

Phase 1 deliberately does **not** authenticate individual local callers: any local
process may use the proxy. That is consistent with the threat model — malicious local
code is *expected* to try, and is bounded by per-secret spend policy in the broker,
not by gatekeeping at the agent. Per-caller policy is a later phase.

---

## 5 · Request flow

**Intercepted host (e.g. OpenAI):**
```
tool ──TLS(leaf)──▶ agent
  agent: terminate TLS, read request
  agent: detect ref per [detect]; strip it; capture location
  agent: fail closed if no recognizable ref
  agent ──mTLS──▶ broker   { ref, upstream(method,url,headers-minus-cred,body_b64), caller }
  broker ▶ upstream ▶ broker (see broker-core.md)
  agent ◀── response ── broker
tool ◀── response(verbatim, streamed) ── agent
```

**AWS (sdk-dummy mode):** the AWS SDK is configured with dummy credentials whose
access key id is the sentinel ref (`cfdt:aws/dev`). It produces a request signed with
a bogus key; the agent **detects the sentinel**, discards the bogus `Authorization`,
and forwards the *unsigned canonical* request + ref. The broker re-signs with the
real key (SigV4). See broker-core.md §6.

**Non-intercepted host:** `CONNECT host:443` → blind TCP tunnel, agent never decrypts.

**Broker error mapping:** the broker's structured error becomes an HTTP response the
tool's SDK understands — e.g. broker `403` (policy) → a `403` to the tool with a
`confidant_error` body; broker `503` (fail-closed) → a `502`/`503` with a clear
message. The agent never fabricates a *success* the broker didn't grant.

---

## 6 · Ref detection

A **ref** is what tools are configured with in place of a real secret; it is inert if
leaked. The agent must find it deterministically per host:

- **`header` mode:** read the named header, strip the configured prefix, expect a `cfdt:` value. (OpenAI/GitHub: `Authorization: Bearer cfdt:openai/personal#…`.)
- **`query` mode:** read a named query param (discouraged — avoid secrets/refs in URLs where possible; supported for legacy APIs).
- **`aws-sdk-dummy` mode:** recognize the sentinel access-key-id in the SigV4 `Authorization` header's `Credential=<akid>/…` field; treat the whole request as an unsigned canonical to forward (the broker re-signs). The sentinel **must be slash-free** — SigV4 uses `/` as the `Credential=` delimiter, so the parser reads only up to the first `/`. The `cfdt:` ref (which contains a `/`) is configured separately via `ref`, not carried in the request.

Rules:
- A `cfdt:` value must resolve via `[refs]` to a known secret id, else **reject** (unknown ref, `404`-equivalent to the tool).
- The optional `#hint` suffix is **display-only** and is stripped before forwarding; it is never logged.
- If detection yields something that is **not** a `cfdt:` ref on an intercepted host (i.e. looks like a real secret), **reject and do not forward** (I-A8).

---

## 7 · Invariants (each maps to a test in §8)

- **I-A1** The agent never possesses a plaintext long-lived secret; it handles only refs and its own device/CA key material.
- **I-A2** The proxy binds only to loopback; non-loopback connections are refused.
- **I-A3** Non-intercepted hosts are blind-tunnelled; the agent generates no leaf cert and decrypts nothing for them.
- **I-A4** For intercepted hosts the agent's only upstream-direction connection is the mTLS channel to the broker; it never calls the real API.
- **I-A5** If the broker is unreachable or denies, intercepted requests fail closed; non-intercepted traffic is unaffected.
- **I-A6** The local MITM CA is name-constrained to the intercept list and cannot mint a valid cert for any other domain.
- **I-A7** The agent adds no credential of its own beyond its mTLS client identity to the broker.
- **I-A8** A request to an intercepted host without a recognizable `cfdt:` ref is rejected and forwarded nowhere.
- **I-A9** The broker server cert is pinned; a cert not matching the pin aborts the connection.
- **I-A10** `caller` metadata is best-effort and advisory; the agent never blocks or authorizes on it.
- **I-A11** Refs' `#hint` suffixes and all request/response bodies are never written to logs.
- **I-A12** The agent reaches the broker only over the tailnet (private, no public route); if the tailnet is down, intercepted requests fail closed and non-intercepted traffic is unaffected.

---

## 8 · Tests

### Unit
- Ref detection across `header` / `query` / `aws-sdk-dummy` modes; prefix stripping; `#hint` removal.
- Reject paths: unknown ref, non-`cfdt:` value on intercepted host.
- CA generation produces a **name-constrained** cert; assert it cannot sign a leaf for an out-of-list domain.
- Broker error → tool-facing HTTP mapping table.

### Integration (agent + mock broker + real tool client)
- **T-A1 Happy path:** `curl`/SDK with `HTTPS_PROXY=127.0.0.1:8317` to an intercepted host with a ref → agent forwards to mock broker, response returned verbatim. *(I-A1, I-A4)*
- **T-A2 Blind tunnel:** request to a non-intercepted host → end-to-end TLS to the real host; assert the agent generated no leaf and read no plaintext. *(I-A3)*
- **T-A3 Fail closed (broker down):** stop the mock broker → intercepted request errors clearly; a concurrent non-intercepted request still succeeds. *(I-A5)*
- **T-A4 No-ref rejection:** intercepted host with a *real-looking* key (no `cfdt:`) → rejected; assert broker was **not** called and no upstream connection was made. *(I-A8)*
- **T-A5 Loopback only:** connect from a non-loopback interface → refused. *(I-A2)*
- **T-A6 Broker pin:** present a broker cert not matching the SPKI pin → connection aborted. *(I-A9)*
- **T-A7 AWS dummy-cred:** boto3 with the sentinel access key id → agent strips the bogus signature and forwards the unsigned canonical + ref (assert mock broker receives no valid signature and the correct ref). 
- **T-A8 Streaming passthrough:** mock broker streams SSE → tool receives chunks incrementally, not buffered. 
- **T-A9 Warm connection reuse + reconnect:** N sequential requests reuse one mTLS connection; restart the broker → agent reconnects with backoff and the next request succeeds. 
- **T-A10 Concurrency:** many parallel requests multiplex correctly with no cross-talk of responses. 
- **T-A11 Config reload:** add an intercept host via SIGHUP without dropping the warm connection. 
- **T-A12 Log hygiene:** run T-A1 and assert logs contain no body bytes and no `#hint` value. *(I-A11)*
- **T-A13 Tailnet down → fail closed:** simulate the tailnet being unreachable → intercepted requests fail closed with a clear error; a concurrent non-intercepted request still tunnels fine. *(I-A12)*

---

## 9 · Cross-component end-to-end (agent + broker + mock upstream)

Run the **real agent** against the **real broker** (dev KEK in M2, Confidential Space
in M3) with a mock upstream, driving an actual client (`curl`, then `claude code`):

- **E2E-1 No local secret, successful call:** with only refs configured locally, a request to an intercepted host succeeds end-to-end; scan the agent's process memory and the local filesystem/dotfiles for the real secret string → **absent**. Prove the secret exists only in the broker.
- **E2E-2 Malicious-lib simulation:** a stub "malicious" local process reads env, dotfiles, and hits the proxy directly; verify it obtains **no secret**, and that any calls it makes are bounded by (and audited under) the secret's spend policy.
- **E2E-3 Exfil attempt blocked:** the stub tries to reach a non-allowlisted host through the proxy → blind-tunnelled (agent) and, if it targets a brokered secret against a disallowed host, denied at the broker; nothing leaves with a credential.
- **E2E-4 OAuth round trip:** an intercepted OAuth API call triggers a broker-side refresh/rotation; the tool sees a normal success and no token ever appears locally.
- **E2E-5 Attestation break (M3):** point the agent at a broker running a non-blessed image digest → calls fail closed (KMS refuses); confirm no upstream call and a clear tool-facing error.
- **E2E-6 Private path only:** the agent reaches the broker via MagicDNS over the tailnet and succeeds; from a host off the tailnet, the broker's address is unreachable. Confirms there is no public route to the broker (pairs with broker E-B4).

---

## 10 · Open questions (agent-specific)

- **CA trust-store scope.** Name-constrained CA in the *user* trust store vs. per-tool `NODE_EXTRA_CA_CERTS`/`REQUESTS_CA_BUNDLE` to avoid a system-wide CA at all. The latter is narrower but per-tool.
- **Caller metadata fidelity.** How much effort to spend on reliable local-port→pid→exe attribution (racy on some OSes); Phase 1 keeps it best-effort and advisory.
- **Non-HTTP protocols.** Phase 1 is HTTP(S) only. gRPC-over-HTTP2 to intercepted hosts — supported via the same MITM path, or deferred?
- **Windows support.** Loopback proxy + CA install differs on Windows; macOS/Linux first.
