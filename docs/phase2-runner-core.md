# Confidant - Phase 2 Core Runner

**Status:** Draft for build — scoped to a single-resource, synchronous side effect  
**Version:** 0.2  
**Date:** 2026-09-12  
**Parent:** [phase1-secrets-broker.md](./phase1-secrets-broker.md)  
**Example skill:** [pay_invoice](../confidant-skills/payments/pay_invoice/SPEC.md)

Phase 2 adds a minimal trusted execution layer for business actions. Local code stays
untrusted. It can name an action and provide selectors, but a measured enclave validates
the request against private authoritative state, standing authorization, durable
idempotency, and declassification policy before any side effect happens.

The core design goal is that `confidant-agent`, `confidant-runner`, and
`confidant-proxy` stay small, stable, and provider-neutral. Payments, refunds, cloud
remediation, trading, and other workflows are trusted skills, not core modules.

If one sentence has to survive: **the core hosts measured skills and enforces the
boundaries; skills contain the business logic.**

---

## 1. Scope

This spec defines the production-grade core runner and its hooks:

- agent-to-runner action API
- measured trusted-skill registry
- runner host services exposed to skills
- proxy-backed connector interface
- durable operation state
- runner-derived idempotency, audit, and declassification
- runner-to-proxy internal egress
- deployment, attestation, network, and test gates

This spec does **not** define a concrete payment rail, provider schema, invoice schema,
or transaction format. Those belong in a skill module, such as
[`confidant-skills/payments/pay_invoice`](../confidant-skills/payments/pay_invoice/SPEC.md).

---

## 2. Goals And Non-Goals

**Goals**

- Keep private business data, connector responses, credentials, wallet auth material,
  and intermediate reasoning out of the local environment.
- Keep core modules minimal: stable protocol, policy, attestation, state, credential,
  audit, and declassification machinery only.
- Let untrusted local agents trigger pre-authorized side effects through narrow,
  measured trusted-skill actions.
- Make every trusted unit reproducible, measured, and pinned by attestation.
- Require every action to declare what it may read, call, change, persist, and return.
- Support unattended autonomous actions without per-transaction confirmation, but only
  when every consequential field is authoritatively determined and exposure is bounded by
  standing authorization.
- Make state and audit durable enough that retries, races, crashes, and replay attempts do
  not cause duplicate side effects.
- Allow many use cases to be added as skills without expanding the trusted core or
  weakening the existing invariants.

**Non-goals**

- Running arbitrary caller-supplied code in the enclave.
- Importing provider SDKs or business workflows into `confidant-agent`,
  `confidant-runner`, or `confidant-proxy`.
- Making the local agent honest. It remains adversarial.
- Offering a confirmation gate for non-determinable actions. If recipient, amount, target,
  or other consequential fields cannot be determined from authoritative sources, the
  action is not admissible.
- Replacing provider-native controls. Provider policies, limits, approvals, and spend
  permissions are defense in depth.
- Local filesystem sandboxing for untrusted tools. That remains a separate phase.

---

## 3. Threat Model

The adversary is untrusted local code running with the user's ambient local privileges:
an agent plugin, dependency, MCP tool, generated script, or compromised CLI.

The adversary can:

- call the local Confidant agent
- choose action ids and action inputs
- retry, race, and replay requests
- inspect local env vars, dotfiles, logs, and process memory
- attempt prompt injection against the local agent
- exfiltrate anything returned locally

The adversary should not be able to:

- read connector credentials or auth material
- read private connector responses unless explicitly declassified
- modify skill policy, egress, code, schema, or output policy at request time
- trigger side effects outside a measured skill manifest and proxy credential policy
- bypass idempotency or approval gates by retrying
- cause raw provider responses or sensitive intermediate state to return locally

Out of scope:

- compromise of reviewed trusted skill code itself
- malicious authoritative systems returning false records
- provider compromise
- hiding public side effects from public networks
- side-channel resistance beyond the Confidential Space threat model

---

## 4. System Model

```text
LOCAL MACHINE (untrusted)                 GCP CONFIDENTIAL SPACE (trusted)
+----------------------+                  +------------------------------------+
| coding agent / tool  |                  | runner pool                        |
| chooses selectors    |                  | +------------------------------+   |
+----------+-----------+                  | | confidant-runner             |   |
           |                              | | skill host + state + audit   |   |
           v                              | +---------------+--------------+   |
+----------------------+ mTLS + tailnet   |                 | internal egress   |
| confidant-agent      +----------------->|                 v                  |
| local, secretless    |                  | +------------------------------+   |
+----------^-----------+                  | | confidant-proxy              |   |
           |                              | | credentialed egress broker   |   |
           |                              | +-------+-----------+----------+   |
           |                              +---------|-----------|--------------+
           |                                        |           |
           |                                        v           v
           |                                  SaaS APIs     payment/cloud/etc.
           |                                        |           |
           +-------- declassified output <----------+-----------+
```

| Component | Runs | Responsibility | Sees private data? | Sees credentials? |
|---|---|---|---|---|
| `confidant-agent` | Local | Authenticates to runner, forwards action calls, returns declassified outputs | No | No |
| `confidant-runner` | Enclave | Minimal trusted-skill host; validates action envelopes; provides state, audit, connector calls, and output validation | Yes | No |
| `confidant-proxy` | Enclave | Minimal credentialed egress broker; unwraps/mints/signs/injects credentials; enforces declarative credential and delegation policy | Provider responses in transit | Yes, ephemeral |
| `confidant-skills` bundles | Runner image or measured bundle set | Trusted recipes with provider schemas, connector adapters, business logic, policy templates, and tests | Yes | No |
| Runner state bucket | Cloud Storage | Operation logs, receipts, capability snapshots, directory snapshots, audit | Metadata and declassified receipts; app-sealed/MACed | No |
| Credential store | Proxy-controlled | Sealed credentials plus credential/delegation policy | Policy metadata | Ciphertext at rest |

The core modules deliberately do not import provider SDKs or encode provider workflows.
The runner hosts measured skills. The proxy performs generic credentialed egress. Skills
contain business-specific parsing, validation, transaction construction, and provider
request shaping.

---

## 5. Core Boundary

`confidant-agent` owns:

- local authenticated forwarding to the runner
- caller metadata collection for audit only
- returning declassified outputs
- no secret handling and no business authorization

`confidant-runner` owns:

- agent authentication and action routing
- measured skill registry and digest allowlist
- input envelope validation and canonicalization hooks
- static manifest authorization
- durable operation keys, receipts, and audit
- state record sealing/MAC verification
- proxy-backed connector invocation
- output schema validation and max-byte enforcement
- panic hygiene, constant denial, and declassification boundary

`confidant-proxy` owns:

- credential unwrap and DEK handling
- static, signed, and OAuth credential primitives
- credential policy and runner/action delegation policy
- host, method, path, endpoint-shape, and evidence checks
- egress allowlist, TLS validation, optional pinning
- credential scrubbing and credential-use audit

`confidant-skills` owns, per trusted recipe:

- provider request/response schemas
- connector adapters over the runner connector interface
- private response parsing
- business policy
- authoritative determination of consequential fields
- provider transaction/request construction
- receipt construction and proposed declassified fields
- skill-specific tests and fixtures

Core dependency rule: core packages may depend on standard runtime libraries and generic
Confidant interfaces only. Provider-specific dependencies and generated provider schemas
are allowed only under `confidant-skills/*`.

---

## 6. Trusted Skill Model

A trusted skill bundle exports one or more actions. Each action has a manifest pinned by
digest:

```json
{
  "id": "example.action.v1",
  "kind": "trusted_skill_action",
  "skill_bundle": "confidant-skills/example",
  "skill_version": "0.1.0",
  "skill_digest": "sha256:<pinned skill bundle digest>",
  "input_schema": "ExampleSelector",
  "output_schema": "ExampleReceipt",
  "authoritative_bindings": {
    "target": { "source": "authoritative-system/prod", "key": "selector.id" },
    "amount": { "source": "record.balance" },
    "eligibility": ["record.exists", "record.status == 'approved'"]
  },
  "connectors": [
    { "id": "authoritative-system/prod", "role": "source", "scopes": ["read"] },
    { "id": "effect-rail/prod", "role": "effect", "scopes": ["mutate"] }
  ],
  "egress": {
    "allow_hosts": ["api.example.com"],
    "allow_methods": ["GET", "POST"]
  },
  "side_effects": [
    { "kind": "example_effect", "max_amount_usd": "250.00" }
  ],
  "declassify": {
    "mode": "schema",
    "schema": "ExampleReceipt",
    "max_bytes": 4096,
    "residual_leak": "<declared residual>"
  },
  "limits": {
    "timeout_ms": 20000,
    "rpm": 10
  }
}
```

The manifest, schema hashes, connector roles, side-effect declarations, output schema, and
skill digest are part of the runner measured allowlist. A caller can select only an action
id. It cannot choose code, a skill bundle, connector scope, egress host, output policy, or
declassification mode.

### Skill Interface

Each skill action implements the runner host interface:

```go
type Action interface {
    ID() string
    Manifest() Manifest
    ValidateInput(json.RawMessage) (CanonicalInput, error)
    Plan(ctx ActionContext, in CanonicalInput) (Plan, error)
    Execute(ctx ActionContext, plan Plan) (Receipt, error)
    Declassify(receipt Receipt) (json.RawMessage, error)
}
```

`ActionContext` is a capability object, not a general runtime. It exposes only:

- declared connector calls through the proxy-backed connector interface
- durable operation/event APIs
- receipt write/read APIs
- audit APIs
- bounded time and randomness helpers
- manifest, schema, and capability metadata

It must not expose raw network clients, filesystem authority, process spawning,
environment variables, plaintext credentials, or direct response streaming.

### Admissibility

An action is admissible for autonomous execution only if:

- every consequential field is authoritatively determined from private trusted sources
- worst-case side effects over all adversary-chosen selectors are within enrollment caps
- the side effect maps to one obligation resource, so the operation key alone serializes it
- declassification is schema-bounded and byte-bounded
- provider-specific failure modes fail closed or resolve by a synchronous idempotent retry

If an action needs arbitrary caller-provided recipient, amount, target, or code, it is not
registered. There is no "offer it with a confirmation" path in Phase 2. Actions that need
multi-resource locks, a standalone effect ledger, or asynchronous reconciliation are
deferred (see §17).

---

## 7. Request And Response Contract

Agent-to-runner request:

```json
POST /v1/actions/{action_id}
{
  "idempotency_key": "caller-visible-key",
  "input": {
    "selector_id": "source:12345"
  },
  "caller": {
    "pid": 4821,
    "exe": "node",
    "workspace": "confidant-demo"
  }
}
```

Rules:

- `input` is selectors-only unless a field is explicitly marked non-consequential.
- `caller` is audit metadata only and never authorizes.
- `idempotency_key` is required for side-effecting actions, but it is not the durable
  operation identity.
- Unknown fields, oversize inputs, malformed selectors, consequential values, and schema
  mismatches fail before any connector call.

Runner-to-agent response:

```json
{
  "action_id": "example.action.v1",
  "status": "posted",
  "receipt": {
    "receipt_id": "rcpt_...",
    "selector_id": "source:12345"
  }
}
```

Denials use a single constant caller-facing code for all pre-side-effect validation
failures in an action. Specific reasons live only in enclave audit.

---

## 8. Runner Pipeline

1. Authenticate agent mTLS identity and enforce tailnet ingress.
2. Parse action id, resolve pinned skill action, verify skill digest and manifest/schema
   hashes against measured allowlist.
3. Validate request size, content type, and JSON envelope.
4. Call skill input validation and canonicalize input.
5. Compute deterministic operation key:
   `hash(action_id || selector || policy_hash || capability_hash || directory_hash)`.
   The key is derived from the single obligation resource, so it doubles as the mutual
   exclusion for that resource; no separate lock object is required.
6. Claim the operation by creating the `reserved` event with `ifGenerationMatch=0`.
   - If a committed receipt already exists, return it.
   - If the claim loses the race (`412`), another attempt owns the operation: return its
     committed receipt, or a retryable coarse error if it is still in flight.
   - If caller idempotency is bound to different canonical input, deny.
7. Run static manifest authorization that does not need private reads.
8. Fetch private context through declared connector roles, let the skill run private
   validations and determine every consequential field, then append `validated`.
9. Verify provider-native policy or evidence when the skill declares such a precondition.
10. Append durable `submitted`, with the stored provider idempotency material, before the
    side-effecting provider call.
11. Ask the proxy to call the declared effect connector using the runner-derived operation
    context and the stored provider idempotency material.
12. Commit the declassified `posted` receipt durably before returning success.
13. Build output only from declared receipt fields; validate output schema, reject extra
    fields, and enforce max bytes.
14. Append action audit and return the declassified output or a constant denial.

If any step fails before `submitted`, the runner audits once, discards private context, and
returns a constant denial. If a step fails after `submitted`, the runner never blindly
resubmits: it returns the committed receipt if present, otherwise it re-issues the exact
stored provider request under the stored provider idempotency key and reads the provider's
synchronous status. Because this phase targets a synchronous, provider-idempotent rail, that
one call resolves every crash window.

---

## 9. Proxy Egress Pipeline

Runner-to-proxy requests include action context:

```json
{
  "ref": "cfdt:provider/prod",
  "context": {
    "runner_principal": "runner:default",
    "action_id": "example.action.v1",
    "invocation_id": "act_abc123",
    "connector_role": "source",
    "operation_key": "op_...",
    "idempotency_key": "caller-visible-key",
    "policy_evidence": {
      "provider_policy_id": "policy_...",
      "provider_policy_hash": "sha256:..."
    }
  },
  "upstream": {
    "method": "GET",
    "url": "https://api.example.com/v1/record/12345",
    "headers": { "accept": "application/json" }
  }
}
```

The proxy:

1. Authenticates runner identity from transport.
2. Binds transport identity to `runner_principal`; rejects mismatches.
3. Resolves `ref` to credential policy.
4. Verifies host, method, path, endpoint shape, connector role, and declared action id.
5. Verifies delegate policy names the runner principal, action id, and role.
6. Verifies rate, spend, concurrency, and declarative provider-policy evidence required by
   the credential policy.
7. Unwraps, mints, signs, or injects credential material.
8. Calls upstream through egress allowlist and TLS verification.
9. Scrubs credential reflections from response metadata and errors.
10. Appends credential-use audit.
11. Returns upstream response only to the runner.

The proxy must not parse business objects or execute provider SDK workflows. It can enforce
declarative policy and generic credential primitives.

---

## 10. Durable State

Production runner durable state lives outside the immutable image in a dedicated Cloud
Storage bucket reachable only by the runner's attested workload identity. Local disk is not
production authority state.

State classes:

| State | Purpose |
|---|---|
| Operation events | Ordered state machine for one action selector and policy/capability/directory version |
| Receipts | Declassified output records returned to local callers |
| Audit | Hash-chained allow/deny/fail metadata |
| Capabilities | Signed standing-authorization snapshots |
| Directories | Signed or measured authoritative lookup snapshots |

Operation states:

| State | Meaning |
|---|---|
| `reserved` | Operation identity is claimed; no side effect has started |
| `validated` | Private validations passed and consequential fields are determined |
| `submitted` | Provider call has started or may have started |
| `posted` | Provider result and declassified receipt are committed |
| `failed` | Validation failed before provider submission; no side effect occurred |

Cloud Storage rules:

- Use `ifGenerationMatch=0` for create-if-absent immutable events and receipts.
- Use `ifGenerationMatch=<generation>` only for optional index CAS updates.
- Treat `412 Precondition Failed` as a coordination result, not an exceptional path: it
  means another attempt already owns the operation.
- The immutable event stream is authoritative. Mutable indexes are caches.
- App-seal or MAC every app-owned state record with a runner-state key distinct from the
  proxy credential KEK.
- Associated data binds record type, object path, action id, operation key, schema version,
  policy/capability/directory hashes, and predecessor event path/generation/hash when
  present.
- Fail closed on missing predecessor, unexpected generation, MAC failure, rollback
  evidence, or invalid signature.
- Runner IAM must not have production delete permission for ledger, receipt, or audit
  prefixes.

Default object layout:

```text
gs://confidant-runner-state/
  ledger/<action_id>/<op_hash>/events/000_reserved.json.enc
  ledger/<action_id>/<op_hash>/events/010_validated.json.enc
  ledger/<action_id>/<op_hash>/events/020_submitted.json.enc
  ledger/<action_id>/<op_hash>/events/030_posted.json.enc
  receipts/<receipt_id>.json.enc
  audit/YYYY/MM/DD/<event_id>.json.enc
  capabilities/<capability_id>/<version>.json
  directories/<directory_id>/<version>.json
```

Cloud Storage is enough for the single-resource idempotency this phase needs: the operation
key is the obligation, and one create-if-absent write serializes it. It is not a general
multi-object transaction system. Actions that need multi-resource coordination or hard
aggregate invariants are deferred (see §17).

---

## 11. Idempotency And Reconciliation

The runner operation ledger is the authoritative long-lived duplicate-effect guard.
Provider idempotency keys are an auxiliary retry aid.

Rules:

- The durable operation key is derived by the runner, not supplied by the caller.
- Caller idempotency keys are stored and checked for consistency only.
- Provider idempotency material is minted by the runner and stored before `submitted`.
- After `submitted`, retries must not mint fresh provider idempotency material.
- Retry order after `submitted`:
  1. return the committed receipt if present
  2. otherwise re-issue the exact stored provider request under the stored provider
     idempotency key and read the provider's synchronous status
  3. commit `posted` on success; return a constant denial on a terminal provider failure

Because this phase targets a synchronous, provider-idempotent rail, step 2 resolves every
crash window in one call. Asynchronous rails that need evidence-based reconciliation or an
operator queue are deferred (see §17).

---

## 12. Transports And Deployment

Agent-to-runner:

- mTLS over tailnet-only ingress
- no public runner ingress
- caller identity is audit metadata, not authorization

Runner-to-proxy:

| Deployment shape | Transport | Identity mechanism |
|---|---|---|
| Same enclave, same VM/container group | Unix domain socket | filesystem permissions plus peer credentials |
| Same enclave, separate namespace | loopback mTLS | pinned runner/proxy certs |
| Separate attested instances | mTLS over private network or tailnet | runner cert plus attestation-bound enrollment |

MVP UDS:

```text
socket: /run/confidant/egress.sock
owner: confidant-proxy
group: confidant-runner
directory mode: 0750
socket mode: 0660
protocol: HTTP/1.1 JSON over Unix domain socket
```

Deployment requirements:

- Runner and proxy are separate processes or at least separate packages with an explicit
  egress interface.
- Runner has no direct public provider egress.
- Proxy is the only component allowed to reach external provider APIs.
- Proxy measured config includes KMS key, WIF audience, credential module set, egress
  posture, credential policy hashes, delegate policy hashes, and evidence requirements.
- Runner measured config includes action ids, skill bundle digests, manifest hashes,
  schema hashes, connector roles, output schemas, state bucket, state key, and proxy
  identity pins.
- Runtime operational config may include timeouts, display names, audit sink, and endpoint
  URLs whose hosts are already pinned by measured policy.

---

## 13. Guarantees

- **G-R1 No local secrets.** Long-lived credentials and provider auth material never exist
  locally after enrollment.
- **G-R2 No runner credentials.** The runner never receives plaintext credentials, wallet
  secrets, OAuth tokens, provider signing keys, or auth headers.
- **G-R3 No runner internet egress.** Production runners cannot call public provider APIs
  directly.
- **G-R4 Measured skill authority.** Only pinned skill digests and manifests can request
  delegated egress or side effects.
- **G-R5 Authoritative determination before side effect.** No side effect is submitted
  until static policy, input schema, private validations, idempotency, and
  consequential-field derivation pass.
- **G-R6 Schema declassification.** Outputs are validated against declared schemas and max
  byte sizes before local return.
- **G-R7 Fail closed.** Missing policy, invalid input, connector failure, attestation
  failure, state tamper, provider-policy mismatch, or output-schema failure denies without
  private data return.
- **G-R8 Auditable outcomes.** Allowed, denied, and failed outcomes produce secret-free
  hash-chained audit records.

---

## 14. Invariants

- **I-R1** The local agent never receives connector credentials, raw provider auth
  material, or private connector responses.
- **I-R2** Runners never receive credentials or provider signing material.
- **I-R3** Action id selects a measured skill action and manifest; request fields cannot
  select code, egress, connector scopes, or output policy.
- **I-R4** Core modules do not import provider SDKs or skill packages.
- **I-R5** Input schema validation and static authorization complete before proxy egress.
- **I-R6** Proxy validates credential and delegation policy before unwrap, mint, sign, or
  injection.
- **I-R7** Side effects happen only through the proxy using declared connector roles,
  action ids, and egress hosts.
- **I-R8** Runner network policy blocks direct public egress.
- **I-R9** Side-effecting requests require idempotency keys, but durable operation identity
  is runner-derived.
- **I-R10** Same caller idempotency key with different canonical input is rejected.
- **I-R11** Receipts are durably committed before success returns.
- **I-R12** Output validation rejects extra fields and raw provider payloads.
- **I-R13** Pre-side-effect denials use one constant caller-facing code per action.
- **I-R14** Audit contains metadata only, never secrets or private payload bodies.
- **I-R15** Provider policy state or evidence is checked before side effects when declared.
- **I-R16** Multiple runners coordinate by the runner-derived operation key: the first
  create-if-absent write wins and every other attempt returns its receipt or a retryable
  error.
- **I-R17** `submitted` is appended before provider side effect.
- **I-R18** After `submitted`, retries return the receipt or an exact stored provider retry;
  never blind resubmission.
- **I-R19** Runner durable state is app-sealed/MACed and bound to object path, schema,
  action, operation, and predecessor evidence.
- **I-R20** Cloud Storage is not used for hard multi-object aggregate invariants.

---

## 15. Tests

Core unit tests:

- skill registry rejects unknown action, duplicate action id, missing schema, unpinned skill
  digest, and manifest/schema hash mismatch
- core dependency guard fails if agent, runner, or proxy imports provider SDKs or
  `confidant-skills/*`
- canonicalization stable across JSON order
- input schema rejects unknown fields and consequential fields not in schema
- idempotency accepts same key and same canonical input, rejects conflicting input
- operation key ignores caller idempotency format
- state machine permits only valid transitions
- Cloud Storage writers use generation preconditions
- sealing/MAC fails on path, schema, predecessor, or hash tamper
- UDS peer credential mapping rejects claimed-principal mismatch
- proxy delegation rejects wrong runner, action, role, method, path, host, or evidence
  before credential unwrap
- output validation rejects raw provider response, extra fields, oversize output, and
  binary blobs
- redaction removes auth headers, connector response bodies, wallet secrets, JWTs, and
  token-looking values from errors and logs

Core integration/security tests:

- fake skill happy path through fake proxy returns only schema output
- disabling a pinned skill removes its action without changing core code
- invalid input/static denial never calls proxy
- undelegated runner context never unwraps credentials
- runner direct public egress test action fails before network connection
- 50 concurrent identical requests produce one provider call and one receipt
- concurrent conflicting idempotency rejects all but first committed input
- injected crashes before and after the provider call never cause blind resubmission
- crash after `submitted` re-issues the exact stored request under the stored provider key
  and commits `posted` from the provider's synchronous status, with no second side effect
- state tamper/rollback fails closed
- audit chain verifies over mixed allow, deny, and fail records
- production IAM denies delete on immutable runner-state prefixes

Validation before production:

- reproducible runner and proxy image builds with manifest hash reports
- attestation policy pinned separately for runner and proxy image/config
- skill manifest report for every enabled bundle: digest, schema hashes, test report,
  review record
- core dependency audit verifies no provider SDK imports or skill-package imports
- runner/proxy identity pins verified
- UDS ownership, directory mode, socket mode, and peer credentials verified
- runner state bucket, KMS key, IAM, retention, and no-delete policy verified
- no direct runner public egress; proxy-only provider egress
- end-to-end no-leak scan across local response, agent logs, runner logs, proxy logs,
  receipts, and audit
- disaster test for provider success plus receipt-write failure

---

## 16. Skill Author Checklist

A new trusted skill must provide:

- `SPEC.md` with action contract, threat model delta, manifest, invariants, tests, and
  operational runbook
- input and output schemas
- canonical operation-key components
- connector role declarations
- egress host/method/path declarations
- side-effect declaration and caps
- provider-policy evidence requirements, if any
- declassification schema and residual leak statement
- fake connector test fixtures
- replay, race, and crash tests
- no-leak tests for private context and provider responses
- manifest digest and reproducible build instructions

---

## 17. Deferred (Later Iterations)

This phase is intentionally scoped to a single-resource, synchronous, provider-idempotent
side effect. The machinery below is designed for but not built until an action needs it.
Each addition is additive: it changes neither the agent contract, the measured-skill model,
the proxy boundary, nor the declassification rules.

| Deferred | Add it when an action needs | Why it is not on the critical path now |
|---|---|---|
| Multi-resource lease-locks | to hold more than one resource at once | one obligation per action means the operation key already serializes it |
| Standalone effect ledger | a duplicate-effect guard independent of the operation key | the operation key is the obligation for this phase |
| Evidence-based reconciliation + operator queue | an asynchronous rail a synchronous retry cannot prove | the demo rail is synchronous and provider-idempotent |
| Cumulative / aggregate caps | any non-fake deployment | needs a transactional state layer or one conservative aggregate effect key |

Real lease-locks need lease expiry and a fencing token, not a bare Cloud Storage object —
which is exactly why they are deferred rather than approximated here.

---

## Open Questions

- Whether the core should later support WASM skills. If so, the same measured digest,
  host-services-only, no-provider-in-core rule applies.
- Whether some skill classes need a transactional state backend for aggregate invariants
  (see §17).

