# Confidant - Phase 2 Core Runner

**Status:** Draft for build - V1 read-only confidential query runner
**Version:** 0.3
**Date:** 2026-09-13
**Parent:** [phase1-secrets-broker.md](./phase1-secrets-broker.md)
**First demo skill:** [github.repo_security_brief](../confidant-skills/github/repo_security_brief/SPEC.md)

Phase 2 V1 adds the smallest useful trusted execution layer: a measured runner for
read-only confidential queries. Local code stays untrusted. It can name a query and
provide selectors, but a measured enclave validates the request, fetches private data
through declared read-only connectors, and returns only schema-bounded declassified
output.

V1 deliberately avoids side effects. That removes operation ledgers, idempotency keys,
locks, provider idempotency material, and crash reconciliation from the critical path.
The design goal is simple, secure, and minimal.

If one sentence has to survive: **the runner executes measured read-only skills and
enforces connector scope plus declassification; skills contain the private business
logic.**

---

## 1. Scope

This spec defines the Phase 2 V1 core runner:

- `confidant-agent` to runner query API
- measured trusted-query skill registry
- runner host services exposed to skills
- sealed-source reads
- proxy-backed read-only connector calls
- schema-bounded declassification
- audit and redaction
- runner-to-proxy internal egress
- deployment, attestation, network, and test gates

This spec does **not** define side-effecting actions. Payments, refunds, cloud
remediation, trading, ticket updates, email sends, or any other mutation are deferred
until a later side-effect phase.

First V1 demo: `github.repo_security_brief.v1`, a private repository security posture
brief. Codex can invoke it from a natural prompt, the runner reads only fixed GitHub
security-alert endpoints through the proxy, and the local caller receives only a
schema-bounded prioritized brief.

---

## 2. Goals And Non-Goals

**Goals**

- Keep private business data, connector responses, credentials, auth material, and
  intermediate reasoning out of the local environment.
- Keep core modules minimal: stable protocol, policy, attestation, read connector,
  audit, and declassification machinery only.
- Let untrusted local agents trigger pre-reviewed read-only queries through narrow,
  measured trusted-skill code.
- Make every trusted query reproducible, measured, and pinned by attestation.
- Require every query to declare what it may read, call, inspect, persist, and return.
- Keep the proxy as the only credentialed egress component.
- Make all local outputs schema-bounded, byte-bounded, and explicitly declassified.
- Allow later side-effecting actions to reuse the registry, connector, audit, and
  declassification machinery without complicating V1.

**Non-goals**

- Any mutation or externally visible side effect.
- Running arbitrary caller-supplied code, query languages, scripts, SQL, GraphQL, or
  provider SDK workflows chosen by the caller.
- Importing provider SDKs or business workflows into `confidant-agent`,
  `confidant-runner`, or `confidant-proxy`.
- Making the local agent honest. It remains adversarial.
- Durable operation ledgers, idempotency, locks, provider idempotency keys, or crash
  reconciliation.
- Aggregate spend caps or multi-resource coordination.
- Local filesystem sandboxing for untrusted tools. That remains a separate phase.

---

## 3. Threat Model

The adversary is untrusted local code running with the user's ambient local privileges:
an agent plugin, dependency, MCP tool, generated script, or compromised CLI.

The adversary can:

- call the local Confidant agent or CLI
- choose query ids and query inputs
- retry, race, and replay requests
- inspect local env vars, dotfiles, logs, and process memory
- attempt prompt injection against the local agent
- exfiltrate anything returned locally

The adversary should not be able to:

- read connector credentials or auth material
- read raw private connector responses unless explicitly declassified
- modify skill policy, egress, code, schema, connector scope, or output policy at
  request time
- trigger write, mutate, send, create, update, delete, confirm, execute, or submit
  operations through the V1 runner
- cause raw provider responses or sensitive intermediate state to return locally
- bypass output policy by selecting alternate fields, formats, or response sizes

Out of scope:

- compromise of reviewed trusted skill code itself
- malicious authoritative systems returning false records
- provider compromise
- hiding the fact that a read request reached a provider from the provider
- side-channel resistance beyond the Confidential Space threat model

---

## 4. System Model

```text
LOCAL MACHINE (untrusted)                 GCP CONFIDENTIAL SPACE (trusted)
+----------------------+                  +------------------------------------+
| coding agent / tool  |                  | runner pool                        |
| chooses query+input   |                  | +------------------------------+   |
+----------+-----------+                  | | confidant-runner             |   |
           |                              | | read skill host + audit      |   |
           v                              | +---------------+--------------+   |
+----------------------+ mTLS + tailnet   |                 | internal egress   |
| confidant-agent       +----------------->|                 v                  |
| serve/query/mcp       |                  | +------------------------------+   |
+----------^-----------+                  | | confidant-proxy              |   |
           |                              | | credentialed egress broker   |   |
           |                              | +-------+----------------------+   |
           |                              +---------|--------------------------+
           |                                        |
           |                                        v
           |                                  SaaS/read APIs
           |                                        |
           +-------- declassified output <----------+
```

| Component | Runs | Responsibility | Sees private data? | Sees credentials? |
|---|---|---|---|---|
| `confidant-agent` | Local | Secretless local binary with `serve`, `query invoke`, and `mcp` modes | No | No |
| `confidant-runner` | Enclave | Minimal read-skill host; validates envelopes; provides sealed-source reads, read connector calls, audit, and output validation | Yes | No |
| `confidant-proxy` | Enclave | Minimal credentialed egress broker; unwraps/mints/signs/injects credentials; enforces declarative credential and delegation policy | Provider responses in transit | Yes, ephemeral |
| `confidant-skills` bundles | Compiled into the runner image | Trusted read recipes with provider schemas, parsing, private logic, output construction, tests, and fixtures | Yes | No |
| Runner audit/state bucket | Cloud Storage | Audit, optional immutable query records, capability snapshots, directory snapshots | Metadata and declassified outputs; app-sealed/MACed where app-owned | No |
| Credential store | Proxy-controlled | Sealed credentials plus credential/delegation policy | Policy metadata | Ciphertext at rest |

The core modules deliberately do not import provider SDKs or encode provider workflows.
The runner hosts measured read skills. The proxy performs generic credentialed egress.
Skills contain business-specific parsing, validation, and result construction.

---

## 5. Core Boundary

`confidant-agent` owns:

- local authenticated forwarding to the runner for query and MCP modes
- Phase 1 transparent proxy serving for existing credentialed API calls
- caller metadata collection for audit only
- returning declassified outputs
- no secret handling and no business authorization

`confidant-runner` owns:

- agent authentication and query routing
- measured skill registry and digest allowlist
- input envelope validation and canonicalization hooks
- static manifest authorization
- sealed-source reads
- proxy-backed read connector invocation
- output schema validation and max-byte enforcement
- panic hygiene, constant denial, redaction, and declassification boundary
- query audit and optional immutable query records

`confidant-proxy` owns:

- credential unwrap and DEK handling
- static, signed, and OAuth credential primitives
- credential policy and runner/query/role delegation policy
- host, method, path, endpoint-shape, and evidence checks
- egress allowlist, TLS validation, optional pinning
- credential scrubbing and credential-use audit

`confidant-skills` owns, per trusted read recipe:

- input and output schemas
- provider request/response schemas
- connector adapters over the runner connector interface
- private response parsing
- business policy
- result construction and proposed declassified fields
- skill-specific tests and fixtures

Core dependency rule: core packages may depend on standard runtime libraries and generic
Confidant interfaces only. Provider-specific dependencies and generated provider schemas
are allowed only under `confidant-skills/*`.

---

## 6. Trusted Query Skill Model

A trusted skill bundle exports one or more read-only queries. Each query has a manifest
pinned by digest:

```json
{
  "id": "example.lookup.v1",
  "kind": "trusted_query",
  "skill_bundle": "confidant-skills/example",
  "skill_version": "0.1.0",
  "skill_digest": "sha256:<pinned skill bundle digest>",
  "input_schema": "ExampleLookupSelector",
  "output_schema": "ExampleLookupView",
  "authoritative_bindings": {
    "record": { "source": "authoritative-system/prod", "key": "selector.id" },
    "eligibility": ["record.exists", "caller may learn this view"]
  },
  "connectors": [
    {
      "id": "authoritative-system/prod",
      "kind": "egress",
      "role": "source",
      "scopes": ["read"]
    }
  ],
  "egress": {
    "allow_hosts": ["api.example.com"],
    "allow_methods": ["GET", "HEAD"],
    "allow_paths": ["/v1/records/*"]
  },
  "declassify": {
    "mode": "schema",
    "schema": "ExampleLookupView",
    "max_bytes": 4096,
    "residual_leak": "<declared residual>"
  },
  "limits": {
    "timeout_ms": 10000,
    "rpm": 30,
    "max_connector_response_bytes": 1048576
  }
}
```

The manifest, schema hashes, connector roles, output schema, declassification policy,
and skill digest are part of the runner measured allowlist. A caller can select only a
query id. It cannot choose code, a skill bundle, connector scope, egress host, output
policy, or declassification mode.

Each connector declares a `kind`:

- `sealed_source`: measured fixtures or signed directory/capability snapshots, read
  locally through `QueryContext`
- `egress`: credentialed read call brokered by the proxy

Only `egress` connectors carry egress host/path declarations, and only they reach the
network.

### V1 Read-Only Rule

V1 egress supports `GET` and `HEAD` only. Endpoint allowlists are still required because
method alone is not a complete read-only guarantee. APIs that require `POST` for
read-only search, GraphQL, export jobs, or async reports are deferred until the runner has
explicit endpoint-level read semantics and stronger response controls.

### Skill Interface

Each query implements the runner host interface:

```go
type Query interface {
    ID() string
    Manifest() Manifest
    ValidateInput(json.RawMessage) (CanonicalInput, error)
    Run(ctx QueryContext, in CanonicalInput) (QueryResult, error)
    Declassify(result QueryResult) (json.RawMessage, error)
}
```

`QueryContext` is a capability object, not a general runtime. It exposes only:

- declared read-only egress connector calls through the proxy-backed connector interface
- declared sealed-source reads
- audit helpers
- bounded time helpers
- manifest, schema, and capability metadata

It must not expose raw network clients, write connector methods, filesystem authority,
process spawning, environment variables, plaintext credentials, direct response
streaming to local callers, or mutation-oriented state APIs.

### Admissibility

A query is admissible for V1 only if:

- all connector calls are read-only by declared method, host, path, scope, and proxy
  delegation policy
- caller input is selectors plus explicitly marked non-consequential presentation hints
- no caller input is interpreted as a provider query language, endpoint path, projection,
  SQL, GraphQL, script, or filter expression
- declassification is schema-bounded and byte-bounded
- private validation denials can be returned with a constant caller-facing code when
  membership or eligibility leaks matter
- connector response sizes, timeouts, and call counts are bounded

If a use case needs mutation, arbitrary caller-provided queries, async exports, streaming
raw data, or provider-side jobs, it is not registered in V1.

### Schemas, Bindings, And Loading

- **Schemas.** `input_schema` and `output_schema` name Go structs. Input is decoded with
  unknown-field rejection; output is built only from declared result fields. A canonical
  hash of each schema is pinned in the measured allowlist, so any schema change changes
  the measurement. The core ships no dynamic schema language.
- **Bindings are declarative.** `authoritative_bindings` and `eligibility` are measured,
  human-reviewed statements of what the skill must prove. The runner does not evaluate
  them and ships no expression engine; the skill's `Run` code enforces them.
- **Loading.** Skills are compiled into the runner image and registered at build time.
  `skill_digest` is the hash of the skill package plus its embedded sealed sources.
  Enabling or disabling a query is a runner config flag over the registry, not a core
  code change. Separately-loadable measured bundles are deferred.

---

## 7. Local Agent Modes

V1 uses one local binary with three modes:

```text
confidant-agent serve
confidant-agent query invoke <query_id> --input '{...}'
confidant-agent mcp
```

All three modes share the same local configuration root and trust material:

- runner/broker tailnet endpoint
- device client certificate and key for mTLS
- runner/broker SPKI pin
- caller metadata collection
- timeouts and retry policy

`serve` is the Phase 1 transparent proxy mode. It handles `HTTPS_PROXY`, the local
name-constrained MITM CA, intercepted hosts, `cfdt:` refs, and forwarding to
`confidant-proxy`.

`query invoke` is the human and CI diagnostic path for Phase 2. It does not use
`HTTPS_PROXY`, the local MITM CA, or `cfdt:` refs. It calls the runner's
`/v1/queries/{query_id}` endpoint directly over mTLS/tailnet and prints the
declassified result.

`mcp` is the primary agent integration path. It exposes read-only MCP tools backed by the
same direct runner client used by `query invoke`. The MCP bridge is local and secretless;
it should expose one focused tool per enabled query, with a tool name, description, JSON
schema, and read-only annotation. It should not expose a generic arbitrary query tool by
default.

At startup, `mcp` fetches the runner's public query catalog and maps each enabled query to
one MCP tool. The catalog is for ergonomics only; it contains no private data, no
credential refs, and no connector responses. The runner remains authoritative for every
invocation and revalidates query id, input schema, manifest policy, connector scope, and
output policy on each call.

The shared implementation unit is a secretless runner client library used by both
`query invoke` and `mcp`. The transparent proxy pipeline is separate, but it shares config
loading, device identity, endpoint pins, and caller metadata helpers.

---

## 8. Request And Response Contract

Public catalog request:

```json
GET /v1/queries
```

The response is a public, measured tool catalog for local display and MCP tool
registration:

```json
{
  "queries": [
    {
      "id": "example.lookup.v1",
      "tool_name": "confidant_example_lookup",
      "description": "Look up the approved public view of an example record.",
      "input_schema": { "type": "object" },
      "read_only": true
    }
  ]
}
```

The catalog must not include private data, credential refs, raw connector metadata, or
unbounded examples. A stale or tampered local catalog cannot grant authority because
`POST /v1/queries/{query_id}` validates the measured registry again.

Query invocation request:

```json
POST /v1/queries/{query_id}
{
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
- Unknown fields, oversize inputs, malformed selectors, consequential values, and schema
  mismatches fail before any connector call.
- No caller-supplied idempotency key exists in V1. Read queries may include an optional
  caller trace id later, but it is audit-only.

Runner-to-agent response:

```json
{
  "query_id": "example.lookup.v1",
  "status": "ok",
  "result": {
    "selector_id": "source:12345"
  }
}
```

Denials use a single constant caller-facing code for all private validation failures in a
query. Specific reasons live only in enclave audit.

---

## 9. Runner Pipeline

1. Authenticate agent mTLS identity and enforce tailnet ingress.
2. For `GET /v1/queries`, return the public measured query catalog.
3. For `POST /v1/queries/{query_id}`, parse query id, resolve pinned skill query, verify skill digest and manifest/schema
   hashes against the measured allowlist.
4. Validate request size, content type, and JSON envelope.
5. Call skill input validation and canonicalize input.
6. Run static manifest authorization:
   - query is enabled
   - connector ids, roles, scopes, hosts, methods, and paths are measured
   - all egress methods are V1 read methods
   - limits are within runner maximums
7. Construct a `QueryContext` containing only declared sealed-source and read-only egress
   capabilities for this query invocation.
8. Let the skill fetch private context and compute a private result.
9. Ask the skill to declassify the result into the declared output shape.
10. Validate output schema, reject extra fields, reject raw connector responses, and enforce
   max bytes.
11. Append query audit and return the declassified output.

If any step fails, the runner audits once, discards private context, and returns either a
generic transport/configuration error or the query's constant denial. No durable operation
state is required because no side effect can occur.

---

## 10. Proxy Read Egress Pipeline

Runner-to-proxy read requests include query context:

```json
{
  "ref": "cfdt:provider/prod",
  "context": {
    "runner_principal": "runner:default",
    "query_id": "example.lookup.v1",
    "invocation_id": "qry_abc123",
    "connector_role": "source"
  },
  "upstream": {
    "method": "GET",
    "url": "https://api.example.com/v1/records/12345",
    "headers": { "accept": "application/json" }
  }
}
```

The proxy:

1. Authenticates runner identity from transport.
2. Binds transport identity to `runner_principal`; rejects mismatches.
3. Resolves `ref` to credential policy.
4. Verifies host, method, path, endpoint shape, connector role, and declared query id.
5. Verifies delegate policy names the runner principal, query id, and role.
6. Verifies rate, concurrency, response-size, and declarative provider-policy evidence
   required by the credential policy.
7. Unwraps, mints, signs, or injects credential material.
8. Calls upstream through egress allowlist and TLS verification.
9. Scrubs credential reflections from response metadata and errors.
10. Appends credential-use audit.
11. Returns upstream response only to the runner.

The proxy must not parse business objects or execute provider SDK workflows. It can
enforce declarative policy and generic credential primitives.

---

## 11. State And Audit

V1 has no side-effect operation ledger. Production runner state is limited to audit,
optional immutable query invocation records, capabilities, and directories.

| State | Purpose |
|---|---|
| Audit | Hash-chained allow/deny/fail metadata |
| Query records | Optional immutable metadata for one invocation; never authoritative for correctness |
| Capabilities | Signed standing-authorization snapshots |
| Directories | Signed or measured authoritative lookup snapshots |

Cloud Storage rules:

- Use `ifGenerationMatch=0` for create-if-absent immutable audit/query records.
- Mutable indexes are caches only.
- App-seal or MAC every app-owned state record with a runner-state key distinct from the
  proxy credential KEK.
- Associated data binds record type, object path, query id, invocation id, schema version,
  and capability/directory hashes when present.
- Fail closed on MAC failure, rollback evidence, unexpected generation, or invalid
  signature.
- Runner IAM must not have production delete permission for audit or immutable query
  record prefixes.

Default object layout:

```text
gs://confidant-runner-state/
  audit/YYYY/MM/DD/<event_id>.json.enc
  queries/YYYY/MM/DD/<invocation_id>.json.enc
  capabilities/<capability_id>/<version>.json
  directories/<directory_id>/<version>.json
```

Audit records include query-safe metadata only: query id, invocation id, caller metadata,
connector ids, safe selector hash or explicitly public selector, status, denial class,
output schema, output byte count, and timing. They do not include raw private payloads,
raw connector responses, credentials, auth headers, or token-looking values.

---

## 12. Transports And Deployment

`confidant-agent` to runner:

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
- Runner measured config includes query ids, skill bundle digests, manifest hashes,
  schema hashes, connector roles, output schemas, state bucket, state key, and proxy
  identity pins.
- Runtime operational config may include timeouts, display names, audit sink, and endpoint
  URLs whose hosts are already pinned by measured policy.

---

## 13. Guarantees

- **G-R1 No local secrets.** Long-lived credentials and provider auth material never exist
  locally after enrollment.
- **G-R2 No runner credentials.** The runner never receives plaintext credentials,
  provider signing keys, OAuth tokens, or auth headers.
- **G-R3 No runner internet egress.** Production runners cannot call public provider APIs
  directly.
- **G-R4 Measured skill authority.** Only pinned skill digests and manifests can request
  delegated read egress.
- **G-R5 Read-only egress.** V1 connector calls are restricted to declared read methods,
  hosts, paths, scopes, and proxy delegation policy.
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
  material, or raw private connector responses.
- **I-R2** Runners never receive credentials or provider signing material.
- **I-R3** Query id selects a measured skill query and manifest; request fields cannot
  select code, egress, connector scopes, or output policy.
- **I-R4** Core modules do not import provider SDKs or skill packages.
- **I-R5** Input schema validation and static authorization complete before proxy egress.
- **I-R6** Proxy validates credential and delegation policy before unwrap, mint, sign, or
  injection.
- **I-R7** Connector calls happen only through the proxy using declared connector roles,
  query ids, hosts, methods, and paths.
- **I-R8** Runner network policy blocks direct public egress.
- **I-R9** V1 exposes no write, mutate, send, create, update, delete, confirm, execute, or
  submit connector capability.
- **I-R10** `QueryContext` exposes only capabilities declared by the selected manifest.
- **I-R11** Output validation rejects extra fields and raw provider payloads.
- **I-R12** Private validation denials use one constant caller-facing code per query.
- **I-R13** Audit contains metadata only, never secrets or private payload bodies.
- **I-R14** Provider policy state or evidence is checked before connector calls when
  declared.
- **I-R15** Runner durable state is app-sealed/MACed where app-owned and bound to object
  path, schema, query, invocation, and relevant version evidence.
- **I-R16** The runner evaluates no manifest expressions; `authoritative_bindings` and
  `eligibility` are declarative and enforced by skill code.
- **I-R17** `sealed_source` reads are local and never traverse the proxy; only `egress`
  connectors reach the network.
- **I-R18** Connector response size and query output size are both bounded.

---

## 15. Tests

Core unit tests:

- `confidant-agent query invoke` and `confidant-agent mcp` use the shared runner client,
  not the transparent proxy/MITM path
- `confidant-agent mcp` exposes one read-only tool per enabled query and does not expose a
  generic arbitrary query tool by default
- public query catalog contains only safe metadata and cannot authorize an invocation
- skill registry rejects unknown query, duplicate query id, missing schema, unpinned skill
  digest, manifest/schema hash mismatch, and a connector `kind` that is not
  `sealed_source` or `egress`
- registry rejects V1 manifests with side-effect declarations or non-read egress methods
- core dependency guard fails if agent, runner, or proxy imports provider SDKs or if core
  packages import `confidant-skills/*`
- canonicalization stable across JSON order
- input schema rejects unknown fields and consequential fields not in schema
- manifest authorization rejects undeclared connector id, role, host, method, path, scope,
  response limit, or output schema
- output validation rejects raw provider response, extra fields, oversize output, and
  binary blobs
- redaction removes auth headers, connector response bodies, JWTs, and token-looking values
  from errors and logs

Core integration/security tests:

- Codex can call a Confidant query through MCP from a natural-language prompt and receives
  only the declassified schema output
- GitHub repo security demo path can be invoked through MCP from "check my private repo
  security posture" and returns counts/prioritized findings without raw alert payloads,
  secret values, source snippets, credentials, or auth headers
- fake read skill happy path through fake proxy returns only schema output
- disabling a pinned skill removes its query without changing core code
- invalid input/static denial never calls proxy
- undelegated runner context never unwraps credentials
- runner direct public egress test query fails before network connection
- `sealed_source` reads open no network socket; only `egress` connectors reach the proxy
- private validation denials are caller-indistinguishable where configured
- connector response over max bytes fails closed and returns no partial private data
- output schema failure audits and returns no partial private data
- state tamper/rollback fails closed for app-owned audit/query records
- audit chain verifies over mixed allow, deny, and fail records
- production IAM denies delete on immutable runner-state prefixes

Validation before production:

- reproducible runner and proxy image builds with manifest hash reports
- attestation policy pinned separately for runner and proxy image/config
- skill manifest report for every enabled bundle: digest, schema hashes, test report,
  review record
- core dependency audit verifies no provider SDK imports or skill-package imports in core
- runner/proxy identity pins verified
- UDS ownership, directory mode, socket mode, and peer credentials verified
- runner state bucket, KMS key, IAM, retention, and no-delete policy verified
- no direct runner public egress; proxy-only provider egress
- end-to-end no-leak scan across local response, agent logs, runner logs, proxy logs,
  query records, and audit

---

## 16. Skill Author Checklist

A new trusted read skill must provide:

- `SPEC.md` with query contract, threat model delta, manifest, invariants, tests, and
  operational runbook
- input and output schemas
- connector role declarations
- egress host/method/path declarations
- response-size and output-size limits
- provider-policy evidence requirements, if any
- declassification schema and residual leak statement
- fake connector test fixtures
- no-leak tests for private context and provider responses
- manifest digest and reproducible build instructions

---

## 17. Deferred

The machinery below is intentionally not part of V1.

| Deferred | Add it when a use case needs | Why it is not in V1 |
|---|---|---|
| Side-effecting actions | payments, refunds, sends, creates, updates, deletes, trades, remediations | requires operation identity, idempotency, crash recovery, and reconciliation |
| Durable operation ledger | duplicate-effect prevention | no V1 side effects |
| Caller idempotency index | same idempotency key with different mutation input must be rejected | no V1 mutations |
| Multi-resource lease-locks | more than one mutable resource at once | no V1 mutations |
| Standalone effect ledger | duplicate-effect guard independent of operation key | no V1 effects |
| Evidence-based reconciliation + operator queue | asynchronous rails or jobs | no V1 async effects |
| Cumulative / aggregate caps | non-fake payment or spend workflows | no V1 spend |
| Read-only `POST`/GraphQL/search | APIs that encode reads as request bodies | needs endpoint-level read semantics and stricter request/output controls |
| Separately-loadable skill bundles | adding skills without rebuilding the runner image | V1 compiles skills into one measured image |
| WASM skills | stronger runtime isolation for skill code | compile-time Go skills are simpler for V1 |

---

## Resolved For First Demo

- The first V1 read-only demo skill is `github.repo_security_brief.v1`.
- The demo uses fixed GitHub REST read endpoints for repository Dependabot alerts, code
  scanning alerts, and secret scanning alerts.
- The caller may supply only a repository selector. The runner validates the selector
  against configured repository authorization before GitHub egress.
- The local output is a bounded posture brief: coverage status, aggregate counts, risk
  level, and the top prioritized remediation items.
- Secret values, source snippets, raw alert payloads, credentials, and auth headers are
  never declassified.
