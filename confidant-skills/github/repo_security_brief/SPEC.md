# GitHub Repo Security Brief Skill

**Status:** First Phase 2 V1 demo - draft for build
**Query id:** `github.repo_security_brief.v1`
**Skill path:** `confidant-skills/github/repo_security_brief`
**Runner phase:** Phase 2 V1 read-only confidential query runner
**Date:** 2026-09-13

This skill answers: **"check my private repo security posture."**

It lets Codex or a human invoke one measured read-only query against a configured private
GitHub repository. The runner reads GitHub security-alert data through the proxy, ranks
what matters first, and returns only a bounded declassified brief.

If one sentence has to survive: **Codex can learn what to fix first without receiving the
GitHub credential, raw alert payloads, secret values, or private intermediate data.**

---

## 1. User Story

From a Codex workspace:

```text
User: Check my private repo security posture.
Codex -> confidant-agent mcp -> github.repo_security_brief.v1
Confidant -> declassified brief
Codex: You have 2 critical dependency alerts, 1 high code-scanning alert, and no
declassified secret values. Start with package X in requirements.txt.
```

Direct diagnostic path:

```bash
confidant-agent query invoke github.repo_security_brief.v1 \
  --input '{"owner":"OWNER","repo":"REPO"}'
```

---

## 2. V1 Contract

Input is a selector only:

```json
{
  "owner": "OWNER",
  "repo": "REPO"
}
```

Rules:

- `owner` and `repo` are GitHub path components, not URLs and not query strings.
- Unknown fields are rejected.
- The runner validates `owner/repo` against a sealed configured repository allowlist
  before any GitHub call.
- Unknown or unauthorized repositories return the same constant denial and make no
  provider egress.
- Caller-provided filters, search strings, sort expressions, projections, or page tokens
  are not accepted in V1.

Output is a bounded brief:

```json
{
  "repo": { "owner": "OWNER", "name": "REPO" },
  "generated_at": "2026-09-13T12:00:00Z",
  "risk_level": "high",
  "coverage": [
    { "source": "dependabot", "status": "ok", "truncated": false },
    { "source": "code_scanning", "status": "ok", "truncated": false },
    { "source": "secret_scanning", "status": "unavailable", "truncated": false }
  ],
  "counts": {
    "dependabot": { "critical": 1, "high": 2, "medium": 4, "low": 0 },
    "code_scanning": { "critical": 0, "high": 1, "medium": 3, "low": 0 },
    "secret_scanning": { "open": 0, "publicly_leaked": 0, "active_or_unknown": 0 }
  },
  "top_findings": [
    {
      "priority": 1,
      "kind": "dependabot",
      "severity": "critical",
      "title": "Upgrade vulnerable direct runtime dependency",
      "package": "example-package",
      "ecosystem": "pip",
      "manifest_path": "requirements.txt",
      "alert_number": 12,
      "why_first": "Critical direct runtime dependency with a patched version available.",
      "remediation_hint": "Upgrade to the first patched version reported by GitHub."
    }
  ],
  "redactions": {
    "secret_values_removed": true,
    "source_snippets_removed": true,
    "raw_payloads_removed": true
  }
}
```

`top_findings` is capped at 10 items. Output is capped at 16 KiB.

---

## 3. GitHub Reads

The skill uses the GitHub REST API through one `egress` connector:

```json
{
  "id": "github/security-alerts",
  "kind": "egress",
  "role": "repo_security_source",
  "scopes": ["security_alerts.read"]
}
```

Allowed upstream calls:

| Source | Method | Path shape | Fixed query |
|---|---|---|---|
| Dependabot alerts | `GET` | `/repos/{owner}/{repo}/dependabot/alerts` | `state=open&per_page=100` |
| Code scanning alerts | `GET` | `/repos/{owner}/{repo}/code-scanning/alerts` | `state=open&per_page=100` |
| Secret scanning alerts | `GET` | `/repos/{owner}/{repo}/secret-scanning/alerts` | `state=open&per_page=100&hide_secret=true` |

The skill does not call GitHub GraphQL, search APIs, write APIs, update alert APIs,
autofix APIs, SARIF upload APIs, or repository content APIs in V1.

Reference API docs:

- GitHub Dependabot alerts:
  <https://docs.github.com/en/rest/dependabot/alerts>
- GitHub code scanning alerts:
  <https://docs.github.com/en/rest/code-scanning/code-scanning>
- GitHub secret scanning alerts:
  <https://docs.github.com/en/rest/secret-scanning/secret-scanning>

---

## 4. Credential And Policy

V1 uses an enrolled GitHub credential stored only behind `confidant-proxy`.

Recommended first credential shape:

- fine-grained personal access token
- limited to the demo repository or a small explicit repository set
- read permission for Dependabot alerts
- read permission for code scanning alerts
- read permission for secret scanning alerts
- short expiration where practical

The GitHub principal still needs whatever repository role GitHub requires for these
security-alert APIs. If a configured source is disabled, unavailable, or not accessible
to the credential, the skill reports source coverage rather than provider error bodies.

Later, the same skill can move to a GitHub App installation token without changing the
local agent or runner query contract.

Proxy delegate policy must bind:

- runner principal
- `query_id == "github.repo_security_brief.v1"`
- connector role `repo_security_source`
- host `api.github.com`
- method `GET`
- the configured repository path set
- fixed query parameter shapes

---

## 5. Declassification

Allowed local output:

- selected repository owner/name
- coverage status per source
- aggregate counts by source and severity
- risk level
- top prioritized findings
- package/ecosystem/manifest path for dependency alerts
- safe code-scanning rule name, severity, file path, and line when present
- secret-scanning secret type/display name, state, validity class, public-leak flag, and
  safe location path/line when present
- GitHub alert number and safe web URL when present

Never declassify:

- GitHub credential material or auth headers
- raw GitHub JSON responses
- secret values from secret scanning alerts
- source code snippets
- full alert descriptions
- arbitrary actor lists, assignees, comments, or dismissal metadata
- provider error bodies
- response fields not named in the output schema

The residual leak is intentional and bounded: a local caller learns that the configured
repository has the summarized alert posture returned in the schema.

---

## 6. Ranking

Findings are ranked deterministically:

1. Open secret-scanning alerts with `publicly_leaked == true`.
2. Open secret-scanning alerts with active or unknown validity.
3. Critical Dependabot alerts for direct runtime dependencies with a patched version.
4. Critical or high code-scanning alerts on the default branch.
5. High Dependabot alerts for direct runtime dependencies with a patched version.
6. Remaining medium and low alerts, grouped and sampled only if there is room.

Ties sort by severity, direct/runtime impact, patched-version availability, alert update
time, then alert number.

---

## 7. Failure Semantics

- Unauthorized repository selector: constant denial, no GitHub call.
- Unknown repository selector: same constant denial, no GitHub call.
- GitHub `403` or `404` for a configured source: mark that source as `unavailable` unless
  every source fails before useful output can be produced.
- GitHub rate limit or transient failure: mark that source as `failed` with no provider
  error body.
- Pagination beyond the first page: set `truncated=true`; do not follow pagination in
  the first implementation.
- Output-schema failure: deny and return no partial result.

If all configured sources fail, return the query's constant caller-facing failure code.
Detailed reasons live only in enclave audit.

---

## 8. Manifest Sketch

```json
{
  "id": "github.repo_security_brief.v1",
  "kind": "trusted_query",
  "skill_bundle": "confidant-skills/github/repo_security_brief",
  "skill_version": "0.1.0",
  "skill_digest": "sha256:<pinned skill bundle digest>",
  "input_schema": "GitHubRepoSecurityBriefInput",
  "output_schema": "GitHubRepoSecurityBrief",
  "authoritative_bindings": {
    "repository": {
      "source": "sealed_source/github-authorized-repos",
      "key": "canonical owner/repo selector"
    },
    "eligibility": ["repository is configured", "caller may learn this brief"]
  },
  "connectors": [
    {
      "id": "github-authorized-repos",
      "kind": "sealed_source",
      "role": "repo_authorization",
      "scopes": ["repository.read"]
    },
    {
      "id": "github/security-alerts",
      "kind": "egress",
      "role": "repo_security_source",
      "scopes": ["security_alerts.read"]
    }
  ],
  "egress": {
    "allow_hosts": ["api.github.com"],
    "allow_methods": ["GET"],
    "allow_paths": [
      "/repos/{owner}/{repo}/dependabot/alerts",
      "/repos/{owner}/{repo}/code-scanning/alerts",
      "/repos/{owner}/{repo}/secret-scanning/alerts"
    ]
  },
  "declassify": {
    "mode": "schema",
    "schema": "GitHubRepoSecurityBrief",
    "max_bytes": 16384,
    "residual_leak": "Configured repository alert posture is returned as aggregate counts and capped prioritized findings."
  },
  "limits": {
    "timeout_ms": 15000,
    "rpm": 20,
    "max_connector_response_bytes": 1048576,
    "max_connector_calls": 3
  }
}
```

---

## 9. Invariants

- **I-GH1** Unknown or unauthorized `owner/repo` is denied before proxy egress.
- **I-GH2** The caller cannot choose GitHub endpoint paths, query params, fields, filters,
  page tokens, GraphQL, or search strings.
- **I-GH3** All GitHub egress is `GET` to `api.github.com` and one of the three declared
  repository security-alert path shapes.
- **I-GH4** The proxy validates repository path scope before credential injection.
- **I-GH5** GitHub credential material is visible only to the proxy and never to the
  runner, agent, local caller, logs, query records, or audit payloads.
- **I-GH6** Secret-scanning `secret` values are dropped before result construction and are
  covered by explicit no-leak tests.
- **I-GH7** Raw GitHub response bodies are never declassified.
- **I-GH8** Per-source provider failures do not expose provider error bodies.
- **I-GH9** Output is schema-bound, byte-bound, and capped at 10 findings.
- **I-GH10** Pagination is not followed in V1; truncation is surfaced as metadata only.

---

## 10. Tests

Skill unit tests:

- input rejects unknown fields, URLs, path traversal, slashes inside owner/repo, oversized
  values, and missing owner/repo
- unauthorized repo selector returns the constant denial and does not call the fake proxy
- manifest rejects non-GET methods, undeclared paths, unfixed query params, and missing
  sealed-source authorization
- Dependabot fixture maps severity, package, ecosystem, manifest path, patched version,
  direct/runtime relationship, and alert number into safe findings
- code-scanning fixture maps severity, rule name, path, line, and alert number into safe
  findings without source snippets
- secret-scanning fixture maps secret type, state, validity, leak flags, path, line, and
  alert number without returning the secret value
- ranking is deterministic across mixed fixtures
- first-page overflow sets `truncated=true`
- output validation rejects extra fields and oversized output
- no-leak scan fails if output, logs, audit, or query records contain token-looking values,
  secret fixture strings, auth headers, raw JSON payloads, or provider error bodies

Demo integration test:

- Codex-compatible MCP client invokes `confidant_github_repo_security_brief` from the
  natural-language prompt "check my private repo security posture" and receives only the
  declassified schema output.

---

## 11. Coding Decision Log

No runner-design blocker remains for this demo. The implementation defaults are:

- use a fine-grained PAT first, then consider GitHub App installation tokens later
- use configured repository allowlisting before egress
- call one page per GitHub source and surface truncation
- tolerate unavailable code-scanning or secret-scanning sources with coverage metadata
- use explicit `owner` and `repo` fields in the runner API; the MCP bridge may infer those
  fields from the current git remote as a convenience, but the runner still treats them as
  ordinary selectors and validates them against the configured allowlist
