# Confidant - Phase 2: Confidential Queries

**Status:** Split spec index
**Version:** 0.4
**Date:** 2026-09-13
**Parent:** [phase1-secrets-broker.md](./phase1-secrets-broker.md)

Phase 2 V1 is now scoped to read-only confidential queries:

- [Phase 2 Core Runner](./phase2-runner-core.md) defines the production-grade,
  provider-neutral trusted query runner/proxy/skill-host architecture.
- The first demo skill is
  [GitHub Repo Security Brief](../confidant-skills/github/repo_security_brief/SPEC.md):
  "check my private repo security posture."
- Side-effecting trusted actions, including
  [Pay Invoice](../confidant-skills/payments/pay_invoice/SPEC.md), are deferred until
  the read-only runner, connector scoping, audit, and declassification boundary are
  implemented and validated.

This file remains as the Phase 2 navigation page so existing links keep working. The
security boundary is intentionally split:

- The core runner stays minimal, stable, and flexible enough to host many trusted use
  cases without importing provider SDKs or business workflows.
- Each trusted use case lives in `confidant-skills/*` with its own manifest, schemas,
  provider adapters, business logic, invariants, tests, and runbook.

If one sentence has to survive: **the V1 core hosts measured read-only skills and
enforces connector scope plus declassification; skills contain the private business
logic.**

---

## Core Contract

The core spec owns:

- `confidant-agent`, `confidant-runner`, and `confidant-proxy` responsibilities
- measured trusted-skill registry
- runner host services and query interface
- proxy-backed read-only connector interface
- audit and declassification
- runner-to-proxy internal egress
- deployment, attestation, network, and production validation gates

See [phase2-runner-core.md](./phase2-runner-core.md).

---

## First V1 Demo Skill

The first skill is a private GitHub repository security posture brief:

```text
confidant-skills/github/repo_security_brief
query id: github.repo_security_brief.v1
connector: GitHub REST API, read-only repository security alerts
```

The demo lets Codex answer a natural prompt such as "check my private repo security
posture" by invoking a measured runner query. The runner reads GitHub security-alert
data through the proxy and returns only a bounded prioritization brief. It does not
return raw GitHub payloads, secret values, source snippets, credentials, or auth headers.

See [confidant-skills/github/repo_security_brief/SPEC.md](../confidant-skills/github/repo_security_brief/SPEC.md).

---

## Deferred Side-Effect Skill

The payment demo is preserved as a future side-effect skill design, not the V1 runner
implementation target:

```text
confidant-skills/payments/pay_invoice
action id: payments.pay_invoice.v1
rail: Stripe test mode (synchronous PaymentIntent)
```

Before implementing this payment skill, a later phase must add operation identity,
idempotency, locks or equivalent duplicate-effect prevention, and crash reconciliation.

See [confidant-skills/payments/pay_invoice/SPEC.md](../confidant-skills/payments/pay_invoice/SPEC.md).
