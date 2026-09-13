# Confidant - Phase 2: Confidential Actions

**Status:** Split spec index  
**Version:** 0.3  
**Date:** 2026-09-12  
**Parent:** [phase1-secrets-broker.md](./phase1-secrets-broker.md)

Phase 2 is now split into two authoritative specs:

- [Phase 2 Core Runner](./phase2-runner-core.md) defines the production-grade,
  provider-neutral trusted runner/proxy/skill-host architecture.
- [Pay Invoice skill](../confidant-skills/payments/pay_invoice/SPEC.md)
  defines the first trusted payment recipe, scoped to a Stripe test-mode demo.

This file remains as the Phase 2 navigation page so existing links keep working. The
security boundary is intentionally split:

- The core runner stays minimal, stable, and flexible enough to host many trusted use
  cases without importing provider SDKs or business workflows.
- Each trusted use case lives in `confidant-skills/*` with its own manifest, schemas,
  provider adapters, business logic, invariants, tests, and runbook.

If one sentence has to survive: **the core hosts measured skills and enforces the
boundaries; skills contain the business logic.**

---

## Core Contract

The core spec owns:

- `confidant-agent`, `confidant-runner`, and `confidant-proxy` responsibilities
- measured trusted-skill registry
- runner host services and action interface
- proxy-backed connector interface
- durable operation/effect state
- idempotency, locks, reconciliation, audit, and declassification
- runner-to-proxy internal egress
- deployment, attestation, network, and production validation gates

See [phase2-runner-core.md](./phase2-runner-core.md).

---

## First Skill

The first skill is the payment demo:

```text
confidant-skills/payments/pay_invoice
action id: payments.pay_invoice.v1
rail: Stripe test mode (synchronous PaymentIntent)
```

The payment skill owns invoice fixtures, vendor-directory binding, amount derivation,
Stripe request shaping, payment-specific invariants, and demo runbook.

See [confidant-skills/payments/pay_invoice/SPEC.md](../confidant-skills/payments/pay_invoice/SPEC.md).

