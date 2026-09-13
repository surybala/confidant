# Confidant Skills

Trusted skills are measured recipe bundles hosted by the Phase 2 core runner.

Core modules stay provider-neutral:

- `confidant-agent` forwards action calls and returns declassified outputs.
- `confidant-runner` hosts pinned skills and enforces state, locks, audit, and output
  validation.
- `confidant-proxy` performs declarative credentialed egress.

Provider schemas, business logic, transaction construction, and use-case-specific tests
belong under `confidant-skills/*`.

Current skills:

- [payments/pay_invoice](./payments/pay_invoice/SPEC.md) - Stripe test-mode invoice
  payment demo.

