# Confidant Skills

Trusted skills are measured recipe bundles hosted by the Phase 2 core runner.

Core modules stay provider-neutral:

- `confidant-agent` forwards query calls and returns declassified outputs.
- `confidant-runner` hosts pinned read skills and enforces connector scope, audit, and output
  validation.
- `confidant-proxy` performs declarative credentialed egress.

Provider schemas, business logic, result construction, and use-case-specific tests
belong under `confidant-skills/*`.

Current read-only skills:

- [github/repo_security_brief](./github/repo_security_brief/SPEC.md) - private
  repository security posture brief, the first Phase 2 V1 demo.

Deferred side-effect skills:

- [payments/pay_invoice](./payments/pay_invoice/SPEC.md) - Stripe test-mode invoice
  payment design, deferred until after read-only runner V1.
