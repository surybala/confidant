# Confidant Skill - Pay Invoice (Stripe test mode)

**Status:** Draft v1 for Stripe test-mode demo  
**Version:** 0.2  
**Date:** 2026-09-12  
**Core dependency:** [Phase 2 Core Runner](../../../docs/phase2-runner-core.md)  
**Action id:** `payments.pay_invoice.v1`

This trusted skill settles a pre-approved invoice through a synchronous payment API. The v1
demo uses **Stripe in test mode**. It lives under `confidant-skills` because invoice
parsing, vendor-directory binding, amount derivation, Stripe request shaping, and
payment-specific policy are business logic, not core runner logic.

The rail is deliberately a **synchronous, provider-is-system-of-record** API. There is no
blockchain, no wallet, no transaction signing, no chain finality, and no
reconstruct-from-chain reconciliation. This keeps the demo focused on the one thing it is
meant to prove: **superior security of the Confidant runner around an economically
consequential action.**

If one sentence has to survive: **the caller names an invoice; the skill proves it is
already payable, derives the amount and destination from private authoritative state, asks
the proxy to submit one idempotent Stripe payment, and returns only a receipt.**

---

## 1. Demo Scope

The v1 demo uses:

- sealed fixture invoice store as the invoice source
- sealed fixture vendor directory as the destination-routing source
- Cloud Storage runner state for the operation ledger, receipts, and audit
- Stripe **test mode** as the payment rail (`api.stripe.com`)
- one synchronous `POST /v1/payment_intents` with `confirm=true`
- a Stripe **restricted key** (`rk_test_...`) scoped to writing PaymentIntents only
- fake money only (Stripe test mode)

The v1 demo does not use QuickBooks, live mode, real funds, arbitrary destinations, caller
provided amounts, cross-rail spend, or Confidant-side cumulative vendor/day spend caps.

---

## 2. Threat Model Delta

The core runner threat model applies. This skill additionally assumes:

- the local caller may choose invoice ids to try to learn private state
- the local caller may retry, race, or replay payment attempts
- the local caller may try to supply amount, currency, vendor, destination, or key material
- the local caller may try to pay already-paid, unapproved, unknown, over-cap, or
  non-allowlisted invoices
- Stripe (the provider) sees the payment; unlike a public chain, the payment is **not**
  broadcast to a public ledger, so recipient, amount, and timing are not publicly readable

Out of scope for this v1 demo:

- malicious fixture data signed by the operator
- Stripe compromise
- real AP system write-back
- production settlement accounting

---

## 3. Goals And Non-Goals

**Goals**

- Demonstrate the full Phase 2 shape using a real, economically consequential side effect.
- Keep all payment logic inside this skill bundle, not in runner/proxy/agent core.
- Prove selectors-only input, authoritative amount/destination derivation, allowlist, cap,
  approval, duplicate-payment guard, idempotency, and receipt-only declassification.
- Be repeatable in CI with a fake Stripe connector and fake fixture stores.
- Be runnable against real Stripe test mode with a restricted key.

**Non-goals**

- Live-mode payment or real funds.
- Arbitrary-destination payment.
- Human confirmation in the request path.
- Replacing Stripe's own controls (restricted-key scope, Radar, limits).
- Full QuickBooks integration in v1.
- Cross-rail or cumulative vendor/day spend caps.

---

## 4. Skill Manifest

```json
{
  "id": "payments.pay_invoice.v1",
  "kind": "trusted_skill_action",
  "skill_bundle": "confidant-skills/payments/pay_invoice",
  "skill_version": "0.2.0",
  "skill_digest": "sha256:<pinned skill bundle digest>",
  "input_schema": "PayInvoiceSelector",
  "output_schema": "PayInvoiceReceipt",
  "authoritative_bindings": {
    "vendor_id": { "source": "invoice.vendor_id" },
    "destination_ref": { "source": "vendor-directory/demo", "key": "invoice.vendor_id" },
    "amount_minor": { "source": "invoice.balance_usd" },
    "currency": { "source": "invoice.currency" },
    "eligibility": [
      "invoice.exists",
      "invoice.status == 'unpaid'",
      "invoice.approval_status == 'approved_for_payment'",
      "invoice.vendor_id in vendor-directory/demo.allowlist",
      "invoice.balance_usd > 0",
      "invoice.balance_usd <= side_effects[0].max_amount_usd"
    ]
  },
  "connectors": [
    { "id": "fixture-invoices/demo", "role": "invoice_source", "scopes": ["invoice.read"] },
    { "id": "fixture-vendor-directory/demo", "role": "vendor_source", "scopes": ["vendor.read"] },
    { "id": "stripe/test", "role": "payment_rail", "scopes": ["payment.create"] }
  ],
  "egress": {
    "allow_hosts": ["api.stripe.com"],
    "allow_methods": ["POST"],
    "allow_paths": ["/v1/payment_intents"]
  },
  "side_effects": [
    {
      "kind": "payment",
      "rail": "stripe-test",
      "currency": "usd",
      "max_amount_usd": "25.00"
    }
  ],
  "declassify": {
    "mode": "schema",
    "schema": "PayInvoiceReceipt",
    "max_bytes": 4096,
    "residual_leak": "<=1 bit: a payable invoice was paid to an allowlisted vendor"
  },
  "limits": {
    "timeout_ms": 15000,
    "rpm": 10
  }
}
```

---

## 5. Request And Response

Request:

```json
POST /v1/actions/payments.pay_invoice.v1
{
  "idempotency_key": "invoice-pay:fixture:inv_2026_0001",
  "input": {
    "invoice_id": "fixture:inv_2026_0001",
    "memo": "September hosting"
  },
  "caller": { "pid": 4821, "exe": "node", "workspace": "confidant-demo" }
}
```

Input rules:

- `invoice_id` selects the obligation.
- `memo` is non-consequential and may be echoed.
- `idempotency_key` is checked for caller consistency only; it is not the durable
  operation identity.
- `amount`, `currency`, `vendor_id`, `destination`, `customer`, and any key material are
  rejected if present.

Response:

```json
{
  "action_id": "payments.pay_invoice.v1",
  "status": "posted",
  "receipt": {
    "receipt_id": "rcpt_...",
    "invoice_id": "fixture:inv_2026_0001",
    "vendor_id": "acme",
    "amount": "12.34",
    "currency": "usd",
    "provider": "stripe",
    "payment_intent_id": "pi_...",
    "payment_status": "succeeded",
    "idempotency_key": "invoice-pay:fixture:inv_2026_0001",
    "posted_at": "2026-09-12T00:00:00Z"
  }
}
```

Not returned:

- full invoice body
- vendor directory or the Stripe destination reference (by default)
- Stripe restricted key or any auth header
- raw Stripe response
- rejection reason beyond a constant denial

---

## 6. Authoritative Fixture State

Demo invoice fixture:

```json
{
  "invoice_id": "fixture:inv_2026_0001",
  "vendor_id": "acme",
  "status": "unpaid",
  "approval_status": "approved_for_payment",
  "balance_usd": "12.34",
  "currency": "usd",
  "updated_at": "2026-09-12T00:00:00Z"
}
```

Demo vendor directory fixture:

```json
{
  "directory_id": "vendor-directory/demo",
  "version": "2026-09-12.demo",
  "vendors": {
    "acme": {
      "display_id": "acme",
      "destination_ref": "cus_DEMO_ACME",
      "allowlisted": true
    }
  }
}
```

Fixture rules:

- Fixtures are measured with the skill or signed and verified before use.
- The vendor directory is the fund-routing root of trust; the caller can never supply
  `destination_ref`.
- No action path may mutate the invoice fixtures or the vendor directory.
- Unknown invoice, paid invoice, unapproved invoice, non-allowlisted vendor, unknown
  destination, unsupported currency, and over-cap amount all return the **same**
  caller-facing denial.

---

## 7. Amount Rules

Stripe amounts are integers in the currency's minor unit (cents for USD).

- the invoice amount is decimal USD in `balance_usd`
- amount must be positive
- amount must have at most 2 decimal places
- amount is converted to minor units by exact decimal scaling: `amount * 100`
- rounding is forbidden; more than 2 decimal places fails closed
- the minor-unit amount must be a positive integer
- amount must be within `max_amount_usd`

The canonical payment-request key covers: action id, operation key, invoice id, vendor id,
destination ref, currency, minor-unit amount, Stripe endpoint path, and the runner-minted
Stripe idempotency key.

---

## 8. Stripe Connector

The skill uses the proxy-backed connector role `payment_rail` with ref `cfdt:stripe/test`.

Stripe request shape (form-encoded, per Stripe's API):

```text
POST https://api.stripe.com/v1/payment_intents
Content-Type: application/x-www-form-urlencoded
Idempotency-Key: <runner-minted UUIDv4>

amount=1234&currency=usd&customer=cus_DEMO_ACME&confirm=true
&payment_method=pm_card_visa&metadata[invoice_id]=fixture:inv_2026_0001
&metadata[vendor_id]=acme
```

`pm_card_visa` is Stripe's test payment method that confirms synchronously to `succeeded`,
so the demo needs no webhook or polling.

Credential handling:

- the skill never receives the Stripe restricted key or any auth header
- the proxy injects `Authorization: Bearer <rk_test_...>` using the existing generic
  `static` credential primitive (`template: "Bearer {secret}"`) — no new credential module
- the proxy credential policy for `cfdt:stripe/test` restricts host (`api.stripe.com`),
  method (`POST`), endpoint path (`/v1/payment_intents`), action id
  (`payments.pay_invoice.v1`), runner principal, and connector role (`payment_rail`)
- the runner persists the Stripe idempotency key before `submitted`

Provider-native controls (defense in depth, not parsed by Confidant):

- the Stripe key is a **restricted key** scoped to writing PaymentIntents only
- optional Stripe Radar / amount limits apply on Stripe's side
- there is no per-payment provider-policy read or preflight; least privilege is enforced by
  the restricted-key scope, so no separate policy-verification round trip is needed

---

## 9. Idempotency And Reconciliation

Business idempotency is owned by the core runner Cloud Storage ledger. Stripe's
`Idempotency-Key` is a provider-side duplicate guard. Because Stripe is synchronous and is
the system of record, reconciliation is a single call, not a subsystem.

Operation identity:

```text
operation: hash(action_id + invoice_id + policy_hash + capability_hash + directory_hash)
obligation resource: payable/fixture-invoices/demo/<invoice_id>
```

Rules:

- the runner mints a UUIDv4 Stripe idempotency key and stores it before `submitted`
- retry with the same operation reuses the same key and the exact same request
- retry never mints a fresh Stripe idempotency key for the same operation

Reconciliation (synchronous, no chain):

1. If a receipt is committed, return it.
2. If `submitted` exists and no receipt exists, re-`POST` the exact stored request with the
   stored `Idempotency-Key`. Stripe returns the same PaymentIntent rather than creating a
   second one.
3. Read `payment_status` from that response. Commit `posted` when it is `succeeded`.
4. If Stripe reports a terminal failure, record `failed_before_side_effect` semantics for
   the operation and return a constant denial (no money moved).
5. Never create a second payment for the same operation while `submitted` or `posted`
   evidence exists.

There is no operator-reconciliation queue for the demo: a synchronous idempotent re-call
resolves every crash window deterministically.

---

## 10. Authorization And No Confirmation

There is no per-payment Confidant confirmation. Standing authorization is:

- signed or measured vendor directory (destination binding)
- per-invoice cap (`max_amount_usd`)
- restricted-key scope on Stripe's side
- required `approved_for_payment` status on the invoice

The local request has no amount, currency, destination, or key dial. The worst case for
compromised local code is paying already-unpaid, already-approved, allowlisted fixture
invoices within the per-invoice cap earlier than intended.

> **Known limitation (inherited from core):** there is no cumulative cap in v1, so the
> aggregate worst case is (per-invoice cap x number of approved allowlisted invoices). For
> the test demo the fixture set is tiny and the money is fake. A cumulative cap or a single
> conservative aggregate effect key is required before any non-fake deployment.

---

## 11. Skill Invariants

- **I-PAY1** Request input is selectors-only: `invoice_id` plus non-consequential `memo`.
- **I-PAY2** Amount comes from invoice `balance_usd`, never from the request.
- **I-PAY3** Vendor comes from the invoice, never from the request.
- **I-PAY4** Destination comes from the vendor directory keyed by invoice vendor, never from
  the request.
- **I-PAY5** The vendor directory is immutable to the skill action.
- **I-PAY6** Invoice must exist, be unpaid, and be `approved_for_payment`.
- **I-PAY7** Unknown, paid, unapproved, non-allowlisted, over-cap, and unsupported-currency
  denials are caller-indistinguishable.
- **I-PAY8** Currency and destination are pinned by fixtures; the rail is Stripe test mode.
- **I-PAY9** Minor-unit conversion is exact; more than 2 decimals fails closed.
- **I-PAY10** The proxy refuses Stripe credential use without matching host, path, method,
  action id, runner principal, and connector role.
- **I-PAY11** `submitted` is durable before the Stripe call.
- **I-PAY12** The Stripe idempotency key is UUIDv4, stored before `submitted`, and reused.
- **I-PAY13** After `submitted`, the skill returns the receipt, an exact idempotent retry,
  or a constant denial; it never creates a second payment.
- **I-PAY14** The receipt excludes the destination reference by default.
- **I-PAY15** Raw invoice, vendor directory, Stripe key, auth header, and raw Stripe
  response are never declassified.
- **I-PAY16** Live mode and real funds are not supported by this v1 demo skill.

---

## 12. Tests

Unit tests:

- input rejects amount, currency, vendor, destination, customer, key material
- invoice id parser accepts only fixture invoice ids
- amount parser rejects zero, negative, over-cap, malformed, and >2 decimal places
- minor-unit conversion is exact (`12.34` -> `1234`)
- canonical payment-request key is stable and includes policy/capability/directory hashes
- output schema rejects extra fields and raw provider response
- constant denial responses are byte-identical for all pre-side-effect denials

Integration with a fake Stripe connector:

- happy path pays the fixture invoice and returns receipt only
- unknown / paid / unapproved / non-allowlisted / over-cap invoices are each denied before
  the Stripe connector is called
- fake Stripe rejects a non-UUIDv4 idempotency key
- duplicate request returns the committed receipt with no second provider call
- two different caller idempotency keys for the same invoice produce exactly one payment
- crash after `submitted` re-sends the exact stored request and Stripe returns the same
  PaymentIntent (no double charge)
- terminal Stripe failure yields a constant denial and no committed receipt

Security tests:

- no local response, logs, receipts, or audit contain the invoice body, vendor directory,
  destination reference, Stripe key, auth header, or raw Stripe response
- the skill cannot call hosts, methods, or paths outside the manifest
- the proxy refuses a Stripe call without the correct action id, runner principal, connector
  role, endpoint path, and method
- disabling or omitting the skill removes the action without touching core runner/proxy

End-to-end demo (the attack script that sells the security):

- deploy the dev runner with the sealed fixture invoice and vendor directory
- run the fake-Stripe happy path in CI
- run the real Stripe **test-mode** happy path and confirm `succeeded` in the Stripe
  dashboard
- **attack 1 (steal credential):** local caller has no key to exfiltrate
- **attack 2 (redirect):** local caller supplies `destination`/`amount`/`currency` -> input
  rejected -> constant denial
- **attack 3 (inflate):** local caller names an unapproved or over-cap invoice -> enclave
  reads authoritative state -> same constant denial, indistinguishable from attack 2
- **attack 4 (exfiltrate):** local caller cannot obtain the invoice body or destination;
  only the schema receipt returns
- **attack 5 (replay/race):** N concurrent identical requests produce one Stripe payment and
  one receipt

---

## 13. Demo Runbook Checklist

Before running the real Stripe test-mode demo:

- skill digest pinned in the runner measured allowlist
- fixture invoice and vendor directory measured or signature-verified
- Stripe **restricted test key** (`rk_test_...`, PaymentIntents write) enrolled through the
  Phase 1 secret path
- proxy credential policy for `cfdt:stripe/test` installed (host/path/method/action/role
  bound)
- vendor `destination_ref` (`cus_DEMO_ACME`) created in the Stripe test account
- runner state bucket and runner-state KMS key configured
- no runner public egress verified
- fake-Stripe test suite passing
- no-leak scan passing

Invocation:

```bash
confidant action invoke payments.pay_invoice.v1 \
  --idempotency-key invoice-pay:fixture:inv_2026_0001 \
  --input '{"invoice_id":"fixture:inv_2026_0001","memo":"September hosting"}'
```

Expected result:

- status `posted`
- receipt includes invoice id, vendor id, amount, currency, provider, payment intent id,
  receipt id
- the local response does not include the destination reference or the raw Stripe response
- the Stripe test dashboard shows one `succeeded` PaymentIntent for the fixture amount

---

## 14. Open Questions For This Skill

- Whether to model the vendor destination as a Stripe customer, a Connect account, or a
  payout target for a more realistic "pay a vendor" direction. The demo uses a pinned
  customer for the least setup; the security properties are identical.
- Whether future production payment skills should write payment status back to the invoice
  system of record after settlement. This v1 fixture demo does not.
- Cumulative caps are out of scope until a transactional state layer or a single
  conservative aggregate effect key is introduced.

---

## References

- Stripe PaymentIntents: https://stripe.com/docs/api/payment_intents
- Stripe Idempotent requests: https://stripe.com/docs/api/idempotent_requests
- Stripe test cards / payment methods: https://stripe.com/docs/testing
- Stripe restricted API keys: https://stripe.com/docs/keys#limit-access
