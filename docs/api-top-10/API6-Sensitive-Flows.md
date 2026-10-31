# API6: Unrestricted Access to Sensitive Business Flows

## What and Why

Automated abuse of legitimate workflows can cause financial loss, unfair allocation, inventory depletion, or operational harm even when authentication and ordinary authorization are correct.

## Example and Failure Mode

A signed-in customer repeats a purchase or reservation flow to exceed a per-customer limit. `vulnerable_can_purchase` demonstrates a flow check that always succeeds; it does not make an order or modify stock.

## Reproduce Locally

```powershell
& "G:\py\python.exe" -m pytest tests/security/test_api6_sensitive_flows.py -q
```

## Identify and Mitigate

Identify high-impact flows and define business invariants such as per-user and per-resource limits, stock constraints, idempotency keys, abuse detection, velocity controls, and risk-based review. Enforce inventory updates atomically in the persistence layer, with database constraints or transactions that preserve inventory consistency; a separate pre-check followed by an update is vulnerable to concurrent requests. Rate limits should reflect business impact, not only raw request count, and should complement idempotency and abuse detection.

The repository does not implement a purchase endpoint or inventory ledger. The secure helper is a teaching example of input and business-limit checks; it does not prevent concurrent purchase abuse and is not a transactional commerce implementation.

## Test Coverage

Tests cover the helper's quantity, stock, customer cap, and invalid-count cases. Login and registration rate-limit behavior is covered in the authentication suite.

## References

- [OWASP API6:2023 Unrestricted Access to Sensitive Business Flows](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/)
