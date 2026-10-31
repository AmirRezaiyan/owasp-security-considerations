# API10: Unsafe Consumption of APIs

## What and Why

Unsafe consumption happens when a service trusts data received from an upstream API without validating its transport, content, structure, or business meaning. A trusted partner can be compromised, misconfigured, or return malformed data.

## Example and Failure Mode

A partner response contains an unexpected administrator field, a value outside allowed bounds, or an HTML error body that application code treats as JSON. `vulnerable_trust_partner_response` demonstrates unvalidated pass-through using a local dictionary.

## Reproduce Locally

```powershell
& "G:\py\python.exe" -m pytest tests/security/test_api10_unsafe_consumption.py tests/security/test_external_api_client.py -q
```

## Identify and Mitigate

Treat upstream APIs as untrusted. Use an explicit destination allowlist and TLS, bound connection/read time and response size, avoid redirects, validate the content type, parse safely, and validate data with a strict schema before use. Map failures to sanitized errors and never place credentials in URLs or client-visible messages.

`ExternalAPIClient` implements the transport boundary; `PartnerRecord` demonstrates strict field/type/range validation, including rejection of unknown fields and boolean-as-integer values. The service requires callers to provide their own response model and exact host allowlist.

## Test Coverage

Mocked tests cover destination validation, DNS rebinding, private/reserved IP rejection, redirect disabling, response-size/content-type checks, malformed JSON, strict schema boundaries, and sanitized failures. They make no network calls.

## References

- [OWASP API10:2023 Unsafe Consumption of APIs](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/)
