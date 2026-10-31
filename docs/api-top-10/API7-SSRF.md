# API7: Server Side Request Forgery (SSRF)

## What and Why

SSRF occurs when a server makes a request to a destination influenced by a caller. The server may have access to loopback services, private networks, or metadata services that the caller cannot reach directly.

## Example and Failure Mode

A URL-fetch feature accepts `http://127.0.0.1/...` and makes the request. The vulnerable helper only demonstrates scheme-only acceptance; it never performs a network request.

## Reproduce Locally

```powershell
& "G:\py\python.exe" -m pytest tests/security/test_api7_ssrf.py tests/security/test_external_api_client.py -q
```

## Identify and Mitigate

Prefer configured service identifiers over arbitrary URLs. If URLs are required, allowlist exact destinations and schemes, validate ports, reject credentials/fragments, resolve DNS and reject every non-global answer, disable redirects, set timeouts, and cap response size. Revalidate DNS on each connection and retain TLS certificate verification. Network egress policy provides defense in depth.

`ExternalAPIClient` applies these controls and returns sanitized errors. The connector uses the canonical numeric IPs returned by the validating resolver, so the HTTP connection does not perform a second hostname lookup after validation; TLS verification still uses the requested hostname. The client requires an explicit host allowlist and is not exposed as an API endpoint.

## Test Coverage

Tests reject HTTP, private/reserved/mapped DNS and literal IPs, non-allowlisted hosts, URL credentials, unauthorized ports, redirects, oversized responses, malformed JSON, and unexpected content. The rebinding test intercepts aiohttp at `_wrap_create_connection` and verifies the exact socket-address tuple contains the validated IP; it stops before creating a socket, so it proves address handoff but not a completed TCP/TLS exchange. No test resolves or contacts internal or external targets.

## References

- [OWASP API7:2023 Server Side Request Forgery](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/)
