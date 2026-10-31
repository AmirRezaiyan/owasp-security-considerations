# API8: Security Misconfiguration

## What and Why

Misconfiguration includes insecure defaults, excessive debug output, unintended documentation or CORS exposure, and inconsistent hardening across environments. These weaknesses can expose internals or make other attacks easier.

## Example and Failure Mode

An unhandled exception is serialized with its full message, leaking a database path or credential. `vulnerable_error_response` models that leak using a local exception only.

## Reproduce Locally

```powershell
& "G:\py\python.exe" -m pytest tests/security/test_api8_misconfiguration.py tests/security/test_api2_broken_authentication.py -q
```

## Identify and Mitigate

Review debug and API-doc settings, CORS origins, error handling, default credentials, headers, dependency versions, and environment-specific configuration. Use safe defaults, fail startup for unsafe production settings, and expose generic client errors while retaining appropriately protected server diagnostics.

Production settings reject weak/default JWT keys, debug mode, and enabled vulnerable examples. The main app disables docs and OpenAPI in production, sanitizes unexpected and request-validation errors, applies `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy` headers, and exposes only a minimal health status.

## Test Coverage

Tests verify generic error output and production rejection of weak secrets, debug mode, and vulnerable-demo activation.

## References

- [OWASP API8:2023 Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
