# API2: Broken Authentication

## What and Why

Broken authentication includes weak credential verification, inadequate brute-force protection, and tokens that are missing or incorrectly validate identity and expiry. Successful attacks can turn unauthenticated requests into account access.

## Example and Failure Mode

A service issues a bearer token with a subject but no expiry, or accepts credentials without limiting repeated guesses. `vulnerable_token_claims` models the missing-expiry case without issuing a real token. The production implementation hashes passwords with Argon2, validates required JWT claims and signature, checks the active user, and rate-limits login through Redis.

## Reproduce Locally

```powershell
& "G:\py\python.exe" -m pytest tests/security/test_api2_authentication.py tests/security/test_api2_broken_authentication.py -q
```

The first file contrasts local claim dictionaries; the existing authentication tests exercise password hashing, token validation, and rate-limit behavior without using external services.

## Identify and Mitigate

Check password storage, generic login errors, token algorithms and required claims, expiration handling, inactive-user checks, and abuse limits. Use established password hashing and token libraries, validate tokens server-side, protect signing keys, and make rate limiting fail closed when the limiter is unavailable.

## Test Coverage

Tests cover correct and incorrect passwords, expired/wrong-signature/wrong-algorithm tokens, missing claims, rate-limit boundaries, Redis failure, and demo token lifetime validation.

## References

- [OWASP API2:2023 Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
