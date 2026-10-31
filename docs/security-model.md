# Security Model

## Identity and Authorization

Passwords are hashed with Argon2 through `pwdlib`. Access tokens are signed using the configured HS256 key and include subject, issue time, and expiry. Protected routes resolve the token subject to an active database user. The task API scopes every object query to the current user's ID; the admin user list uses the shared `require_admin` permission check.

## Data Exposure

Authentication responses do not return password hashes. User and admin responses use the public `UserPublic` schema containing only an ID and username. Request schemas reject unknown properties, and validation responses omit submitted input values. Unexpected application exceptions receive a generic response rather than the exception text. The application adds baseline anti-sniffing, frame, and referrer headers.

## Resource and Abuse Controls

Task pagination bounds `skip` and `limit`. Login and registration use Redis-backed limits keyed by a one-way hash of the client IP; Redis failures return service unavailable rather than bypassing the control. These controls do not constitute a complete abuse-prevention or business-flow system.

## Outbound Requests

The external client requires an exact hostname allowlist, HTTPS, port 443, and a globally routable destination. Its resolver rejects private, loopback, link-local, and other non-global DNS results, disables DNS caching and redirects, and preserves normal TLS certificate verification. It applies timeouts, a streaming response-size cap, JSON content checks, and caller-supplied Pydantic validation. It is a reusable service, not a currently exposed endpoint.

## Educational Vulnerabilities

Vulnerable examples are isolated Python helpers, not API routes. They only manipulate local values and cannot issue network requests. `ENABLE_VULNERABLE_DEMOS` defaults to false; production settings reject true. Tests enable the helpers only with a function-scoped setting override. Never enable the flag in a shared or production deployment.

## Operational Limits

The project is an educational baseline. It has no schema migration lifecycle, production secret rotation, refresh-token/revocation system, complete account recovery workflow, or comprehensive deployment hardening. Review [SECURITY.md](../SECURITY.md) and the [OWASP category guides](api-top-10/) before adapting it.
