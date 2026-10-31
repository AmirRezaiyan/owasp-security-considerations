"""API8: unsafe defaults and verbose errors can expose internals or enable abuse.

Scenario: an exception response includes a database URL or filesystem path.
Reference: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/.
"""

from app.vulnerabilities import require_vulnerable_demos_enabled


def vulnerable_error_response(error: Exception) -> dict[str, str]:
    """Demonstrate leaking an exception string to the API caller."""
    require_vulnerable_demos_enabled()
    return {"detail": str(error)}


def secure_error_response() -> dict[str, str]:
    """Return a stable public message without implementation details."""
    return {"detail": "An unexpected internal server error occurred."}
