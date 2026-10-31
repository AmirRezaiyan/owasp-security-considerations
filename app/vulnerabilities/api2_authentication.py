"""API2: weak identity proof or token lifecycle controls enable account takeover.

Scenario: a token with no expiry remains usable indefinitely after issuance.
These helpers only construct in-memory claims and never authenticate real users.
Reference: https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/.
"""

from datetime import datetime

from app.vulnerabilities import require_vulnerable_demos_enabled


def vulnerable_token_claims(subject: str) -> dict[str, str]:
    """Demonstrate a token claim set without issuance or expiry timestamps."""
    require_vulnerable_demos_enabled()
    return {"sub": subject}


def secure_token_claims(
    subject: str,
    issued_at: int,
    expires_at: int,
    *,
    maximum_lifetime_seconds: int = 1800,
) -> dict[str, str | int]:
    """Build bounded token claims after validating subject and lifetime."""
    if (
        not subject.strip()
        or type(issued_at) is not int
        or type(expires_at) is not int
        or type(maximum_lifetime_seconds) is not int
        or maximum_lifetime_seconds <= 0
        or issued_at <= 0
        or expires_at <= issued_at
    ):
        raise ValueError("Invalid token claims.")
    if expires_at - issued_at > maximum_lifetime_seconds:
        raise ValueError("Token lifetime exceeds the allowed maximum.")
    return {"sub": subject, "iat": issued_at, "exp": expires_at}


def token_is_current(
    claims: dict[str, object],
    now: datetime,
    *,
    maximum_lifetime_seconds: int = 1800,
) -> bool:
    """Check timestamp types, issuance time, lifetime, and expiry."""
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    now_timestamp = int(now.timestamp())
    return (
        type(issued_at) is int
        and type(expires_at) is int
        and type(maximum_lifetime_seconds) is int
        and maximum_lifetime_seconds > 0
        and 0 < issued_at <= now_timestamp < expires_at
        and expires_at - issued_at <= maximum_lifetime_seconds
    )
