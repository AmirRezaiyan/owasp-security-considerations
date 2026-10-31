"""API5: function-level authorization protects privileged operations.

Scenario: an ordinary account calls a user-administration function directly.
Reference: https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/.
"""

from app.vulnerabilities import require_vulnerable_demos_enabled


def vulnerable_admin_action() -> bool:
    """Demonstrate a privileged operation that has no role check."""
    require_vulnerable_demos_enabled()
    return True


def secure_admin_action(*, role: str, is_active: bool) -> bool:
    """Allow the operation only for an active administrator."""
    return is_active and role == "admin"
