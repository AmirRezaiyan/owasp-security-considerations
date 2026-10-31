"""API6: sensitive business flows need abuse-aware limits, not just auth.

Scenario: repeated checkout requests reserve more units than a per-customer cap.
The helper is a deterministic check; production inventory must be updated atomically.
Reference: https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/.
"""

from app.vulnerabilities import require_vulnerable_demos_enabled


def vulnerable_can_purchase() -> bool:
    """Demonstrate a purchase decision with no quantity or flow limits."""
    require_vulnerable_demos_enabled()
    return True


def secure_can_purchase(
    *,
    quantity: int,
    already_purchased: int,
    available_stock: int,
    customer_limit: int,
) -> bool:
    """Check positive quantity, current stock, and per-customer limits."""
    if quantity < 1 or already_purchased < 0 or available_stock < 0 or customer_limit < 1:
        return False
    return quantity <= available_stock and already_purchased + quantity <= customer_limit
