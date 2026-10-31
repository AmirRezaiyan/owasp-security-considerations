"""API9: undocumented or stale API versions expand the attack surface.

Scenario: an old route remains active after the current version is released.
This module filters a local route inventory and does not inspect a live server.
Reference: https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/.
"""

from app.vulnerabilities import require_vulnerable_demos_enabled


def vulnerable_route_inventory(
    routes: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Demonstrate publishing every route, including inactive old versions."""
    require_vulnerable_demos_enabled()
    return list(routes)


def current_route_inventory(routes: list[dict[str, object]]) -> list[dict[str, object]]:
    """Return only explicitly active v1 route records."""
    return [
        route for route in routes if route.get("active") is True and route.get("version") == "v1"
    ]
