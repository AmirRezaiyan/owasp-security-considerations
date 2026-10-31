from app.vulnerabilities.api9_inventory import (
    current_route_inventory,
    vulnerable_route_inventory,
)


def test_inventory_demo_hides_inactive_old_versions(enable_vulnerable_demos):
    routes = [
        {"path": "/api/v1/tasks", "version": "v1", "active": True},
        {"path": "/api/v0/tasks", "version": "v0", "active": False},
    ]

    assert len(vulnerable_route_inventory(routes)) == 2
    assert current_route_inventory(routes) == [routes[0]]
