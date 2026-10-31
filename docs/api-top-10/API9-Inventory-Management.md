# API9: Improper Inventory Management

## What and Why

Untracked API hosts, versions, routes, or environments leave forgotten interfaces available without current security controls or documentation. Attackers can find and use stale functionality that teams no longer monitor.

## Example and Failure Mode

An old API version remains deployed after clients migrate to v1. `vulnerable_route_inventory` models publishing every route record, including inactive versions, using local data only.

## Reproduce Locally

```powershell
& "G:\py\python.exe" -m pytest tests/security/test_api9_inventory.py -q
```

## Identify and Mitigate

Maintain a source-of-truth inventory of API versions, owners, environments, and lifecycle state. Compare deployed routes with that inventory, document deprecation timelines, remove retired interfaces through a controlled change, and include shadow/staging APIs in review.

This repository currently mounts a single `/api/v1` router. The helper filters a sample inventory; it is not an automated discovery or deployment scanner.

## Test Coverage

Tests show an inactive v0 route included by the vulnerable helper and excluded by the current-version filter.

## References

- [OWASP API9:2023 Improper Inventory Management](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/)
