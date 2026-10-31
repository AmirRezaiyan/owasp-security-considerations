"""API4: unbounded inputs and work can exhaust CPU, memory, or paid resources.

Scenario: an endpoint returns an entire dataset because the caller requests an
unbounded page size. This module uses local lists only.
Reference: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/.
"""

from app.vulnerabilities import require_vulnerable_demos_enabled


def vulnerable_page(items: list[object], skip: int = 0) -> list[object]:
    """Demonstrate a page operation that has no maximum result count."""
    require_vulnerable_demos_enabled()
    return items[skip:]


def secure_page(
    items: list[object],
    *,
    skip: int,
    limit: int,
    maximum_limit: int = 100,
    maximum_skip: int = 10_000,
) -> list[object]:
    """Validate pagination values and cap the amount of returned data."""
    if (
        type(skip) is not int
        or type(limit) is not int
        or type(maximum_limit) is not int
        or type(maximum_skip) is not int
        or skip < 0
        or skip > maximum_skip
        or limit < 1
        or maximum_limit < 1
        or maximum_skip < 0
    ):
        raise ValueError("Pagination values are outside the allowed range.")
    return items[skip : skip + min(limit, maximum_limit)]
