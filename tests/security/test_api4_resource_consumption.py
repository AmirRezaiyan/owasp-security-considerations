import pytest
from fastapi import status

from app.vulnerabilities.api4_resource_consumption import secure_page, vulnerable_page


def test_resource_demo_contrasts_unbounded_and_bounded_pages(enable_vulnerable_demos):
    items = list(range(250))

    assert len(vulnerable_page(items)) == 250
    assert len(secure_page(items, skip=0, limit=500, maximum_limit=100)) == 100


@pytest.mark.parametrize(("skip", "limit"), [(-1, 1), (0, 0)])
def test_secure_page_rejects_invalid_pagination(skip, limit):
    with pytest.raises(ValueError):
        secure_page([], skip=skip, limit=limit)


def test_secure_page_rejects_excessive_offsets_and_boolean_values():
    with pytest.raises(ValueError):
        secure_page([], skip=10_001, limit=1)
    with pytest.raises(ValueError):
        secure_page([], skip=True, limit=1)


@pytest.mark.parametrize("query", ["limit=101", "skip=10001"])
def test_tasks_endpoint_enforces_pagination_bounds(
    api_client,
    authenticate_as,
    regular_user,
    query,
):
    authenticate_as(regular_user)

    response = api_client.get(f"/api/v1/tasks?{query}")

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
