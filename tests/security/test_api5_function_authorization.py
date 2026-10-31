import pytest
from fastapi import status

from app.vulnerabilities.api5_function_authorization import (
    secure_admin_action,
    vulnerable_admin_action,
)


def test_admin_can_list_users_without_sensitive_fields(
    api_client,
    authenticate_as,
    admin_user,
    regular_user,
):
    authenticate_as(admin_user)

    response = api_client.get("/api/v1/admin/users")

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == [
        {"id": admin_user.id, "username": admin_user.username},
        {"id": regular_user.id, "username": regular_user.username},
    ]
    assert "hashed_password" not in response.text
    assert "email" not in response.text


@pytest.mark.parametrize("query", ["limit=101", "skip=10001"])
def test_admin_user_listing_bounds_pagination(
    api_client,
    authenticate_as,
    admin_user,
    query,
):
    authenticate_as(admin_user)

    response = api_client.get(f"/api/v1/admin/users?{query}")

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


def test_regular_user_cannot_access_admin_routes(
    api_client,
    authenticate_as,
    regular_user,
):
    authenticate_as(regular_user)

    response = api_client.get("/api/v1/admin/users")

    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_unauthenticated_user_cannot_access_admin_routes(api_client):
    response = api_client.get("/api/v1/admin/users")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_inactive_administrator_cannot_access_admin_routes(
    api_client,
    authenticate_as,
    user_factory,
):
    inactive_admin = user_factory(username="inactive-admin", is_admin=True, is_active=False)
    authenticate_as(inactive_admin)

    response = api_client.get("/api/v1/admin/users")

    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_function_authorization_demo_requires_active_admin(enable_vulnerable_demos):
    assert vulnerable_admin_action()
    assert secure_admin_action(role="admin", is_active=True)
    assert not secure_admin_action(role="user", is_active=True)
    assert not secure_admin_action(role="admin", is_active=False)
