import pytest

from app.config import settings
from app.vulnerabilities.api3_property_authorization import (
    secure_update_profile,
    vulnerable_update_profile,
)


def test_property_authorization_rejects_mass_assignment(enable_vulnerable_demos):
    vulnerable = {"display_name": "Learner", "is_admin": False}
    vulnerable_update_profile(vulnerable, {"is_admin": True})
    assert vulnerable["is_admin"] is True

    with pytest.raises(ValueError, match="cannot be changed"):
        secure_update_profile({"display_name": "Learner", "is_admin": False}, {"is_admin": True})


def test_property_authorization_validates_values_and_fields():
    with pytest.raises(ValueError, match="must be text"):
        secure_update_profile({}, {"bio": 12})

    with pytest.raises(ValueError, match="cannot be changed"):
        secure_update_profile({}, {"unknown": "value"})

    with pytest.raises(ValueError, match="allowed length"):
        secure_update_profile({}, {"display_name": "x" * 81})

    assert secure_update_profile({}, {"display_name": "Learner"}) == {"display_name": "Learner"}


def test_property_authorization_enforces_boundaries_without_mutating_profile():
    profile = {"display_name": "Learner", "bio": "Original"}
    updated = secure_update_profile(
        profile,
        {"display_name": "L" * 80, "bio": "B" * 2000},
    )

    assert updated == {"display_name": "L" * 80, "bio": "B" * 2000}
    assert profile == {"display_name": "Learner", "bio": "Original"}

    with pytest.raises(ValueError):
        secure_update_profile({}, {"display_name": " " * 3})
    with pytest.raises(ValueError):
        secure_update_profile({}, {"bio": "B" * 2001})


def test_property_vulnerability_demo_requires_opt_in(monkeypatch):
    monkeypatch.setattr(settings, "enable_vulnerable_demos", False)

    with pytest.raises(RuntimeError, match="disabled"):
        vulnerable_update_profile({}, {"is_admin": True})


def test_task_update_schema_does_not_apply_unapproved_properties(
    api_client,
    authenticate_as,
    regular_user,
    user_factory,
):
    authenticate_as(regular_user)
    other_user = user_factory(username="other-user")
    created = api_client.post(
        "/api/v1/tasks",
        json={"title": "Owned task"},
    )

    response = api_client.patch(
        f"/api/v1/tasks/{created.json()['id']}",
        json={"title": "Updated task", "owner_id": other_user.id},
    )

    assert response.status_code == 422

    unchanged = api_client.get(f"/api/v1/tasks/{created.json()['id']}")
    assert unchanged.json()["owner_id"] == regular_user.id
    assert unchanged.json()["title"] == "Owned task"
