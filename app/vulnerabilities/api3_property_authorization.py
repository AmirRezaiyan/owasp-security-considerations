"""API3: callers must not control properties they are not authorized to change.

Scenario: a profile update accepts ``is_admin`` along with a display name.
Reference: https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/.
"""

from app.vulnerabilities import require_vulnerable_demos_enabled

EDITABLE_PROFILE_FIELDS = frozenset({"display_name", "bio"})


def vulnerable_update_profile(
    profile: dict[str, object],
    changes: dict[str, object],
) -> dict[str, object]:
    """Demonstrate mass assignment by applying every caller-supplied property."""
    require_vulnerable_demos_enabled()
    profile.update(changes)
    return profile


def secure_update_profile(
    profile: dict[str, object],
    changes: dict[str, object],
) -> dict[str, object]:
    """Apply only explicitly editable properties and reject unknown input."""
    unexpected = changes.keys() - EDITABLE_PROFILE_FIELDS
    if unexpected:
        raise ValueError("One or more profile fields cannot be changed.")
    if any(not isinstance(value, str) for value in changes.values()):
        raise ValueError("Profile values must be text.")
    if "display_name" in changes and (
        not changes["display_name"].strip() or not 1 <= len(changes["display_name"]) <= 80
    ):
        raise ValueError("Profile values exceed the allowed length.")
    if "bio" in changes and len(changes["bio"]) > 2000:
        raise ValueError("Profile values exceed the allowed length.")
    return {**profile, **changes}
