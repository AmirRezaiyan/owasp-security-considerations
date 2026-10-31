"""API1: BOLA occurs when object access is not scoped to the caller.

Scenario: a caller changes a task identifier and reads another user's task.
The vulnerable helper is a local data-only simulation; it never queries the app DB.
Reference: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/.
"""

from app.vulnerabilities import require_vulnerable_demos_enabled


def vulnerable_read_object(
    objects: dict[int, dict[str, object]],
    object_id: int,
) -> dict[str, object] | None:
    """Demonstrate an object lookup that forgets to check its owner."""
    require_vulnerable_demos_enabled()
    return objects.get(object_id)


def secure_read_object(
    objects: dict[int, dict[str, object]],
    object_id: int,
    requester_id: int,
) -> dict[str, object] | None:
    """Return an object only when its stored owner matches the requester."""
    record = objects.get(object_id)
    if record is None or record.get("owner_id") != requester_id:
        return None
    return record
