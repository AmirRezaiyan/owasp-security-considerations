# API3: Broken Object Property Level Authorization

## What and Why

API3 covers excessive data exposure and mass assignment: a caller can read or change object properties outside their authorization. This can expose sensitive fields or allow privilege changes.

## Example and Failure Mode

A profile endpoint accepts `{"display_name":"Sam","is_admin":true}` and copies every field onto the model. The local `vulnerable_update_profile` helper demonstrates that unsafe assignment; it never touches a real user row.

## Reproduce Locally

```powershell
& "G:\py\python.exe" -m pytest tests/security/test_api3_property_authorization.py -q
```

## Identify and Mitigate

Compare request and response schemas with the caller's permissions. Use explicit allowlisted update fields, reject unexpected fields where appropriate, validate type and size, and serialize through minimal response schemas. Never accept role, ownership, or account-state properties from an ordinary user unless a separately authorized workflow permits it.

The task API uses separate create/update/response schemas, and `UserPublic` excludes email and password hash fields. Keep these schemas aligned with the authorization model.

## Test Coverage

The tests show the vulnerable helper changing `is_admin`, verify secure rejection of privileged/unknown fields and invalid values, and exercise the task API's typed update contract.

## References

- [OWASP API3:2023 Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
