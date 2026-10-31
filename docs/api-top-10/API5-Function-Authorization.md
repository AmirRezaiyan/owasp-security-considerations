# API5: Broken Function Level Authorization

## What and Why

Function-level authorization failures allow users to invoke operations reserved for administrators or other privileged roles. Hiding a button or using an obscure URL does not enforce authorization.

## Example and Failure Mode

A regular account requests a user-administration endpoint directly. `vulnerable_admin_action` models a privileged function without a role check; the production admin route uses the shared `require_admin` utility.

## Reproduce Locally

```powershell
& "G:\py\python.exe" -m pytest tests/security/test_api5_function_authorization.py -q
```

## Identify and Mitigate

Map routes and actions to roles, enforce authorization on the server for every request, and test anonymous, regular, inactive, and administrator cases. Reuse a centralized permission check rather than duplicating role logic. Return only data necessary for the privileged task.

`GET /api/v1/admin/users` requires an active administrator and serializes results with `UserPublic`, which omits email and password hashes.

## Test Coverage

Integration tests verify admin access, regular-user denial, unauthenticated denial, and absence of sensitive properties in the response. Helper tests cover inactive and non-admin roles.

## References

- [OWASP API5:2023 Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
