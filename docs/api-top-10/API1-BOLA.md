# API1: Broken Object Level Authorization (BOLA)

## What and Why

BOLA occurs when an API uses a caller-controlled object identifier without verifying that the authenticated caller may access that specific object. A sequential ID is not a permission check; exposure can reveal or alter another user's records.

## Example and Failure Mode

A user changes `/api/v1/tasks/41` to `/api/v1/tasks/42`. If the handler loads task 42 by ID alone, it may disclose or modify another owner's task. The intentionally vulnerable helper `vulnerable_read_object` demonstrates this unscoped lookup using a local dictionary only.

## Reproduce Locally

```powershell
& "G:\py\python.exe" -m pytest tests/security/test_api1_bola.py -k demo -q
```

The test opts into the local demonstration and compares it with `secure_read_object`. No HTTP request or persistent database is involved.

## Identify and Mitigate

Review every object read, update, and delete for a permission decision tied to the authenticated user and the specific object. Prefer a database query constrained by both object ID and owner ID. Return a consistent not-found response where disclosing object existence is unnecessary. Test cross-user access for every operation.

The task routes implement owner-scoped queries; the existing integration-level unit tests verify that other users cannot read, update, or delete a task.

## Test Coverage

`tests/security/test_api1_bola.py` tests the vulnerable contrast, authorized owner actions, and cross-owner denial. `app/api/v1/tasks.py` contains the production route behavior.

## References

- [OWASP API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
