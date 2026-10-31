# API4: Unrestricted Resource Consumption

## What and Why

An API can be exhausted when request size, result count, execution time, or operation frequency is not bounded. Resource abuse can cause outages and unexpected infrastructure or third-party costs.

## Example and Failure Mode

A collection endpoint returns every row when no page size is supplied, or accepts a huge limit. `vulnerable_page` models unbounded local slicing; it performs no I/O.

## Reproduce Locally

```powershell
& "G:\py\python.exe" -m pytest tests/security/test_api4_resource_consumption.py -q
```

## Identify and Mitigate

Inventory expensive handlers and bound pagination, payload sizes, concurrency, timeouts, and costly workflows. Validate positive offsets and sizes and cap the maximum page size. Apply rate limits appropriate to the action and ensure infrastructure-level request limits complement application validation.

`GET /api/v1/tasks` and the administrator user list bound both offset (`0..10000`) and page size (`1..100`); task schema fields also have maximum lengths. Login and registration use Redis-backed limits. These application bounds should be complemented by deployment-level request and database resource limits.

## Test Coverage

The tests compare unbounded and bounded local results, reject invalid pagination, and assert that a task list request above the API limit receives a validation error. Authentication tests cover rate-limit boundaries and Redis failure behavior.

## References

- [OWASP API4:2023 Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
