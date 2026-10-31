# Testing

## Run the Suite

```powershell
& "G:\py\python.exe" -m pytest -q
& "G:\py\python.exe" scripts/run_security_tests.py
```

The convenience script runs `tests/security`, uses the active Python executable, and returns pytest's exit status. CI runs the full test suite.

## Test Design

- SQLite fixtures use a fresh in-memory database for each test.
- Route integration tests mount the v1 router without starting the production Redis lifespan and override only database/auth dependencies needed by the test.
- Vulnerable demo tests opt in using a function-scoped settings override and contrast vulnerable and secure helper behavior.
- SSRF transport tests live in `tests/security/test_external_api_client.py`; API7's educational comparison remains in `test_api7_ssrf.py`, and API10 schema/helper coverage remains in `test_api10_unsafe_consumption.py`. DNS answers and HTTP responses are mocked, and the aiohttp connector test stops before socket creation.
- Existing BOLA and authentication tests remain part of the suite.

## Quality Checks

```powershell
ruff check .
ruff format --check .
```

When changing authorization, test both a denied user and the authorized case. When changing input handling, cover invalid types, boundary values, and output sanitization. Keep tests independent of Docker, Redis availability, external APIs, and persistent local database files.
