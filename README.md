# OWASP API Security Lab

A practical FastAPI learning laboratory for the OWASP API Security Top 10 (2023). The application provides a small authenticated task API with secure-by-default controls; isolated Python demonstrations contrast selected vulnerable patterns with mitigations. The demonstrations are not exposed as HTTP routes.

## What Is Included

- JWT bearer authentication with Argon2 password hashing and expiring tokens.
- Owner-scoped task operations and bounded pagination.
- Paginated administrator-only user listing that returns public fields only.
- Redis-backed login and registration rate limiting that fails closed when Redis is unavailable.
- Production checks for strong signing keys, disabled debug mode, and disabled vulnerable demonstrations.
- An allowlisted outbound JSON client with HTTPS-only URLs, connector-pinned public DNS answers, no redirects, timeouts, streaming response-size limits, content-type checks, and Pydantic validation.
- Local-only demonstrations and deterministic tests for API1 through API10.

## OWASP API Security Top 10 (2023)

| Category | Learning focus | Guide |
| --- | --- | --- |
| API1 | Broken Object Level Authorization | [API1 BOLA](docs/api-top-10/API1-BOLA.md) |
| API2 | Broken Authentication | [API2 Authentication](docs/api-top-10/API2-Authentication.md) |
| API3 | Broken Object Property Level Authorization | [API3 Property Authorization](docs/api-top-10/API3-Property-Authorization.md) |
| API4 | Unrestricted Resource Consumption | [API4 Resource Consumption](docs/api-top-10/API4-Resource-Consumption.md) |
| API5 | Broken Function Level Authorization | [API5 Function Authorization](docs/api-top-10/API5-Function-Authorization.md) |
| API6 | Unrestricted Access to Sensitive Business Flows | [API6 Sensitive Flows](docs/api-top-10/API6-Sensitive-Flows.md) |
| API7 | Server Side Request Forgery | [API7 SSRF](docs/api-top-10/API7-SSRF.md) |
| API8 | Security Misconfiguration | [API8 Misconfiguration](docs/api-top-10/API8-Security-Misconfiguration.md) |
| API9 | Improper Inventory Management | [API9 Inventory](docs/api-top-10/API9-Inventory-Management.md) |
| API10 | Unsafe Consumption of APIs | [API10 Unsafe Consumption](docs/api-top-10/API10-Unsafe-Consumption.md) |

## Technology

Python 3.12+, FastAPI, SQLAlchemy 2, Pydantic 2, SQLite, Redis, PyJWT, Argon2 (`pwdlib`), aiohttp, pytest, Ruff, Docker Compose, and GitHub Actions.

## Architecture

`app/api/v1/` contains the versioned routes. `app/core/` owns authentication, permissions, rate limiting, and error handling. SQLAlchemy models and Pydantic schemas are separated under `app/models/` and `app/schemas/`. `app/services/external_api.py` is the outbound API boundary. `app/vulnerabilities/` contains isolated teaching functions, not routers. See [Architecture](docs/architecture.md) and [Security Model](docs/security-model.md).

## Setup on Windows PowerShell

Use Python 3.12 or newer. From the repository root:

```powershell
& "G:\py\python.exe" -m venv .venv
& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip
& ".\.venv\Scripts\python.exe" -m pip install -e ".[dev]"
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

The checked-in example uses a development-only signing key. Never deploy with it. The application reads settings from environment variables and `.env`; do not commit `.env`. See [Installation](docs/installation.md) for the full setup and configuration reference.

## Run Locally

The API requires a reachable Redis service for rate limiting. Configure `REDIS_URL` for your local Redis instance, then run:

```powershell
& ".\.venv\Scripts\python.exe" -m uvicorn app.main:app --reload --port 8000
```

Open `http://127.0.0.1:8000/docs` in development. The API is rooted at `/api/v1`; health is available at `/health`.

## Run with Docker Compose

Create `.env` from `.env.example` only when one does not already exist. Then:

```powershell
docker compose up --build -d
docker compose ps
```

Compose exposes the API at `http://localhost:8001` and keeps Redis on the internal Compose network. The existing `8001:8000` mapping is intentional. Stop the services with `docker compose down`; the named database and Redis volumes remain intact. Do not use volume-removal flags unless you explicitly intend to delete those volumes.

## Tests and Code Quality

```powershell
& ".\.venv\Scripts\python.exe" -m pytest -q
& ".\.venv\Scripts\python.exe" scripts/run_security_tests.py
ruff check .
ruff format --check .
```

Tests use in-memory SQLite and mocked external responses; they do not depend on network availability or the local database. More detail is in [Testing](docs/testing.md).

## Secure and Vulnerable Examples

Secure routes are the normal application behavior. Vulnerable examples are pure, local-only functions guarded by `ENABLE_VULNERABLE_DEMOS`; the default is `false`, and production settings reject enabling the flag. They do not create an insecure endpoint, contact a target, or change the normal router. Tests opt in through an isolated fixture. To examine a demonstration, run the focused test listed in its [category guide](docs/api-top-10/).

Do not enable these examples in a deployed or shared environment. The API's ordinary controls and the isolated examples are learning aids, not a substitute for threat modeling, deployment hardening, or independent security review.

## Demo Data

On a disposable, non-production SQLite database, run:

```powershell
& ".\.venv\Scripts\python.exe" scripts/create_demo_data.py
```

The script adds demo learner/admin accounts and sample tasks only when absent; it does not overwrite existing rows or remove data. Existing accounts must match the documented password, role, and active state or the script stops without modifying them. Both demo accounts use `DemoPassword123!` and the `example.test` domain. These credentials are public training values only: never reuse them outside a disposable local lab. The script refuses production mode and non-SQLite database URLs.

## Documentation and Contributions

Start with [Installation](docs/installation.md), [Architecture](docs/architecture.md), [Security Model](docs/security-model.md), and the [API category guides](docs/api-top-10/). Contribution workflow and quality requirements are in [CONTRIBUTING.md](CONTRIBUTING.md). Please report security issues using the process in [SECURITY.md](SECURITY.md), not a public issue containing exploit details.

## Limitations

This is an educational example, not a production-ready service. It does not provide a complete operational account lifecycle, distributed inventory transaction system, schema migration system, or production secrets-management workflow. SQLite and the example configuration are for local learning. The external client is intentionally restrictive and requires an explicit exact-host allowlist and a Pydantic response model. Review the [security model](docs/security-model.md) before adapting any component.
