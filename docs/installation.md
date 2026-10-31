# Installation and Configuration

## Prerequisites

- Python 3.12 or newer.
- Redis 5 or newer for local execution, or Docker with the Compose plugin.
- Git is recommended for contributions.

## Windows PowerShell

From the repository root:

```powershell
& "G:\py\python.exe" -m venv .venv
& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip
& ".\.venv\Scripts\python.exe" -m pip install -e ".[dev]"
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

Do not overwrite an existing `.env`. The sample signing key is explicitly development-only. Supported `ENVIRONMENT` values are `development`, `test`, and `production`; `prod` is normalized to `production`, and any other value is rejected.

For a shared or deployed environment, generate a unique signing key with Python and provide it through the deployment's secret mechanism:

```powershell
& "G:\py\python.exe" -c "import secrets; print(secrets.token_urlsafe(48))"
```

Set `ENVIRONMENT=production` and `DEBUG=false`. Production requires a non-default key of at least 64 characters and rejects a uniform repeated-character placeholder. Length and format checks cannot prove entropy, so generate keys with a cryptographically secure source; do not commit or log the generated value.

## Settings

Settings are read case-insensitively from environment variables and `.env`. Common options:

| Variable | Purpose | Default |
| --- | --- | --- |
| `ENVIRONMENT` | `development`, `test`, or `production`; `prod` is an alias | `development` |
| `DEBUG` | FastAPI debug behavior | `false` in code; `true` in the sample file |
| `SECRET_KEY` | JWT signing key; replace the sample before deployment | Development-only placeholder |
| `DATABASE_URL` | SQLAlchemy database URL | `sqlite:///./owasp_lab.db` |
| `REDIS_URL` | Rate-limit Redis connection | `redis://localhost:6379/0` |
| `ENABLE_VULNERABLE_DEMOS` | Opt into isolated demonstration functions | `false` |
| `CORS_ORIGINS` | Comma-separated allowed browser origins | Local development origins |
| `LOGIN_RATE_LIMIT` | Login attempts per configured window | `5` |
| `REGISTER_RATE_LIMIT` | Registrations per configured window | `5` |

Production settings reject debug mode, a weak/default signing key, and enabled vulnerable demonstrations. `ENABLE_VULNERABLE_DEMOS` does not publish routes; it only allows calling the local demonstration functions.

## Start the API Locally

Provide a Redis service reachable at `REDIS_URL`, then run:

```powershell
& ".\.venv\Scripts\python.exe" -m uvicorn app.main:app --reload --port 8000
```

Development API docs are at `http://127.0.0.1:8000/docs`. Docs and OpenAPI routes are disabled when `ENVIRONMENT=production`.

## Start with Compose

Create `.env` only if it is absent, then start the services:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
docker compose up --build -d
docker compose ps
```

The API is available at `http://localhost:8001`; Redis is private to the Compose network. The API uses a named SQLite volume at `/data`. `docker compose down` stops services without deleting named volumes. Do not add `--volumes` unless you intend to delete persistent data.

## Database Setup

On startup, SQLAlchemy creates missing tables in the configured database. This project has no migration system; see [Architecture](architecture.md) before changing an existing schema. The demo-data script is limited to non-production SQLite and is additive/idempotent.
