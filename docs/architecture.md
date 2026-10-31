# Architecture

## Runtime

`app.main` creates the FastAPI application, registers sanitized exception handling and CORS, mounts the versioned API router, and checks Redis during lifespan startup. The app creates missing SQLite tables from the SQLAlchemy metadata. Redis is required because authentication rate limits fail closed when it is unavailable.

## Application Layers

- `app/api/v1/` exposes authentication, user profile, task, and admin routes under `/api/v1`.
- `app/core/` contains settings-driven authentication dependencies, centralized role/ownership checks, password/JWT helpers, rate limiting, and exception handling.
- `app/models/` defines the SQLAlchemy `User` and `Task` entities.
- `app/schemas/` defines Pydantic request/response shapes; response schemas omit password hashes.
- `app/services/external_api.py` contains a separate outbound JSON client. It is not currently mounted as a public route.
- `app/vulnerabilities/` contains isolated data-only teaching functions. It is not included in the API router.
- `tests/` contains security behavior tests with in-memory SQLite and mocked outbound responses.

## Request Flow

The bearer token dependency validates the signature and expiry, resolves an active user from the database, and injects that user into protected routes. Task queries include the authenticated owner ID. The admin route calls the shared `require_admin` permission utility and serializes results through `UserPublic`.

## Persistence and Migrations

The current application uses SQLAlchemy `metadata.create_all()` for this small SQLite lab. There is no Alembic migration workflow. `create_all()` creates missing tables but does not migrate existing schemas; schema changes requiring data preservation need an explicit migration plan before deployment. The local database is ignored by Git and must not be deleted to work around schema changes.
