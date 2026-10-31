# Contributing

Contributions that improve correctness, security, clarity, or learning value are welcome. Keep changes focused and preserve the existing secure application behavior.

## Development Setup

1. Install Python 3.12 or newer and Redis, or use the provided Compose setup.
2. Create and activate a virtual environment.
3. Install the project and development dependencies with `python -m pip install -e ".[dev]"`.
4. Create `.env` from `.env.example` only if a local `.env` does not already exist. Keep local settings and databases private.
5. Run the tests and Ruff checks before opening a pull request.

See [Installation](docs/installation.md) for Windows PowerShell commands.

## Branch and Pull Request Workflow

- Work on a focused branch based on the current main branch.
- Keep each pull request limited to one coherent change and describe the user-visible or security impact.
- Link related issues, explain compatibility considerations, and call out any configuration or dependency changes.
- Do not commit credentials, `.env`, local databases, generated artifacts, or unrelated formatting changes.
- Do not commit or push on behalf of a maintainer.

## Code Quality

- Follow the existing Python style, type relevant interfaces, and keep authorization in the established permission/dependency layer.
- Prefer explicit Pydantic schemas and bounded inputs. Do not expose ORM password hashes or internal exception details.
- Avoid unnecessary dependencies and abstractions. Add runtime dependencies to `pyproject.toml` only when production code imports them.
- Run `ruff check .`, `ruff format --check .`, and `python -m pytest -q`.
- Do not weaken, skip, or delete an existing security test to make a change pass.

## Tests and Documentation

- Add deterministic tests for both the behavior and its security boundary.
- Use in-memory SQLite, test-local users, and mocks. Do not contact public or internal network targets from tests.
- Exercise both authorization denial and allowed behavior where relevant; test error sanitization and resource bounds.
- Update the relevant API guide and architecture/security documentation when behavior changes. Documentation must not promise a control that is absent from code or tests.

## Security-Specific Rules

- Keep vulnerable teaching functions out of normal API routers and guard them with the explicit demo setting.
- Never enable vulnerable demonstrations in production, shared environments, or public deployments.
- Do not add credential theft, destructive actions, real-target scanning, or examples that contact internal networks.
- Validate URLs and DNS results before outbound connections; disable unsafe redirects and retain TLS verification.
- Report suspected vulnerabilities privately according to [SECURITY.md](SECURITY.md).
