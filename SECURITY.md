# Security Policy

## Supported Versions

This repository is an educational project without a formal release support schedule. Security fixes are currently intended for the latest code on the default branch. Published releases, if any, should be treated as unsupported unless the release notes say otherwise.

## Reporting a Vulnerability

Please do not publish exploitable details in a public issue or pull request. Use GitHub's private vulnerability reporting feature for this repository when it is available. If private reporting is unavailable, contact the repository maintainers through the contact mechanism listed on the GitHub repository/profile and request a private channel. No private email address is specified by this project.

Include, when safe to do so:

- A concise description of the affected component and security impact.
- The affected revision or version and relevant configuration.
- Minimal reproduction steps using only a local copy of this project.
- Expected and observed behavior, with sanitized logs or screenshots if useful.
- Any mitigation or patch idea, if you have one.

Do not include real credentials, personal data, production database contents, or secrets in a report.

## Safe Testing Boundaries

This lab is intended for local, authorized learning. Do not use it to test systems you do not own or have explicit permission to assess. Do not point demonstrations at real internal services, cloud metadata endpoints, public targets, or third-party APIs. The SSRF and unsafe-consumption tests use mocks and local inputs only. Vulnerable demonstrations are not HTTP endpoints and must remain disabled in production.

Do not use the documented demo credentials outside a disposable local database. Do not upload `.env`, signing keys, database files, tokens, or unredacted logs to issues or pull requests. Avoid destructive tests against persistent data; use the in-memory test fixtures.
