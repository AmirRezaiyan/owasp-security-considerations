import logging

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import settings
from app.core.exceptions import register_exception_handlers
from app.main import app
from app.vulnerabilities.api8_misconfiguration import (
    secure_error_response,
    vulnerable_error_response,
)


def test_misconfiguration_demo_contrasts_verbose_and_safe_errors(enable_vulnerable_demos):
    internal_error = RuntimeError("database password path: C:\\private\\settings")

    assert "private" in vulnerable_error_response(internal_error)["detail"]
    assert secure_error_response() == {"detail": "An unexpected internal server error occurred."}


def test_request_validation_does_not_echo_sensitive_input(api_client):
    secret_input = "sensitive-value-" * 12

    response = api_client.post(
        "/api/v1/auth/register",
        json={
            "email": "learner@example.test",
            "username": "learner",
            "password": secret_input,
        },
    )

    assert response.status_code == 422
    assert secret_input not in response.text
    assert "input" not in response.text


def test_health_response_is_minimal_and_includes_security_headers():
    client = TestClient(app, raise_server_exceptions=False)
    try:
        response = client.get("/health")
    finally:
        client.close()

    assert response.json() == {"status": "healthy"}
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_root_does_not_advertise_documentation_in_production(monkeypatch):
    monkeypatch.setattr(settings, "environment", "production")
    client = TestClient(app, raise_server_exceptions=False)
    try:
        response = client.get("/")
    finally:
        client.close()

    assert response.status_code == 200
    assert response.json() == {
        "message": "Welcome to OWASP API Security Lab.",
        "health": "/health",
    }


def test_unexpected_error_is_logged_without_exception_message_or_returned_to_client(caplog):
    test_app = FastAPI()

    @test_app.get("/failure")
    def fail_request():
        raise RuntimeError("credential=do-not-log-this")

    register_exception_handlers(test_app)
    client = TestClient(test_app, raise_server_exceptions=False)

    with caplog.at_level(logging.ERROR, logger="app.core.exceptions"):
        response = client.get("/failure")

    assert response.status_code == 500
    assert response.json() == {"detail": "An unexpected internal server error occurred."}
    assert "RuntimeError" in caplog.text
    assert "do-not-log-this" not in caplog.text
    assert "do-not-log-this" not in response.text
