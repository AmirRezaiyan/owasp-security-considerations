from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.vulnerabilities.api2_authentication import (
    secure_token_claims,
    token_is_current,
    vulnerable_token_claims,
)


def test_vulnerable_demos_are_disabled_by_default():
    assert Settings(_env_file=None).enable_vulnerable_demos is False


@pytest.mark.parametrize("environment", ["production", "Production", " prod ", "PROD"])
def test_settings_normalize_supported_production_names(environment):
    configured = Settings(
        _env_file=None,
        environment=environment,
        secret_key="aB3dE5gH7jK9mN2pQ4rS6tU8vW1xY3zAbC5dE7fG9hJ2kL4mN6pQ8rS1tU3vW5xY",
    )

    assert configured.environment == "production"
    assert configured.is_production


@pytest.mark.parametrize("environment", ["prodution", "staging", "", "  "])
def test_settings_reject_unknown_or_empty_environment_names(environment):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, environment=environment)


def test_settings_accept_development_and_test_environments():
    assert Settings(_env_file=None, environment="DEVELOPMENT").environment == "development"
    assert Settings(_env_file=None, environment=" test ").environment == "test"


def test_authentication_demo_shows_missing_expiry_and_secure_claims(
    enable_vulnerable_demos,
):
    insecure = vulnerable_token_claims("user-1")
    secure = secure_token_claims("user-1", issued_at=100, expires_at=200)

    assert "exp" not in insecure
    assert secure["exp"] == 200
    assert token_is_current(secure, datetime.fromtimestamp(150, UTC))
    assert not token_is_current(secure, datetime.fromtimestamp(200, UTC))


@pytest.mark.parametrize(
    ("subject", "issued_at", "expires_at"),
    [("", 100, 200), ("user", 200, 200), ("user", 100, 2000)],
)
def test_secure_token_claims_reject_invalid_or_unbounded_lifetimes(
    subject,
    issued_at,
    expires_at,
):
    with pytest.raises(ValueError):
        secure_token_claims(subject, issued_at, expires_at)


@pytest.mark.parametrize(
    ("issued_at", "expires_at", "maximum_lifetime_seconds"),
    [
        (True, 200, 1800),
        (100, False, 1800),
        (100, 200, 0),
        (100, 200, -1),
        (100, 200, True),
    ],
)
def test_secure_token_claims_rejects_boolean_timestamps_and_invalid_maximums(
    issued_at,
    expires_at,
    maximum_lifetime_seconds,
):
    with pytest.raises(ValueError):
        secure_token_claims(
            "user",
            issued_at,
            expires_at,
            maximum_lifetime_seconds=maximum_lifetime_seconds,
        )


def test_token_is_current_rejects_future_boolean_and_overlong_claims():
    now = datetime.fromtimestamp(150, UTC)

    assert not token_is_current({"iat": 151, "exp": 200}, now)
    assert not token_is_current({"iat": True, "exp": 200}, now)
    assert not token_is_current({"iat": 100, "exp": False}, now)
    assert not token_is_current({"iat": 100, "exp": 2000}, now)
    assert not token_is_current(
        {"iat": 100, "exp": 200},
        now,
        maximum_lifetime_seconds=0,
    )


def test_production_cannot_enable_vulnerable_demos():
    with pytest.raises(ValueError, match="disabled in production"):
        Settings(
            _env_file=None,
            environment="production",
            secret_key="aB3dE5gH7jK9mN2pQ4rS6tU8vW1xY3zAbC5dE7fG9hJ2kL4mN6pQ8rS1tU3vW5xY",
            enable_vulnerable_demos=True,
        )


def test_production_rejects_default_development_secret():
    with pytest.raises(ValidationError, match="SECRET_KEY"):
        Settings(_env_file=None, environment="production")
