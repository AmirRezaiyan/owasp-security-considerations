from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi import FastAPI, HTTPException, Request
from pydantic import ValidationError
from redis.exceptions import RedisError

from app.config import Settings, settings
from app.core.rate_limit import enforce_rate_limit
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


def test_password_is_hashed():
    password = "StrongPassword123!"

    hashed = hash_password(password)

    assert hashed != password
    assert verify_password(password, hashed)


def test_wrong_password_is_rejected():
    hashed = hash_password("CorrectPassword123!")

    assert not verify_password("WrongPassword123!", hashed)


def test_access_token_contains_required_claims():
    token = create_access_token(
        subject="123",
        expires_delta=timedelta(minutes=5),
    )

    payload = decode_access_token(token)

    assert payload["sub"] == "123"
    assert "iat" in payload
    assert "exp" in payload


def test_expired_token_is_rejected():
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": "123",
            "iat": now - timedelta(minutes=1),
            "exp": now - timedelta(seconds=1),
        },
        settings.secret_key,
        algorithm="HS256",
    )

    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(token)


def test_token_with_wrong_algorithm_is_rejected():
    payload = {
        "sub": "123",
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(minutes=5),
    }

    token = jwt.encode(
        payload,
        "x" * 48,
        algorithm="HS384",
    )

    with pytest.raises(jwt.InvalidAlgorithmError):
        decode_access_token(token)


def test_token_with_wrong_signature_is_rejected():
    payload = {
        "sub": "123",
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(minutes=5),
    }

    token = jwt.encode(
        payload,
        "x" * 48,
        algorithm="HS256",
    )

    with pytest.raises(jwt.InvalidSignatureError):
        decode_access_token(token)


def test_token_without_required_claim_is_rejected():
    payload = {
        "sub": "123",
        "exp": datetime.now(UTC) + timedelta(minutes=5),
    }

    token = jwt.encode(
        payload,
        settings.secret_key,
        algorithm="HS256",
    )

    with pytest.raises(jwt.MissingRequiredClaimError):
        decode_access_token(token)


@pytest.mark.parametrize(
    "claims",
    [
        {"sub": "123", "iat": True, "exp": datetime.now(UTC) + timedelta(minutes=5)},
        {
            "sub": "123",
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=31),
        },
        {
            "sub": "123",
            "iat": datetime.now(UTC) + timedelta(minutes=1),
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        },
        {
            "sub": "   ",
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        },
        {
            "sub": "123",
            "iat": 1.5,
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        },
    ],
)
def test_real_jwt_decoder_rejects_boolean_future_and_overlong_claims(claims):
    token = jwt.encode(claims, settings.secret_key, algorithm="HS256")

    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token(token)


@pytest.mark.parametrize(
    ("subject", "expires_delta"),
    [
        ("", None),
        ("   ", None),
        ("123", timedelta(0)),
        ("123", timedelta(seconds=-1)),
        ("123", timedelta(minutes=31)),
        ("123", "five minutes"),
    ],
)
def test_token_creation_rejects_invalid_subjects_and_lifetimes(subject, expires_delta):
    with pytest.raises(ValueError):
        create_access_token(subject, expires_delta)


def test_token_creation_at_configured_maximum_decodes_successfully():
    token = create_access_token("123", timedelta(minutes=30))

    assert decode_access_token(token)["sub"] == "123"


def test_authentication_dependency_accepts_a_valid_access_token(
    api_client,
    user_factory,
):
    user = user_factory(username="jwt-user")
    token = create_access_token(str(user.id))

    response = api_client.get("/api/v1/tasks", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json() == []


def test_authentication_dependency_returns_generic_401_for_invalid_tokens(
    api_client,
    user_factory,
):
    user = user_factory(username="jwt-user")
    now = datetime.now(UTC)
    invalid_tokens = [
        "not-a-jwt",
        jwt.encode(
            {
                "sub": str(user.id),
                "iat": now - timedelta(minutes=2),
                "exp": now - timedelta(minutes=1),
            },
            settings.secret_key,
            algorithm="HS256",
        ),
        jwt.encode(
            {"sub": str(user.id), "iat": True, "exp": now + timedelta(minutes=5)},
            settings.secret_key,
            algorithm="HS256",
        ),
        jwt.encode(
            {
                "sub": str(user.id),
                "iat": now,
                "exp": now + timedelta(minutes=31),
            },
            settings.secret_key,
            algorithm="HS256",
        ),
        jwt.encode(
            {"sub": str(user.id), "iat": now, "exp": now + timedelta(minutes=5)},
            "incorrect-signing-key-that-is-long-enough",
            algorithm="HS256",
        ),
    ]

    for token in invalid_tokens:
        response = api_client.get(
            "/api/v1/tasks",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"
        assert response.json() == {"detail": "Invalid or expired token"}
        assert "signature" not in response.text.lower()


def test_authentication_dependency_rejects_missing_credentials(api_client):
    response = api_client.get("/api/v1/tasks")

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json() == {"detail": "Not authenticated"}


def test_authentication_dependency_rejects_inactive_user(
    api_client,
    user_factory,
):
    inactive_user = user_factory(username="inactive-jwt-user", is_active=False)
    token = create_access_token(str(inactive_user.id))

    response = api_client.get("/api/v1/tasks", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or inactive user"}


def test_production_rejects_weak_secret_key():
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            environment="production",
            debug=False,
            secret_key="a" * 64,
        )


def test_production_rejects_secret_below_minimum_length():
    with pytest.raises(ValidationError, match="SECRET_KEY"):
        Settings(
            _env_file=None,
            environment="production",
            secret_key="A1b2C3d4E5f6G7h8J9k0L1m2N3p4Q5r6S7t8U9v0W1x2Y3z4A5b6C7d8E9f0G1",
        )


def test_production_rejects_debug_mode():
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            environment="production",
            debug=True,
            secret_key="aB3dE5gH7jK9mN2pQ4rS6tU8vW1xY3zAbC5dE7fG9hJ2kL4mN6pQ8rS1tU3vW5xY",
        )


class FakeRedis:
    def __init__(
        self,
        request_count=1,
        ttl=60,
        error=None,
    ):
        self.request_count = request_count
        self.ttl = ttl
        self.error = error
        self.key = None

    def eval(self, script, number_of_keys, key, window_seconds):
        if self.error:
            raise self.error

        self.key = key

        return [
            self.request_count,
            self.ttl,
        ]


def make_request(redis_client):
    app = FastAPI()
    app.state.redis = redis_client

    return Request(
        {
            "type": "http",
            "app": app,
            "client": ("203.0.113.10", 12345),
        }
    )


def test_rate_limit_allows_requests_under_limit():
    redis_client = FakeRedis(request_count=3)
    request = make_request(redis_client)

    enforce_rate_limit(
        request=request,
        action="login",
        limit=5,
        window_seconds=60,
    )


def test_rate_limit_rejects_requests_over_limit():
    redis_client = FakeRedis(
        request_count=6,
        ttl=42,
    )

    request = make_request(redis_client)

    with pytest.raises(HTTPException) as exc_info:
        enforce_rate_limit(
            request=request,
            action="login",
            limit=5,
            window_seconds=60,
        )

    assert exc_info.value.status_code == 429
    assert exc_info.value.headers["Retry-After"] == "42"


def test_rate_limit_does_not_store_raw_ip():
    redis_client = FakeRedis()
    request = make_request(redis_client)

    enforce_rate_limit(
        request=request,
        action="login",
        limit=5,
        window_seconds=60,
    )

    assert "203.0.113.10" not in redis_client.key
    assert redis_client.key.startswith("rate_limit:login:")


def test_rate_limit_fails_closed_when_redis_is_unavailable():
    redis_client = FakeRedis(
        error=RedisError("Redis connection failed"),
    )

    request = make_request(redis_client)

    with pytest.raises(HTTPException) as exc_info:
        enforce_rate_limit(
            request=request,
            action="login",
            limit=5,
            window_seconds=60,
        )

    assert exc_info.value.status_code == 503
