from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from pwdlib import PasswordHash

from app.config import settings

password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:
    return password_hash.verify(plain_password, hashed_password)


def create_access_token(
    subject: str,
    expires_delta: timedelta | None = None,
) -> str:
    if not isinstance(subject, str) or not subject.strip():
        raise ValueError("Token subject must be non-empty text.")

    maximum_lifetime = timedelta(minutes=settings.access_token_expire_minutes)
    if expires_delta is not None and not isinstance(expires_delta, timedelta):
        raise ValueError("Token expiration must be a timedelta.")
    lifetime = expires_delta if expires_delta is not None else maximum_lifetime
    if lifetime <= timedelta(0) or lifetime > maximum_lifetime:
        raise ValueError("Token lifetime is outside the configured limit.")

    now = datetime.now(UTC)
    expires_at = now + lifetime

    payload: dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": expires_at,
    }

    return jwt.encode(
        payload,
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )


def decode_access_token(token: str) -> dict[str, Any]:
    payload = jwt.decode(
        token,
        settings.secret_key,
        algorithms=[settings.jwt_algorithm],
        options={
            "require": ["sub", "exp", "iat"],
        },
    )

    issued_at = payload.get("iat")
    expires_at = payload.get("exp")
    subject = payload.get("sub")
    maximum_lifetime_seconds = settings.access_token_expire_minutes * 60
    if (
        type(issued_at) is not int
        or type(expires_at) is not int
        or not isinstance(subject, str)
        or not subject.strip()
        or issued_at <= 0
        or expires_at <= issued_at
        or expires_at - issued_at > maximum_lifetime_seconds
    ):
        raise jwt.InvalidTokenError("Invalid token claims.")

    return payload
