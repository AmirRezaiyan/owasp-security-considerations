from datetime import timedelta

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.config import settings
from app.core.dependencies import CurrentUser, DatabaseSession
from app.core.rate_limit import enforce_rate_limit
from app.core.security import (
    create_access_token,
    hash_password,
    verify_password,
)
from app.models.user import User
from app.schemas.auth import LoginRequest, TokenResponse
from app.schemas.user import UserCreate, UserResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])


DUMMY_PASSWORD_HASH = hash_password("dummy-password-for-timing")


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    payload: UserCreate,
    db: DatabaseSession,
    request: Request,
):
    enforce_rate_limit(
        request=request,
        action="register",
        limit=settings.register_rate_limit,
        window_seconds=settings.register_rate_limit_window_seconds,
    )

    normalized_email = str(payload.email).lower()

    existing_user = db.scalar(
        select(User).where((User.email == normalized_email) | (User.username == payload.username))
    )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or username is already registered.",
        )

    user = User(
        email=normalized_email,
        username=payload.username,
        hashed_password=hash_password(payload.password),
    )

    db.add(user)

    try:
        db.commit()
        db.refresh(user)

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or username is already registered.",
        ) from None

    return user


@router.post(
    "/login",
    response_model=TokenResponse,
)
def login(
    payload: LoginRequest,
    db: DatabaseSession,
    request: Request,
):
    enforce_rate_limit(
        request=request,
        action="login",
        limit=settings.login_rate_limit,
        window_seconds=settings.login_rate_limit_window_seconds,
    )

    normalized_email = str(payload.email).lower()

    user = db.scalar(select(User).where(User.email == normalized_email))

    if user is None:
        verify_password(
            payload.password,
            DUMMY_PASSWORD_HASH,
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not verify_password(
        payload.password,
        user.hashed_password,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account is inactive.",
        )

    token = create_access_token(
        subject=str(user.id),
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes),
    )

    return TokenResponse(
        access_token=token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.get("/me", response_model=UserResponse)
def get_me(current_user: CurrentUser):
    return current_user
