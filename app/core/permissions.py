from fastapi import HTTPException, status

from app.models.user import User


def require_active_user(user: User) -> User:
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account is inactive.",
        )

    return user


def require_admin(user: User) -> User:
    require_active_user(user)

    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges are required.",
        )

    return user


def require_resource_owner(
    resource_owner_id: int,
    current_user: User,
) -> None:
    if resource_owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resource not found.",
        )
