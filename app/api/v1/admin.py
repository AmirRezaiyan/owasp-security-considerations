from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import select

from app.core.dependencies import CurrentUser, DatabaseSession
from app.core.permissions import require_admin
from app.models.user import User
from app.schemas.user import UserPublic

router = APIRouter(prefix="/admin", tags=["Administration"])


@router.get("/users", response_model=list[UserPublic])
def list_users(
    current_user: CurrentUser,
    db: DatabaseSession,
    skip: Annotated[int, Query(ge=0, le=10_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[User]:
    require_admin(current_user)
    statement = select(User).order_by(User.id).offset(skip).limit(limit)
    return list(db.scalars(statement).all())
