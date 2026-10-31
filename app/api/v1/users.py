from fastapi import APIRouter

from app.core.dependencies import CurrentUser
from app.schemas.user import UserResponse

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(
    current_user: CurrentUser,
):
    return current_user
