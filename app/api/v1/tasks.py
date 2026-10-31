from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Response, status
from sqlalchemy import select

from app.core.dependencies import CurrentUser, DatabaseSession
from app.models.task import Task
from app.schemas.task import TaskCreate, TaskResponse, TaskUpdate

router = APIRouter(prefix="/tasks", tags=["Tasks"])


@router.post(
    "",
    response_model=TaskResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_task(
    payload: TaskCreate,
    current_user: CurrentUser,
    db: DatabaseSession,
) -> Task:
    task = Task(
        title=payload.title,
        description=payload.description,
        owner_id=current_user.id,
    )

    db.add(task)
    db.commit()
    db.refresh(task)

    return task


@router.get(
    "",
    response_model=list[TaskResponse],
)
def list_tasks(
    current_user: CurrentUser,
    db: DatabaseSession,
    skip: Annotated[int, Query(ge=0, le=10_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[Task]:
    statement = (
        select(Task)
        .where(Task.owner_id == current_user.id)
        .order_by(Task.created_at.desc(), Task.id.desc())
        .offset(skip)
        .limit(limit)
    )

    return list(db.scalars(statement).all())


@router.get(
    "/{task_id}",
    response_model=TaskResponse,
)
def get_task(
    task_id: int,
    current_user: CurrentUser,
    db: DatabaseSession,
) -> Task:
    statement = select(Task).where(
        Task.id == task_id,
        Task.owner_id == current_user.id,
    )

    task = db.scalar(statement)

    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found.",
        )

    return task


@router.patch(
    "/{task_id}",
    response_model=TaskResponse,
)
def update_task(
    task_id: int,
    payload: TaskUpdate,
    current_user: CurrentUser,
    db: DatabaseSession,
) -> Task:
    statement = select(Task).where(
        Task.id == task_id,
        Task.owner_id == current_user.id,
    )

    task = db.scalar(statement)

    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found.",
        )

    changes = payload.model_dump(exclude_unset=True)

    if "status" in changes:
        changes["status"] = changes["status"].value

    for field, value in changes.items():
        setattr(task, field, value)

    db.commit()
    db.refresh(task)

    return task


@router.delete(
    "/{task_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_task(
    task_id: int,
    current_user: CurrentUser,
    db: DatabaseSession,
) -> Response:
    statement = select(Task).where(
        Task.id == task_id,
        Task.owner_id == current_user.id,
    )

    task = db.scalar(statement)

    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found.",
        )

    db.delete(task)
    db.commit()

    return Response(status_code=status.HTTP_204_NO_CONTENT)
