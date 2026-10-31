import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.v1.tasks import (
    create_task,
    delete_task,
    get_task,
    list_tasks,
    update_task,
)
from app.config import settings
from app.database import Base
from app.models.task import Task
from app.models.user import User
from app.schemas.task import TaskCreate, TaskStatus, TaskUpdate
from app.vulnerabilities.api1_bola import secure_read_object, vulnerable_read_object


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(bind=engine)

    TestingSessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )

    with TestingSessionLocal() as session:
        yield session

    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def two_users(db_session: Session):
    user_a = User(
        email="user_a@example.com",
        username="user_a",
        hashed_password="not-a-real-password-hash",
        is_active=True,
        is_admin=False,
    )

    user_b = User(
        email="user_b@example.com",
        username="user_b",
        hashed_password="not-a-real-password-hash",
        is_active=True,
        is_admin=False,
    )

    db_session.add_all([user_a, user_b])
    db_session.commit()

    db_session.refresh(user_a)
    db_session.refresh(user_b)

    return user_a, user_b


@pytest.fixture
def task_owned_by_a(db_session: Session, two_users):
    user_a, _ = two_users

    return create_task(
        payload=TaskCreate(
            title="Private task",
            description="This task belongs to user A.",
        ),
        current_user=user_a,
        db=db_session,
    )


def test_user_can_create_own_task(db_session, two_users):
    user_a, _ = two_users

    task = create_task(
        payload=TaskCreate(
            title="My task",
            description="Created by user A.",
        ),
        current_user=user_a,
        db=db_session,
    )

    assert task.id is not None
    assert task.owner_id == user_a.id
    assert task.title == "My task"


def test_user_can_list_only_own_tasks(
    db_session,
    two_users,
    task_owned_by_a,
):
    _, user_b = two_users

    user_b_task = create_task(
        payload=TaskCreate(title="User B task"),
        current_user=user_b,
        db=db_session,
    )

    user_a_tasks = list_tasks(
        current_user=two_users[0],
        db=db_session,
    )

    user_b_tasks = list_tasks(
        current_user=user_b,
        db=db_session,
    )

    assert len(user_a_tasks) == 1
    assert user_a_tasks[0].id == task_owned_by_a.id

    assert len(user_b_tasks) == 1
    assert user_b_tasks[0].id == user_b_task.id


def test_user_can_get_own_task(
    db_session,
    two_users,
    task_owned_by_a,
):
    user_a, _ = two_users

    task = get_task(
        task_id=task_owned_by_a.id,
        current_user=user_a,
        db=db_session,
    )

    assert task.id == task_owned_by_a.id
    assert task.owner_id == user_a.id


def test_user_cannot_get_another_users_task(
    db_session,
    two_users,
    task_owned_by_a,
):
    _, user_b = two_users

    with pytest.raises(HTTPException) as exc_info:
        get_task(
            task_id=task_owned_by_a.id,
            current_user=user_b,
            db=db_session,
        )

    assert exc_info.value.status_code == 404


def test_user_cannot_update_another_users_task(
    db_session,
    two_users,
    task_owned_by_a,
):
    _, user_b = two_users

    with pytest.raises(HTTPException) as exc_info:
        update_task(
            task_id=task_owned_by_a.id,
            payload=TaskUpdate(title="Hacked title"),
            current_user=user_b,
            db=db_session,
        )

    assert exc_info.value.status_code == 404

    db_session.refresh(task_owned_by_a)
    assert task_owned_by_a.title == "Private task"


def test_user_cannot_delete_another_users_task(
    db_session,
    two_users,
    task_owned_by_a,
):
    _, user_b = two_users

    with pytest.raises(HTTPException) as exc_info:
        delete_task(
            task_id=task_owned_by_a.id,
            current_user=user_b,
            db=db_session,
        )

    assert exc_info.value.status_code == 404

    existing_task = db_session.get(Task, task_owned_by_a.id)
    assert existing_task is not None


def test_user_can_update_own_task(
    db_session,
    two_users,
    task_owned_by_a,
):
    user_a, _ = two_users

    updated_task = update_task(
        task_id=task_owned_by_a.id,
        payload=TaskUpdate(
            title="Updated private task",
            status=TaskStatus.COMPLETED,
        ),
        current_user=user_a,
        db=db_session,
    )

    assert updated_task.title == "Updated private task"
    assert updated_task.status == TaskStatus.COMPLETED


def test_user_can_delete_own_task(
    db_session,
    two_users,
    task_owned_by_a,
):
    user_a, _ = two_users

    response = delete_task(
        task_id=task_owned_by_a.id,
        current_user=user_a,
        db=db_session,
    )

    assert response.status_code == 204
    assert db_session.get(Task, task_owned_by_a.id) is None


def test_bola_demo_contrasts_unscoped_and_owner_scoped_reads(
    enable_vulnerable_demos,
):
    objects = {7: {"owner_id": 2, "title": "Private"}}

    assert vulnerable_read_object(objects, 7) == objects[7]
    assert secure_read_object(objects, 7, requester_id=1) is None
    assert secure_read_object(objects, 7, requester_id=2) == objects[7]


def test_bola_demo_is_disabled_without_explicit_opt_in(monkeypatch):
    monkeypatch.setattr(settings, "enable_vulnerable_demos", False)

    with pytest.raises(RuntimeError, match="disabled"):
        vulnerable_read_object({}, 1)
