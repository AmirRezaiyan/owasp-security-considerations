import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.router import api_router
from app.config import settings
from app.core.dependencies import get_current_user
from app.core.exceptions import register_exception_handlers
from app.database import Base, get_db
from app.models.user import User


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)

    with testing_session() as session:
        yield session

    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def api_client(db_session):
    app = FastAPI()
    app.include_router(api_router)
    register_exception_handlers(app)
    app.dependency_overrides[get_db] = lambda: db_session

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()


@pytest.fixture
def user_factory(db_session):
    def create_user(
        *,
        username: str,
        is_admin: bool = False,
        is_active: bool = True,
    ) -> User:
        user = User(
            email=f"{username}@example.test",
            username=username,
            hashed_password="test-hash-not-a-credential",
            is_admin=is_admin,
            is_active=is_active,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        return user

    return create_user


@pytest.fixture
def regular_user(user_factory):
    return user_factory(username="regular-user")


@pytest.fixture
def admin_user(user_factory):
    return user_factory(username="admin-user", is_admin=True)


@pytest.fixture
def enable_vulnerable_demos(monkeypatch):
    monkeypatch.setattr(settings, "enable_vulnerable_demos", True)


@pytest.fixture
def authenticate_as(api_client):
    def set_current_user(user: User) -> None:
        api_client.app.dependency_overrides[get_current_user] = lambda: user

    return set_current_user
