import pytest
from sqlalchemy import select

from app.models.task import Task
from app.models.user import User
from scripts import create_demo_data
from scripts.create_demo_data import DEMO_USERS, populate_demo_data


def test_demo_data_is_additive_and_idempotent(db_session):
    assert populate_demo_data(db_session) == (2, 4)
    learner = db_session.scalar(select(User).where(User.username == "demo-learner"))
    original_hash = learner.hashed_password

    assert populate_demo_data(db_session) == (0, 0)
    assert db_session.query(User).count() == 2
    assert db_session.query(Task).count() == 4
    assert learner.hashed_password == original_hash
    assert db_session.query(Task).filter_by(owner_id=learner.id).count() == 2


@pytest.mark.parametrize(
    ("email", "username"),
    [
        ("learner@example.test", "unrelated-user"),
        ("unrelated@example.test", "demo-learner"),
        ("LEARNER@EXAMPLE.TEST", "unrelated-user"),
    ],
)
def test_demo_data_refuses_to_claim_a_conflicting_identity(db_session, email, username):
    db_session.add(
        User(
            email=email,
            username=username,
            hashed_password="existing-hash",
        )
    )
    db_session.commit()

    with pytest.raises(RuntimeError, match="conflicts"):
        populate_demo_data(db_session)

    assert db_session.query(User).count() == 1


@pytest.mark.parametrize(
    ("user_index", "password", "is_admin", "is_active"),
    [
        (0, "DifferentPassword123!", False, True),
        (0, "DemoPassword123!", True, True),
        (0, "DemoPassword123!", False, False),
        (1, "DifferentPassword123!", True, True),
        (1, "DemoPassword123!", False, True),
    ],
)
def test_demo_data_refuses_existing_accounts_with_mismatched_credentials_or_privileges(
    db_session,
    user_index,
    password,
    is_admin,
    is_active,
):
    from app.core.security import hash_password

    expected_user = DEMO_USERS[user_index]
    existing = User(
        email=expected_user["email"],
        username=expected_user["username"],
        hashed_password=hash_password(password),
        is_admin=is_admin,
        is_active=is_active,
    )
    db_session.add(existing)
    db_session.commit()
    original_hash = existing.hashed_password

    with pytest.raises(RuntimeError, match="does not match"):
        populate_demo_data(db_session)

    db_session.refresh(existing)
    assert existing.hashed_password == original_hash
    assert existing.is_admin is is_admin
    assert db_session.query(User).count() == 1
    assert db_session.query(Task).count() == 0


def test_demo_data_refuses_existing_account_with_unrecognized_password_hash(db_session):
    expected_user = DEMO_USERS[0]
    existing = User(
        email=expected_user["email"],
        username=expected_user["username"],
        hashed_password="not-a-recognized-password-hash",
        is_admin=False,
        is_active=True,
    )
    db_session.add(existing)
    db_session.commit()

    with pytest.raises(RuntimeError, match="does not match"):
        populate_demo_data(db_session)

    assert existing.hashed_password == "not-a-recognized-password-hash"
    assert db_session.query(User).count() == 1


def test_demo_data_refuses_conflicting_existing_sample_task(db_session):
    assert populate_demo_data(db_session) == (2, 4)
    learner = db_session.scalar(select(User).where(User.username == "demo-learner"))
    task = db_session.scalar(
        select(Task).where(Task.owner_id == learner.id, Task.title == "Read the API security model")
    )
    task.description = "User-owned content"
    db_session.commit()

    with pytest.raises(RuntimeError, match="conflicts"):
        populate_demo_data(db_session)

    db_session.refresh(task)
    assert task.description == "User-owned content"
    assert db_session.query(User).count() == 2
    assert db_session.query(Task).count() == 4


def test_demo_data_script_refuses_production_before_database_setup(monkeypatch):
    monkeypatch.setattr(create_demo_data.settings, "environment", "production")
    monkeypatch.setattr(
        create_demo_data,
        "create_tables",
        lambda: pytest.fail("production mode must not touch the database"),
    )

    assert create_demo_data.main() == 2


def test_demo_data_script_refuses_non_sqlite_before_database_setup(monkeypatch):
    monkeypatch.setattr(create_demo_data.settings, "environment", "development")
    monkeypatch.setattr(
        create_demo_data.settings,
        "database_url",
        "postgresql://database.example/lab",
    )
    monkeypatch.setattr(
        create_demo_data,
        "create_tables",
        lambda: pytest.fail("non-SQLite mode must not touch the database"),
    )

    assert create_demo_data.main() == 2
