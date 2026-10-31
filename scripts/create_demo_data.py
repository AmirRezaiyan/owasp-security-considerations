"""Insert clearly labeled, repeatable demo records into a local SQLite database."""

from pwdlib.exceptions import UnknownHashError
from sqlalchemy import func, select
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.orm import Session

from app.config import settings
from app.core.security import hash_password, verify_password
from app.database import SessionLocal, create_tables
from app.models.task import Task
from app.models.user import User

DEMO_USERS = (
    {
        "email": "learner@example.test",
        "username": "demo-learner",
        "password": "DemoPassword123!",
        "is_admin": False,
    },
    {
        "email": "administrator@example.test",
        "username": "demo-admin",
        "password": "DemoPassword123!",
        "is_admin": True,
    },
)

DEMO_TASKS = (
    ("Read the API security model", "Review the local security model guide."),
    ("Inspect task ownership", "Compare object access as two demo users."),
)


def get_or_create_demo_user(
    db: Session,
    user_data: dict[str, object],
) -> tuple[User, bool]:
    email = str(user_data["email"])
    username = str(user_data["username"])
    existing = db.scalar(
        select(User).where(
            (func.lower(User.email) == email.lower())
            | (func.lower(User.username) == username.lower())
        )
    )

    if existing is not None:
        if existing.email != email or existing.username != username:
            raise RuntimeError("A demo identity conflicts with an existing user.")
        try:
            credentials_match = verify_password(
                str(user_data["password"]),
                existing.hashed_password,
            )
        except UnknownHashError:
            credentials_match = False
        if (
            not credentials_match
            or existing.is_admin != bool(user_data["is_admin"])
            or not existing.is_active
        ):
            raise RuntimeError(
                "An existing demo account does not match the documented credentials "
                "and privileges; no account changes were made."
            )
        return existing, False

    user = User(
        email=email,
        username=username,
        hashed_password=hash_password(str(user_data["password"])),
        is_admin=bool(user_data["is_admin"]),
    )
    db.add(user)
    db.flush()
    return user, True


def populate_demo_data(db: Session) -> tuple[int, int]:
    try:
        user_results = [get_or_create_demo_user(db, user_data) for user_data in DEMO_USERS]
        users = [user for user, _ in user_results]
        users_added = sum(created for _, created in user_results)
        task_count = 0

        for user in users:
            for title, description in DEMO_TASKS:
                existing_task = db.scalar(
                    select(Task).where(Task.owner_id == user.id, Task.title == title)
                )
                if existing_task is None:
                    db.add(Task(title=title, description=description, owner_id=user.id))
                    task_count += 1
                elif existing_task.description != description:
                    raise RuntimeError(
                        "An existing demo task conflicts with the expected sample data; "
                        "no task changes were made."
                    )

        db.commit()
        return users_added, task_count
    except Exception:
        db.rollback()
        raise


def main() -> int:
    try:
        database_backend = make_url(settings.database_url).get_backend_name()
    except ArgumentError:
        database_backend = ""

    if settings.is_production or database_backend != "sqlite":
        print("Demo data is allowed only in a non-production SQLite environment.")
        return 2

    create_tables()
    with SessionLocal() as db:
        try:
            users_added, tasks_added = populate_demo_data(db)
        except RuntimeError as exc:
            print(f"Demo data was not changed: {exc}")
            return 2

    print(f"Demo setup complete: {users_added} demo users, {tasks_added} new tasks.")
    print("Demo credentials are documented in README.md; do not reuse them elsewhere.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
