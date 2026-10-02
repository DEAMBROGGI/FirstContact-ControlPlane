from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db() -> None:
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO github_webhook_delivery_claims "
                "(delivery_id, owner_id, generation, lease_expires_at) "
                "SELECT delivery.delivery_id, NULL, 0, NULL "
                "FROM github_webhook_deliveries AS delivery "
                "WHERE NOT EXISTS ("
                "SELECT 1 FROM github_webhook_delivery_claims AS claim "
                "WHERE claim.delivery_id = delivery.delivery_id"
                ")"
            )
        )
    if engine.dialect.name == "postgresql":
        with engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE remediation_work_packages "
                    "ALTER COLUMN implementation_issue_number DROP NOT NULL"
                )
            )


def get_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
