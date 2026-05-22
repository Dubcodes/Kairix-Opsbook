from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _ensure_schema()


def _ensure_schema() -> None:
    inspector = inspect(engine)
    columns = {
        table: {column["name"] for column in inspector.get_columns(table)}
        for table in inspector.get_table_names()
    }
    statements: list[str] = []
    dialect = engine.dialect.name
    if "devices" in columns and "display_order" not in columns["devices"]:
        if dialect == "postgresql":
            statements.append("ALTER TABLE devices ADD COLUMN display_order INTEGER NOT NULL DEFAULT 1000")
        else:
            statements.append("ALTER TABLE devices ADD COLUMN display_order INTEGER DEFAULT 1000")
    if "credentials" in columns and "expires_at" not in columns["credentials"]:
        if dialect == "postgresql":
            statements.append("ALTER TABLE credentials ADD COLUMN expires_at TIMESTAMP WITH TIME ZONE")
        else:
            statements.append("ALTER TABLE credentials ADD COLUMN expires_at DATETIME")
    if not statements:
        return
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
