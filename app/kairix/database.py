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
    if "device_stat_snapshots" in columns:
        stat_columns = columns["device_stat_snapshots"]
        column_specs = {
            "cpu_count": ("INTEGER", "INTEGER"),
            "swap_percent": ("DOUBLE PRECISION", "FLOAT"),
            "swap_used_bytes": ("BIGINT", "BIGINT"),
            "swap_total_bytes": ("BIGINT", "BIGINT"),
            "load_per_core": ("DOUBLE PRECISION", "FLOAT"),
            "network_rx_bytes": ("BIGINT", "BIGINT"),
            "network_tx_bytes": ("BIGINT", "BIGINT"),
            "network_rx_bps": ("DOUBLE PRECISION", "FLOAT"),
            "network_tx_bps": ("DOUBLE PRECISION", "FLOAT"),
            "docker_running_count": ("INTEGER", "INTEGER"),
            "docker_stopped_count": ("INTEGER", "INTEGER"),
            "docker_unhealthy_count": ("INTEGER", "INTEGER"),
            "docker_total_count": ("INTEGER", "INTEGER"),
        }
        for column_name, (postgres_type, default_type) in column_specs.items():
            if column_name not in stat_columns:
                column_type = postgres_type if dialect == "postgresql" else default_type
                statements.append(f"ALTER TABLE device_stat_snapshots ADD COLUMN {column_name} {column_type}")
    if not statements:
        return
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
