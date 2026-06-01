from __future__ import annotations

import os
from dataclasses import dataclass


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("APP_NAME", "Kairix Opsbook")
    app_version: str = os.getenv("APP_VERSION", "0.1.5")
    instance_name: str = os.getenv("INSTANCE_NAME", "Opsbook")
    instance_mode: str = os.getenv("INSTANCE_MODE", "primary").lower()
    database_url: str = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg://opsbook:change-me@db:5432/opsbook",
    )
    opsbook_secret_key: str = os.getenv(
        "OPSBOOK_SECRET_KEY", "dev-secret-change-before-real-use"
    )
    export_secret_key: str = os.getenv(
        "EXPORT_SECRET_KEY", "dev-export-secret-change-before-real-use"
    )
    session_secret_key: str = os.getenv(
        "SESSION_SECRET_KEY", "dev-session-secret-change-before-real-use"
    )
    session_cookie_secure: bool = _bool_env("SESSION_COOKIE_SECURE", False)
    session_timeout_minutes: int = int(os.getenv("SESSION_TIMEOUT_MINUTES", "20"))
    medium_unlock_minutes: int = int(os.getenv("MEDIUM_UNLOCK_MINUTES", "5"))
    export_dir: str = os.getenv("EXPORT_DIR", "/app/exports")
    backup_dir: str = os.getenv("BACKUP_DIR", "/app/backups")

    @property
    def read_only(self) -> bool:
        return self.instance_mode == "standby"


settings = Settings()
