from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet, InvalidToken

from .config import settings

HASH_ITERATIONS = 260_000


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, HASH_ITERATIONS
    )
    return (
        f"pbkdf2_sha256${HASH_ITERATIONS}$"
        f"{base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"
    )


def verify_password(password: str, stored_hash: str | None) -> bool:
    if not stored_hash:
        return False
    try:
        algorithm, iterations, salt_b64, digest_b64 = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, int(iterations)
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _fernet_from_secret(secret: str) -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())
    return Fernet(key)


def encrypt_text(value: str, *, export: bool = False) -> str:
    if value is None:
        value = ""
    secret = settings.export_secret_key if export else settings.opsbook_secret_key
    return _fernet_from_secret(secret).encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_text(token: str, *, export: bool = False) -> str:
    if not token:
        return ""
    secret = settings.export_secret_key if export else settings.opsbook_secret_key
    try:
        return _fernet_from_secret(secret).decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return "[Unable to decrypt: wrong key]"


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def challenge_ok(challenge: str, password_hash: str, secondary_hash: str | None) -> bool:
    return verify_password(challenge, secondary_hash) or verify_password(
        challenge, password_hash
    )


def unlock_expiry(minutes: int | None = None) -> datetime:
    return now_utc() + timedelta(minutes=minutes or settings.medium_unlock_minutes)


def random_secret(length: int = 32) -> str:
    return base64.urlsafe_b64encode(os.urandom(length)).decode("utf-8")

