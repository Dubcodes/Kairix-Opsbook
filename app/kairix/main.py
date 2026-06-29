from __future__ import annotations

import copy
import io
import json
import logging
import re
import shutil
import socket
import secrets
import subprocess
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse
from urllib.request import Request as UrlRequest, urlopen

import pyotp
import qrcode
import qrcode.image.svg
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from . import __version__ as package_version, models
from .config import settings
from .database import SessionLocal, get_db, init_db
from .exporter import create_emergency_export, safe_export_path
from .parser import INVENTORY_COMMAND, parse_smart_paste
from .security import (
    challenge_match,
    decrypt_text,
    encrypt_text,
    hash_password,
    new_csrf_token,
    now_utc,
    password_hash_needs_upgrade,
    unlock_expiry,
    verify_password,
)
from .seeds import seed_initial_data
from .suggestions import TAG_IDEAS, dismiss_suggestion, mute_ping_failure, visible_suggestions
from .utils import (
    format_dt,
    iso_dt,
    merge_tags,
    render_template_vars,
    set_tags,
    slugify,
    tag_map,
    tags_for,
    unique_slug,
)

app = FastAPI(title=settings.app_name, version=settings.app_version)
logger = logging.getLogger(__name__)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret_key,
    https_only=settings.session_cookie_secure,
    same_site="lax",
    max_age=999 * 60,
)
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/favicon.ico")
def favicon_ico() -> RedirectResponse:
    return RedirectResponse("/static/favicon.svg", status_code=308)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'",
    )
    if request.session.get("user_id") or request.url.path in {"/login", "/login/2fa", "/setup"}:
        response.headers.setdefault("Cache-Control", "no-store")
    return response

templates = Jinja2Templates(directory="templates")
templates.env.filters["dt"] = format_dt
templates.env.filters["iso"] = iso_dt
templates.env.globals["render_vars"] = render_template_vars
templates.env.globals["settings"] = settings

NO_CREDENTIALS_MARKER = "[opsbook:no-credentials-needed]"
ACCESS_TOKEN_RE = re.compile(
    r"\b(?:"
    r"github_pat_[A-Za-z0-9_]+|"
    r"gh[pousr]_[A-Za-z0-9_.-]+|"
    r"(?:glpat|gloas|gldt|glrt|glrtr|glcbt|glptt|glft|glimt|glagent|glwt|glsoat|glffct)-[A-Za-z0-9_.-]{12,}|"
    r"x(?:ox[abprs]|app)-[A-Za-z0-9-]{10,}|"
    r"cfut_[A-Za-z0-9_-]{20,}|"
    r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}"
    r")\b"
)


def service_no_credentials_needed(service: models.Service) -> bool:
    return NO_CREDENTIALS_MARKER in (service.notes or "")


def public_notes(value: str) -> str:
    return (value or "").replace(NO_CREDENTIALS_MARKER, "").strip()


def credential_go_url(credential: models.Credential | None) -> str:
    if not credential:
        return ""
    if credential.login_url:
        return credential.login_url
    if credential.service:
        return credential.service.local_url or credential.service.public_url or ""
    return ""


def _url_matches_port(raw_url: str, port_number: int) -> bool:
    try:
        parsed = urlparse(raw_url)
    except ValueError:
        return False
    if not parsed.scheme or not parsed.hostname:
        return False
    try:
        parsed_port = parsed.port
    except ValueError:
        return False
    if parsed_port is None:
        parsed_port = 443 if parsed.scheme == "https" else 80
    return parsed_port == port_number


def port_open_url(port: models.Port | None) -> str:
    if not port or str(port.protocol or "tcp").lower() != "tcp":
        return ""
    for raw_url in (
        getattr(port.service, "local_url", "") if port.service else "",
        getattr(port.service, "public_url", "") if port.service else "",
    ):
        if raw_url and _url_matches_port(raw_url, port.host_port):
            return raw_url
    for url_record in list(getattr(port.service, "urls", []) if port.service else []) + list(getattr(port.device, "urls", []) or []):
        if url_record.url and _url_matches_port(url_record.url, port.host_port):
            return url_record.url
    host = (getattr(port.device, "primary_ip", "") or getattr(port.device, "hostname", "") or "").strip()
    if not host:
        return ""
    scheme = "https" if port.host_port in {443, 8443, 9443} else "http"
    return f"{scheme}://{host}:{port.host_port}/"


def stat_percent(value: float | int | None) -> str:
    if value is None:
        return "n/a"
    try:
        return f"{float(value):.0f}%"
    except (TypeError, ValueError):
        return "n/a"


def stat_bytes(value: int | None) -> str:
    if value is None:
        return "n/a"
    try:
        amount = float(value)
    except (TypeError, ValueError):
        return "n/a"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    unit = units[0]
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            break
        amount /= 1024
    return f"{amount:.1f} {unit}" if unit != "B" else f"{int(amount)} B"


def stat_rate(value: float | int | None) -> str:
    if value is None:
        return "n/a"
    try:
        return f"{stat_bytes(int(float(value)))}/s"
    except (TypeError, ValueError):
        return "n/a"


def stat_duration(seconds: float | int | None) -> str:
    if seconds is None:
        return "n/a"
    try:
        total = int(float(seconds))
    except (TypeError, ValueError):
        return "n/a"
    days, remainder = divmod(total, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _seconds = divmod(remainder, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


templates.env.globals["service_no_credentials_needed"] = service_no_credentials_needed
templates.env.globals["public_notes"] = public_notes
templates.env.globals["credential_go_url"] = credential_go_url
templates.env.globals["port_open_url"] = port_open_url
templates.env.filters["stat_percent"] = stat_percent
templates.env.filters["stat_bytes"] = stat_bytes
templates.env.filters["stat_rate"] = stat_rate
templates.env.filters["stat_duration"] = stat_duration

THEME_DEFAULTS = {
    "theme_mode": "auto",
    "theme_preset": "custom",
    "light_bg": "#f5f7f8",
    "light_surface": "#ffffff",
    "light_text": "#17212b",
    "light_muted": "#687786",
    "light_line": "#d8e0e5",
    "light_accent": "#0f766e",
    "light_accent_text": "#ffffff",
    "dark_bg": "#0f1419",
    "dark_surface": "#151c22",
    "dark_text": "#e7edf2",
    "dark_muted": "#a8b4bf",
    "dark_line": "#33424f",
    "dark_accent": "#5eead4",
    "dark_accent_text": "#06201d",
    "dashboard_recent_limit": "6",
    "compact_forms": "on",
    "session_timeout_minutes": "20",
    "ping_interval_minutes": "60",
    "ping_on_login": "on",
    "validate_services_on_login": "on",
    "ping_failures_before_warning": "3",
    "ping_green_ms": "3",
    "ping_orange_ms": "10",
    "history_retention_days": "90",
    "stats_window_hours": "8",
    "stats_expected_interval_minutes": "5",
    "stats_storage_interval_minutes": "5",
    "stats_retention_days": "30",
    "stats_overview_metrics": "cpu,memory,disk,load",
}

THEME_PRESETS = {
    "custom": {
        "label": "Custom",
        "description": "Use the light and dark color controls below.",
        "swatches": ("#f5f7f8", "#ffffff", "#0f766e", "#17212b"),
    },
    "opsbook": {
        "label": "Opsbook",
        "description": "The calm default palette.",
        "swatches": ("#f5f7f8", "#151c22", "#0f766e", "#5eead4"),
        "light": {
            "bg": "#f5f7f8",
            "surface": "#ffffff",
            "ink": "#17212b",
            "muted": "#687786",
            "line": "#d8e0e5",
            "accent": "#0f766e",
            "accent_ink": "#ffffff",
        },
        "dark": {
            "bg": "#0f1419",
            "surface": "#151c22",
            "ink": "#e7edf2",
            "muted": "#a8b4bf",
            "line": "#33424f",
            "accent": "#5eead4",
            "accent_ink": "#06201d",
        },
    },
    "steel": {
        "label": "Steel",
        "description": "Cool, quiet operations UI.",
        "swatches": ("#111827", "#1f2937", "#38bdf8", "#e5eef7"),
        "dark": {
            "bg": "#111827",
            "surface": "#1f2937",
            "ink": "#e5eef7",
            "muted": "#a8b3c1",
            "line": "#334155",
            "accent": "#38bdf8",
            "accent_ink": "#082f49",
        },
    },
    "jade": {
        "label": "Jade",
        "description": "Dark green with high-visibility actions.",
        "swatches": ("#071512", "#10241f", "#34d399", "#e6fff6"),
        "dark": {
            "bg": "#071512",
            "surface": "#10241f",
            "ink": "#e6fff6",
            "muted": "#9bc7bb",
            "line": "#1f4a3e",
            "accent": "#34d399",
            "accent_ink": "#052e25",
        },
    },
    "daylight": {
        "label": "Daylight",
        "description": "Clean bright theme for daytime use.",
        "swatches": ("#f8fafc", "#ffffff", "#2563eb", "#0f172a"),
        "light": {
            "bg": "#f8fafc",
            "surface": "#ffffff",
            "ink": "#0f172a",
            "muted": "#64748b",
            "line": "#dbe3ec",
            "accent": "#2563eb",
            "accent_ink": "#ffffff",
        },
    },
    "paper": {
        "label": "Paper",
        "description": "Soft light theme with warm surfaces.",
        "swatches": ("#f7f4ef", "#fffdf8", "#8b5cf6", "#1f2937"),
        "light": {
            "bg": "#f7f4ef",
            "surface": "#fffdf8",
            "ink": "#1f2937",
            "muted": "#6b7280",
            "line": "#ddd6c8",
            "accent": "#8b5cf6",
            "accent_ink": "#ffffff",
        },
    },
    "high-contrast": {
        "label": "High Contrast",
        "description": "Maximum contrast for readability.",
        "swatches": ("#000000", "#111111", "#facc15", "#ffffff"),
        "dark": {
            "bg": "#000000",
            "surface": "#111111",
            "ink": "#ffffff",
            "muted": "#d4d4d8",
            "line": "#52525b",
            "accent": "#facc15",
            "accent_ink": "#111111",
        },
    },
    "ocean": {
        "label": "Ocean",
        "description": "Blue-green monitoring palette.",
        "swatches": ("#061826", "#0f2a3a", "#22d3ee", "#e0f7ff"),
        "dark": {
            "bg": "#061826",
            "surface": "#0f2a3a",
            "ink": "#e0f7ff",
            "muted": "#91b6c9",
            "line": "#1e4a5f",
            "accent": "#22d3ee",
            "accent_ink": "#083344",
        },
    },
}

THEME_PRESET_GROUPS = (
    ("Opsbook", ("custom", "opsbook")),
    ("Dark", ("steel", "jade", "ocean", "high-contrast")),
    ("Light", ("daylight", "paper")),
)

PING_THREAD_STARTED = False
EXPORT_JOB_RUN_LOCK = threading.Lock()
EXPORT_JOB_STATE_LOCK = threading.Lock()
EXPORT_JOB_STATE: dict[str, Any] = {
    "status": "idle",
    "started_at": "",
    "finished_at": "",
    "files": [],
    "error": "",
}
STATS_PRUNE_LOCK = threading.Lock()
LAST_STATS_PRUNE_MONOTONIC = 0.0
WEBHOOK_URL_SETTING = "ping_webhook_url_encrypted"
WEBHOOK_SCOPE_SETTING = "ping_webhook_scope"
WEBHOOK_RECOVERY_SETTING = "ping_webhook_send_recovery"
RECOVERY_PHRASE_HASH_SETTING = "recovery_phrase_hash"
TOTP_SCOPE_SETTING = "totp_scope"
TOTP_SCOPE_LOGIN = "login"
TOTP_SCOPE_HIGH_SECURITY = "high_security"
TOTP_SCOPE_BOTH = "both"
TOTP_SCOPES = {TOTP_SCOPE_LOGIN, TOTP_SCOPE_HIGH_SECURITY, TOTP_SCOPE_BOTH}
DEVICE_IMAGE_DIR = "device-images"
SUGGESTION_IMAGE_DIR = "suggestion-images"
MAX_IMAGE_UPLOAD_BYTES = 12 * 1024 * 1024
IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png", ".webp", ".gif"}
STATS_METRIC_CATALOG = [
    {"key": "cpu", "label": "CPU", "detail": "Processor use", "chart": "cpu_percent"},
    {"key": "memory", "label": "Memory", "detail": "RAM use", "chart": "memory_percent"},
    {"key": "disk", "label": "Root disk", "detail": "Main filesystem", "chart": "root_disk_percent"},
    {"key": "load", "label": "Load 1 min", "detail": "Raw system load", "chart": "load_1"},
    {"key": "swap", "label": "Swap", "detail": "Swap or pagefile use", "chart": "swap_percent"},
    {"key": "load_core", "label": "Load/core", "detail": "Load divided by CPU cores", "chart": "load_per_core"},
    {"key": "network", "label": "Network", "detail": "Combined RX/TX rate", "chart": "network_bps"},
    {"key": "freshness", "label": "Agent", "detail": "Freshness and missed reports", "chart": "missed_reports"},
    {"key": "docker", "label": "Docker", "detail": "Container health, opt-in", "chart": "docker_unhealthy_count"},
]
STATS_METRIC_KEYS = {item["key"] for item in STATS_METRIC_CATALOG}
STATS_DEFAULT_OVERVIEW_METRICS = ["cpu", "memory", "disk", "load"]
STATS_DETAIL_METRICS = [item["key"] for item in STATS_METRIC_CATALOG]


@app.on_event("startup")
def startup() -> None:
    global PING_THREAD_STARTED
    init_db()
    with SessionLocal() as db:
        seed_initial_data(db)
        _normalize_unknown_states(db)
        _prune_history(db)
        _prune_stats(db)
        db.commit()
    if not PING_THREAD_STARTED and not settings.read_only:
        PING_THREAD_STARTED = True
        threading.Thread(target=_ping_loop, name="kairix-ping-loop", daemon=True).start()


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def flash(request: Request, message: str, level: str = "info") -> None:
    messages = request.session.setdefault("_flash", [])
    messages.append({"message": message, "level": level})
    request.session["_flash"] = messages


def pop_flashes(request: Request) -> list[dict[str, str]]:
    messages = request.session.pop("_flash", [])
    return list(messages)


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = new_csrf_token()
        request.session["csrf"] = token
    return token


def check_csrf(request: Request, token: str) -> None:
    if not token or token != request.session.get("csrf"):
        raise HTTPException(status_code=400, detail="Invalid form token.")


def ensure_writable() -> None:
    if settings.read_only:
        raise HTTPException(
            status_code=403,
            detail="This Opsbook instance is in standby mode and is read-only.",
        )


def user_count(db: Session) -> int:
    return db.query(models.User).count()


def get_app_settings(db: Session) -> dict[str, str]:
    values = dict(THEME_DEFAULTS)
    for row in db.query(models.AppSetting).all():
        values[row.key] = row.value
    return values


def set_app_setting(db: Session, key: str, value: str) -> None:
    row = db.query(models.AppSetting).filter_by(key=key).first()
    if row:
        row.value = value
    else:
        db.add(models.AppSetting(key=key, value=value))


def css_color(value: str, fallback: str) -> str:
    clean = (value or "").strip()
    if clean.startswith("#") and len(clean) in {4, 7}:
        return clean
    return fallback


def int_setting(db: Session, key: str, default: int, *, minimum: int = 1, maximum: int = 50) -> int:
    raw = get_app_settings(db).get(key, str(default))
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def _clean_stats_metric_keys(raw_keys: list[str] | tuple[str, ...] | str | None, *, limit: int | None = None) -> list[str]:
    if isinstance(raw_keys, str):
        candidates = [part.strip() for part in raw_keys.split(",")]
    else:
        candidates = [str(part).strip() for part in (raw_keys or [])]
    keys: list[str] = []
    for key in candidates:
        if key in STATS_METRIC_KEYS and key not in keys:
            keys.append(key)
    if not keys:
        keys = list(STATS_DEFAULT_OVERVIEW_METRICS)
    return keys[:limit] if limit else keys


def _stats_overview_metric_keys(db: Session) -> list[str]:
    raw = get_app_settings(db).get("stats_overview_metrics", ",".join(STATS_DEFAULT_OVERVIEW_METRICS))
    return _clean_stats_metric_keys(raw, limit=4)


def _stats_expected_interval_minutes(db: Session) -> int:
    return int_setting(db, "stats_expected_interval_minutes", 5, minimum=1, maximum=1440)


def _stats_storage_interval_minutes(db: Session) -> int:
    return int_setting(db, "stats_storage_interval_minutes", 5, minimum=1, maximum=1440)


def _stats_retention_days(db: Session) -> int:
    return int_setting(db, "stats_retention_days", 30, minimum=1, maximum=3650)


def _stats_snapshot_can_coalesce(
    previous: models.DeviceStatSnapshot | None,
    observed_at: datetime,
    received_at: datetime,
    interval_minutes: int,
) -> bool:
    if previous is None or observed_at < _utc(previous.observed_at):
        return False
    bucket_started_at = _utc(previous.created_at or previous.observed_at)
    age_seconds = (received_at - bucket_started_at).total_seconds()
    return 0 <= age_seconds < max(1, interval_minutes) * 60


def _stats_metric_catalog(selected: list[str] | None = None) -> list[dict[str, str]]:
    selected_set = set(selected or [])
    return [{**item, "selected": "true" if item["key"] in selected_set else ""} for item in STATS_METRIC_CATALOG]


def bool_setting(db: Session, key: str, default: bool = False) -> bool:
    raw = get_app_settings(db).get(key)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _app_version_label() -> str:
    parts = [package_version]
    configured_version = str(settings.app_version or "").strip()
    if configured_version and configured_version != package_version:
        parts.append(f"configured {configured_version}")
    if settings.app_build:
        parts.append(f"build {settings.app_build}")
    if settings.app_build_iteration:
        parts.append(f"iteration {settings.app_build_iteration}")
    if settings.app_revision:
        parts.append(settings.app_revision[:7])
    return " · ".join(parts)


DEFAULT_SECRET_VALUES = {
    "opsbook": "dev-secret-change-before-real-use",
    "export": "dev-export-secret-change-before-real-use",
    "session": "dev-session-secret-change-before-real-use",
}
SECURITY_RATE_LIMITS: dict[str, dict[str, Any]] = {}
SECURITY_RATE_LOCK = threading.Lock()


def _client_rate_identity(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _rate_limit_key(request: Request, action: str, subject: str = "") -> str:
    clean_subject = re.sub(r"[^a-z0-9_.:@-]+", "-", subject.strip().lower())[:96]
    return f"{action}:{_client_rate_identity(request)}:{clean_subject}"


def _rate_limited(key: str) -> bool:
    now = now_utc()
    with SECURITY_RATE_LOCK:
        state = SECURITY_RATE_LIMITS.get(key)
        if not state:
            return False
        locked_until = state.get("locked_until")
        if isinstance(locked_until, datetime) and locked_until > now:
            return True
        if locked_until:
            SECURITY_RATE_LIMITS.pop(key, None)
        return False


def _record_rate_failure(
    key: str,
    *,
    max_failures: int = 8,
    window_minutes: int = 10,
    lock_minutes: int = 10,
) -> bool:
    now = now_utc()
    with SECURITY_RATE_LOCK:
        state = SECURITY_RATE_LIMITS.get(key)
        if not state or not isinstance(state.get("first_seen"), datetime) or state["first_seen"] + timedelta(minutes=window_minutes) < now:
            state = {"count": 0, "first_seen": now}
        state["count"] = int(state.get("count") or 0) + 1
        locked = state["count"] >= max_failures
        if locked:
            state["locked_until"] = now + timedelta(minutes=lock_minutes)
            state["count"] = 0
        SECURITY_RATE_LIMITS[key] = state
        return locked


def _clear_rate_limit(key: str) -> None:
    with SECURITY_RATE_LOCK:
        SECURITY_RATE_LIMITS.pop(key, None)


def _secret_posture(value: str, default_value: str, label: str) -> dict[str, str]:
    if value == default_value:
        return {
            "level": "danger",
            "label": label,
            "status": "Default value",
            "detail": "Replace this with a long random value in Portainer before storing real secrets.",
        }
    if len(value.strip()) < 32:
        return {
            "level": "warning",
            "label": label,
            "status": "Short value",
            "detail": "Use a long random value. Keep the same key on a standby mirror that imports this instance's encrypted backups.",
        }
    return {
        "level": "good",
        "label": label,
        "status": "Configured",
        "detail": "A non-default value is configured. Keep it backed up outside Opsbook.",
    }


def _posture_counts(items: list[dict[str, str]]) -> dict[str, int]:
    return {
        "danger": sum(1 for item in items if item["level"] == "danger"),
        "warning": sum(1 for item in items if item["level"] == "warning"),
        "good": sum(1 for item in items if item["level"] == "good"),
    }


def _upgrade_hash_if_needed(
    db: Session,
    user: models.User,
    value: str,
    *,
    field: str = "password_hash",
) -> bool:
    current = getattr(user, field)
    if not password_hash_needs_upgrade(current):
        return False
    setattr(user, field, hash_password(value))
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="password_hash_upgraded" if field == "password_hash" else "reveal_hash_upgraded",
            object_type="user",
            object_id=user.id,
            details_json={"field": field},
        )
    )
    return True


def _account_password_ok_and_upgrade(db: Session, user: models.User, password: str) -> bool:
    if not verify_password(password, user.password_hash):
        return False
    _upgrade_hash_if_needed(db, user, password)
    return True


def _challenge_ok_and_upgrade(db: Session, user: models.User, challenge: str) -> bool:
    match = challenge_match(challenge, user.password_hash, user.secondary_password_hash)
    if not match:
        return False
    field = "secondary_password_hash" if match == "secondary" else "password_hash"
    _upgrade_hash_if_needed(db, user, challenge, field=field)
    return True


def _webhook_scope(db: Session) -> str:
    row = db.query(models.AppSetting).filter_by(key=WEBHOOK_SCOPE_SETTING).first()
    value = (row.value if row and row.value else "both").strip().lower()
    return value if value in {"both", "devices", "services"} else "both"


def _webhook_recovery_enabled(db: Session) -> bool:
    row = db.query(models.AppSetting).filter_by(key=WEBHOOK_RECOVERY_SETTING).first()
    if row is None:
        return True
    return str(row.value).strip().lower() in {"1", "true", "yes", "on"}


def _webhook_url(db: Session) -> str:
    row = db.query(models.AppSetting).filter_by(key=WEBHOOK_URL_SETTING).first()
    if not row or not row.value:
        return ""
    try:
        return decrypt_text(row.value)
    except Exception:
        return ""


def _set_webhook_url(db: Session, url: str) -> None:
    clean = url.strip()
    if not clean:
        set_app_setting(db, WEBHOOK_URL_SETTING, "")
        return
    parsed = urlparse(clean)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Webhook URL must start with http:// or https://.")
    set_app_setting(db, WEBHOOK_URL_SETTING, encrypt_text(clean))


def _webhook_allows(db: Session, object_type: str) -> bool:
    scope = _webhook_scope(db)
    if scope == "both":
        return True
    if scope == "devices":
        return object_type == "device"
    return object_type in {"service", "service_group"}


def _validation_good(details: dict[str, Any]) -> bool | None:
    if not int(details.get("checked") or 0):
        return None
    return bool(details.get("ok")) or bool(details.get("partial"))


def _latest_service_validation_good(db: Session, service: models.Service) -> bool | None:
    latest = _latest_audit(db, "service", service.id, "service_validate")
    if not latest:
        return None
    return _validation_good(latest.details_json or {})


def _send_webhook_payload(db: Session, payload: dict[str, Any]) -> bool:
    url = _webhook_url(db)
    if not url:
        return False
    safe_payload = {
        "app": settings.app_name,
        "instance": settings.instance_name,
        "version": settings.app_version,
        "time_utc": now_utc().isoformat(),
        **payload,
    }
    try:
        request = UrlRequest(
            url,
            data=json.dumps(safe_payload, default=str).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": f"kairix-opsbook/{settings.app_version}"},
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            status_code = getattr(response, "status", 200)
            ok = 200 <= int(status_code) < 300
    except Exception as exc:
        db.add(
            models.AuditLog(
                action="webhook_failed",
                object_type=str(payload.get("object_type") or "webhook"),
                details_json={
                    "event": payload.get("event"),
                    "status": payload.get("status"),
                    "name": payload.get("name"),
                    "error": str(exc)[:240],
                },
            )
        )
        return False
    db.add(
        models.AuditLog(
            action="webhook_sent" if ok else "webhook_failed",
            object_type=str(payload.get("object_type") or "webhook"),
            details_json={
                "event": payload.get("event"),
                "status": payload.get("status"),
                "name": payload.get("name"),
                "http_status": status_code,
            },
        )
    )
    return ok


def _send_ping_webhook_event(
    db: Session,
    *,
    object_type: str,
    status_text: str,
    name: str,
    previous_good: bool | None,
    payload: dict[str, Any],
) -> bool:
    if not _webhook_allows(db, object_type):
        return False
    if status_text == "pass":
        if previous_good is not False or not _webhook_recovery_enabled(db):
            return False
    elif status_text == "fail":
        if previous_good is False:
            return False
    else:
        return False
    return _send_webhook_payload(
        db,
        {
            "event": "ping_state_change",
            "object_type": object_type,
            "status": status_text,
            "name": name,
            **payload,
        },
    )


def _notify_service_validation_webhooks(
    db: Session,
    transitions: list[tuple[models.Service, dict[str, Any], bool | None]],
) -> None:
    grouped_failures: dict[tuple[int, str], list[tuple[models.Service, dict[str, Any], bool | None]]] = {}
    for service, details, previous_good in transitions:
        current_good = _validation_good(details)
        if current_good is None:
            continue
        if current_good:
            _send_ping_webhook_event(
                db,
                object_type="service",
                status_text="pass",
                name=service.name,
                previous_good=previous_good,
                payload={
                    "device": service.device.name if service.device else "",
                    "service": service.name,
                    "group": service.docker_project,
                    "targets": details.get("targets") or [],
                },
            )
            continue
        if previous_good is False:
            continue
        group = (service.docker_project or "").strip()
        if group:
            grouped_failures.setdefault((service.device_id, group), []).append((service, details, previous_good))
        else:
            _send_ping_webhook_event(
                db,
                object_type="service",
                status_text="fail",
                name=service.name,
                previous_good=previous_good,
                payload={
                    "device": service.device.name if service.device else "",
                    "service": service.name,
                    "group": "",
                    "targets": details.get("targets") or [],
                },
            )
    for (_device_id, group), members in grouped_failures.items():
        if len(members) == 1:
            service, details, previous_good = members[0]
            _send_ping_webhook_event(
                db,
                object_type="service",
                status_text="fail",
                name=service.name,
                previous_good=previous_good,
                payload={
                    "device": service.device.name if service.device else "",
                    "service": service.name,
                    "group": group,
                    "targets": details.get("targets") or [],
                },
            )
            continue
        device = members[0][0].device
        _send_ping_webhook_event(
            db,
            object_type="service_group",
            status_text="fail",
            name=group,
            previous_good=True,
            payload={
                "device": device.name if device else "",
                "group": group,
                "services_down": len(members),
                "services": [service.name for service, _details, _previous_good in members],
            },
        )


def _normalize_unknown_states(db: Session) -> None:
    for device in db.query(models.Device).filter(models.Device.status_manual == "unknown").all():
        device.status_manual = ""
    for service in db.query(models.Service).filter(models.Service.status_manual == "unknown").all():
        service.status_manual = ""


def _device_order_query(db: Session):
    return db.query(models.Device).order_by(models.Device.display_order, models.Device.name)


def _service_order_query(db: Session):
    return (
        db.query(models.Service)
        .join(models.Device, models.Service.device_id == models.Device.id)
        .order_by(models.Device.display_order, models.Device.name, models.Service.name)
    )


def _next_device_order(db: Session) -> int:
    current = db.query(func.max(models.Device.display_order)).scalar()
    return (int(current) if current is not None else 0) + 10


def _credential_context_device(credential: models.Credential) -> models.Device | None:
    if credential.service and credential.service.device:
        return credential.service.device
    return credential.device


def _credential_sort_key(credential: models.Credential) -> tuple[int, str, str, str]:
    device = _credential_context_device(credential)
    return (
        device.display_order if device else 999999,
        (device.name if device else "zzzz").lower(),
        (credential.service.name if credential.service else "").lower(),
        credential.label.lower(),
    )


def _token_credentials(db: Session) -> list[models.Credential]:
    tokens = (
        db.query(models.Credential)
        .filter(models.Credential.secret_type == "API token")
        .all()
    )
    return sorted(tokens, key=lambda item: (item.expires_at is None, item.expires_at or datetime.max.replace(tzinfo=timezone.utc), item.label.lower()))


def _token_expiry_status(credential: models.Credential) -> dict[str, str]:
    if not credential.expires_at:
        return {"state": "ok", "label": "No expiry set"}
    expiry = credential.expires_at if credential.expires_at.tzinfo else credential.expires_at.replace(tzinfo=timezone.utc)
    now = now_utc()
    if expiry < now:
        return {"state": "expired", "label": f"Expired {format_dt(expiry)}"}
    if expiry <= now + timedelta(days=7):
        return {"state": "warning", "label": f"Expires soon: {format_dt(expiry)}"}
    return {"state": "ok", "label": f"Expires {format_dt(expiry)}"}


def _service_tokens(service: models.Service) -> list[models.Credential]:
    return [credential for credential in service.credentials if credential.secret_type == "API token"]


def _service_login_credentials(service: models.Service) -> list[models.Credential]:
    return [credential for credential in service.credentials if credential.secret_type != "API token"]


templates.env.globals["service_tokens"] = _service_tokens
templates.env.globals["service_login_credentials"] = _service_login_credentials
templates.env.globals["token_expiry_status"] = _token_expiry_status


def _parse_optional_datetime(value: str) -> datetime | None:
    clean = (value or "").strip()
    if not clean:
        return None
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    try:
        parsed = parsedate_to_datetime(clean)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError, IndexError):
        return None


def _date_input(value: datetime | None) -> str:
    if not value:
        return ""
    return value.date().isoformat()


templates.env.filters["date_input"] = _date_input


def _datetime_local_input(value: datetime | None) -> str:
    if not value:
        return ""
    if value.tzinfo:
        value = value.astimezone()
    return value.strftime("%Y-%m-%dT%H:%M")


templates.env.filters["datetime_local_input"] = _datetime_local_input


def _upload_root(subdir: str) -> Path:
    path = Path(settings.backup_dir) / subdir
    path.mkdir(parents=True, exist_ok=True)
    return path


def _stored_upload_path(subdir: str, stored_filename: str) -> Path:
    clean = Path(stored_filename or "").name
    if not clean:
        raise HTTPException(404, "File not found.")
    return _upload_root(subdir) / clean


def _suffix_for_upload(filename: str, content_type: str) -> str:
    suffix = Path(filename or "").suffix.lower()
    if suffix in IMAGE_SUFFIXES:
        return suffix
    return {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/webp": ".webp",
        "image/gif": ".gif",
    }.get(content_type.lower(), "")


async def _save_image_upload(upload: UploadFile, subdir: str) -> dict[str, Any]:
    original = Path(upload.filename or "image").name
    content_type = (upload.content_type or "").split(";", 1)[0].strip().lower()
    suffix = _suffix_for_upload(original, content_type)
    if not content_type.startswith("image/") or suffix not in IMAGE_SUFFIXES:
        raise ValueError("Use a JPG, PNG, WEBP, or GIF image.")
    data = await upload.read()
    if not data:
        raise ValueError("Choose an image to upload.")
    if len(data) > MAX_IMAGE_UPLOAD_BYTES:
        raise ValueError("Image is too large. Keep uploads under 12 MB.")
    stored = f"{uuid.uuid4().hex}{suffix}"
    path = _upload_root(subdir) / stored
    path.write_bytes(data)
    return {
        "original_filename": original,
        "stored_filename": stored,
        "mime_type": content_type,
        "size_bytes": len(data),
    }


def _extract_ocr_text(path: Path) -> tuple[str, str]:
    engine = shutil.which("tesseract")
    if not engine:
        return "", "Automatic OCR is not available in this container yet."
    try:
        result = subprocess.run(
            [engine, str(path), "stdout", "--psm", "6"],
            capture_output=True,
            text=True,
            timeout=35,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "", "OCR took too long and was skipped."
    except OSError:
        return "", "OCR could not start in this container."
    if result.returncode != 0:
        detail = (result.stderr or "").strip().splitlines()
        return "", detail[-1] if detail else "OCR could not read this image."
    text = re.sub(r"\n{3,}", "\n\n", (result.stdout or "").strip())
    if not text:
        return "", "OCR ran, but no readable text was found."
    return text, ""


RECOVERY_WORDS = [
    "anchor",
    "backup",
    "circuit",
    "docker",
    "lantern",
    "matrix",
    "opsbook",
    "primary",
    "signal",
    "stable",
    "vault",
    "warden",
]


def _suggested_recovery_phrase() -> str:
    words: list[str] = []
    while len(words) < 8:
        word = secrets.choice(RECOVERY_WORDS)
        if word not in words:
            words.append(word)
    words[0] = words[0].title()
    return f"{' '.join(words)} {10 + secrets.randbelow(90)}!"


def _recovery_phrase_hash(db: Session) -> str:
    row = db.query(models.AppSetting).filter_by(key=RECOVERY_PHRASE_HASH_SETTING).first()
    return row.value if row and row.value else ""


def _recovery_enabled(db: Session) -> bool:
    return bool(_recovery_phrase_hash(db))


def _recovery_phrase_error(value: str) -> str:
    phrase = (value or "").strip()
    if len(phrase) < 40 or len(re.findall(r"[A-Za-z0-9]+", phrase)) < 6:
        return "Use a sentence-style recovery phrase with at least 6 words and 40 characters."
    checks = [
        any(char.islower() for char in phrase),
        any(char.isupper() for char in phrase),
        any(char.isdigit() for char in phrase),
        any(not char.isalnum() and not char.isspace() for char in phrase),
    ]
    if not all(checks):
        return "Recovery phrase needs uppercase, lowercase, a number, and a special character."
    return ""


def _totp_scope(db: Session) -> str:
    row = db.query(models.AppSetting).filter_by(key=TOTP_SCOPE_SETTING).first()
    value = row.value if row and row.value else TOTP_SCOPE_LOGIN
    return value if value in TOTP_SCOPES else TOTP_SCOPE_LOGIN


def _set_totp_scope(db: Session, raw_value: str) -> str:
    value = raw_value if raw_value in TOTP_SCOPES else TOTP_SCOPE_LOGIN
    set_app_setting(db, TOTP_SCOPE_SETTING, value)
    return value


def _form_checkbox_enabled(value: str) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _totp_scope_from_flags(login_value: str, high_security_value: str) -> str:
    login_enabled = _form_checkbox_enabled(login_value)
    high_security_enabled = _form_checkbox_enabled(high_security_value)
    if login_enabled and high_security_enabled:
        return TOTP_SCOPE_BOTH
    if high_security_enabled:
        return TOTP_SCOPE_HIGH_SECURITY
    return TOTP_SCOPE_LOGIN


def _totp_scope_label(scope: str) -> str:
    if scope == TOTP_SCOPE_BOTH:
        return "main login and high-security credential reveals"
    if scope == TOTP_SCOPE_HIGH_SECURITY:
        return "high-security credential reveals"
    return "main login"


def _totp_login_enabled(db: Session) -> bool:
    return _totp_scope(db) in {TOTP_SCOPE_LOGIN, TOTP_SCOPE_BOTH}


def _totp_high_security_enabled(db: Session) -> bool:
    return _totp_scope(db) in {TOTP_SCOPE_HIGH_SECURITY, TOTP_SCOPE_BOTH}


def _verify_totp_code(user: models.User, code: str) -> bool:
    if not user.totp_secret_encrypted:
        return False
    secret = decrypt_text(user.totp_secret_encrypted)
    return pyotp.TOTP(secret).verify(code.strip().replace(" ", ""), valid_window=1)


def _credential_requires_totp(db: Session, user: models.User, credential: models.Credential) -> bool:
    return bool(
        user.totp_enabled
        and _totp_high_security_enabled(db)
        and credential.security_level in {"high", "extreme"}
    )


def _security_posture(user: models.User, db: Session) -> list[dict[str, str]]:
    items = [
        _secret_posture(settings.opsbook_secret_key, DEFAULT_SECRET_VALUES["opsbook"], "Opsbook secret key"),
        _secret_posture(settings.export_secret_key, DEFAULT_SECRET_VALUES["export"], "Export secret key"),
        _secret_posture(settings.session_secret_key, DEFAULT_SECRET_VALUES["session"], "Session secret key"),
    ]
    if "change-me" in settings.database_url or not settings.database_url.strip():
        items.append(
            {
                "level": "danger",
                "label": "Database password",
                "status": "Default or missing",
                "detail": "Set a long POSTGRES_PASSWORD in Portainer and redeploy the stack.",
            }
        )
    else:
        items.append(
            {
                "level": "good",
                "label": "Database password",
                "status": "Configured",
                "detail": "The database URL is not using the built-in development password.",
            }
        )
    if settings.session_cookie_secure:
        items.append(
            {
                "level": "good",
                "label": "Secure session cookie",
                "status": "On",
                "detail": "Browsers will only send the session cookie over HTTPS.",
            }
        )
    else:
        items.append(
            {
                "level": "warning",
                "label": "Secure session cookie",
                "status": "Off",
                "detail": "Leave off for plain HTTP LAN testing. Turn SESSION_COOKIE_SECURE=true when Opsbook is served through HTTPS.",
            }
        )
    if password_hash_needs_upgrade(user.password_hash):
        items.append(
            {
                "level": "warning",
                "label": "Account password hash",
                "status": "Legacy strength",
                "detail": "It will upgrade automatically after a successful password check, or immediately when you change the password.",
            }
        )
    else:
        items.append(
            {
                "level": "good",
                "label": "Account password hash",
                "status": "Current strength",
                "detail": "New password hashes use the current Opsbook work factor.",
            }
        )
    if user.secondary_password_hash:
        legacy = password_hash_needs_upgrade(user.secondary_password_hash)
        items.append(
            {
                "level": "warning" if legacy else "good",
                "label": "Reveal password",
                "status": "Legacy strength" if legacy else "Configured",
                "detail": "The reveal password can be upgraded by saving it again or by using Upgrade Existing Hashes. Prefer a phrase over a short PIN.",
            }
        )
    else:
        items.append(
            {
                "level": "warning",
                "label": "Reveal password",
                "status": "Not separate",
                "detail": "Credential reveals fall back to the account password. Add a separate reveal phrase for stronger separation.",
            }
        )
    if user.totp_enabled:
        items.append(
            {
                "level": "good",
                "label": "Two-factor authentication",
                "status": _totp_scope_label(_totp_scope(db)).title(),
                "detail": "2FA is enabled. Keep the recovery phrase configured before relying on it.",
            }
        )
    else:
        items.append(
            {
                "level": "warning",
                "label": "Two-factor authentication",
                "status": "Off",
                "detail": "Enable 2FA for login, high-security reveals, or both.",
            }
        )
    recovery_hash = _recovery_phrase_hash(db)
    if recovery_hash:
        recovery_legacy = password_hash_needs_upgrade(recovery_hash)
        items.append(
            {
                "level": "warning" if recovery_legacy else "good",
                "label": "Recovery phrase",
                "status": "Legacy strength" if recovery_legacy else "Configured",
                "detail": "The recovery phrase is hashed and can help recover access if 2FA is unavailable. Use Upgrade Existing Hashes if it shows legacy strength.",
            }
        )
    else:
        items.append(
            {
                "level": "warning",
                "label": "Recovery phrase",
                "status": "Missing",
                "detail": "Set this before relying on 2FA so you have a controlled recovery path.",
            }
        )
    items.append(
        {
            "level": "good",
            "label": "Brute-force guard",
            "status": "On",
            "detail": "Login, 2FA, and recovery attempts are rate-limited per client while the app process is running.",
        }
    )
    return items


def _recovery_challenge_options(db: Session) -> tuple[list[int], list[dict[str, Any]]]:
    recent = db.query(models.Service).order_by(models.Service.updated_at.desc()).limit(3).all()
    if len(recent) < 3:
        return [], []
    recent_ids = [service.id for service in recent]
    decoys = (
        db.query(models.Service)
        .filter(models.Service.id.notin_(recent_ids))
        .order_by(func.random())
        .limit(3)
        .all()
    )
    if len(decoys) < 3:
        return [], []
    options = recent + decoys
    secrets.SystemRandom().shuffle(options)
    return recent_ids, [
        {
            "id": service.id,
            "name": service.name,
            "device": service.device.name if service.device else "",
        }
        for service in options
    ]


def _history_retention_days(db: Session) -> int:
    return int_setting(db, "history_retention_days", 90, minimum=1, maximum=99999)


def _prune_history(db: Session, days: int | None = None) -> int:
    keep_days = days if days is not None else _history_retention_days(db)
    cutoff = now_utc() - timedelta(days=max(1, keep_days))
    deleted = (
        db.query(models.AuditLog)
        .filter(models.AuditLog.created_at < cutoff)
        .delete(synchronize_session=False)
    )
    return int(deleted or 0)


def _prune_stats(db: Session, days: int | None = None) -> int:
    keep_days = days if days is not None else _stats_retention_days(db)
    cutoff = now_utc() - timedelta(days=max(1, keep_days))
    deleted = (
        db.query(models.DeviceStatSnapshot)
        .filter(models.DeviceStatSnapshot.observed_at < cutoff)
        .delete(synchronize_session=False)
    )
    return int(deleted or 0)


def _maybe_prune_stats(db: Session) -> int:
    global LAST_STATS_PRUNE_MONOTONIC
    current = time.monotonic()
    if current - LAST_STATS_PRUNE_MONOTONIC < 3600:
        return 0
    if not STATS_PRUNE_LOCK.acquire(blocking=False):
        return 0
    try:
        current = time.monotonic()
        if current - LAST_STATS_PRUNE_MONOTONIC < 3600:
            return 0
        deleted = _prune_stats(db)
        LAST_STATS_PRUNE_MONOTONIC = current
        return deleted
    finally:
        STATS_PRUNE_LOCK.release()


def _infer_tags_for_service(service: models.Service) -> str:
    text = " ".join(
        [
            service.name,
            service.type,
            service.docker_project,
            service.compose_path,
            service.container_name,
            service.image,
            service.local_url,
            service.public_url,
        ]
    ).lower()
    tags: list[str] = []
    if "docker" in text or "compose" in text or service.container_name or service.image:
        tags.append("docker")
    if "portainer" in text:
        tags.extend(["portainer", "docker"])
    if "cloudflare" in text or "cloudflared" in text or "tunnel" in text:
        tags.append("cloudflare")
    if "postgres" in text or "postgresql" in text:
        tags.extend(["postgres", "database"])
    if "smb" in text or "samba" in text:
        tags.extend(["smb", "file-sharing"])
    if "ssh" in text:
        tags.extend(["ssh", "remote-access"])
    if "qbittorrent" in text or "torrent" in text:
        tags.extend(["torrent", "media"])
    if "sonarr" in text or "radarr" in text or "plex" in text or "immich" in text:
        tags.append("media")
    if "frigate" in text or "nvr" in text or "camera" in text:
        tags.extend(["frigate", "camera", "nvr"])
    if "home assistant" in text or "home-assistant" in text or "homeassistant" in text:
        tags.extend(["home-assistant", "smart-home"])
    if "mqtt" in text or "mosquitto" in text:
        tags.extend(["mqtt", "iot"])
    if "omada" in text:
        tags.extend(["omada", "network"])
    if "vaultwarden" in text or "bitwarden" in text:
        tags.extend(["vaultwarden", "password-manager"])
    if "filebrowser" in text:
        tags.extend(["filebrowser", "file-sharing"])
    if "syncthing" in text:
        tags.extend(["syncthing", "sync"])
    if "gluetun" in text or "vpn" in text:
        tags.append("vpn")
    if "windows" in text:
        tags.append("windows")
    if "raspberry" in text or "raspbian" in text or "pi " in f" {text} ":
        tags.append("raspberry-pi")
    return ", ".join(dict.fromkeys(tags))


def _infer_tags_for_device(device: models.Device) -> str:
    tags: list[str] = []
    device_text = " ".join(
        [
            device.name,
            device.type,
            device.hostname,
            device.os_name,
            device.os_version,
            device.location,
            device.purpose,
            device.notes,
            device.hardware.model if device.hardware else "",
            device.hardware.cpu if device.hardware else "",
        ]
    ).lower()
    if "debian" in device_text:
        tags.append("debian")
    if "ubuntu" in device_text:
        tags.append("ubuntu")
    if "windows" in device_text:
        tags.append("windows")
    if "raspberry" in device_text or "raspbian" in device_text or " pi " in f" {device_text} ":
        tags.extend(["raspberry-pi", "linux"])
    if device.services:
        tags.extend(["docker", "docker-host"])
    for service in device.services:
        service_tags = _infer_tags_for_service(service)
        if service_tags:
            tags.extend(service_tags.split(", "))
    for port in device.ports:
        if port.host_port == 22:
            tags.append("ssh")
        if port.host_port in {139, 445}:
            tags.append("smb")
    return ", ".join(dict.fromkeys(tag for tag in tags if tag))


def _context_tokens(*values: Any) -> set[str]:
    tokens: set[str] = set()
    for value in values:
        for token in re.findall(r"[a-z0-9]+", str(value or "").lower()):
            if len(token) > 1:
                tokens.add(token)
    return tokens


def _command_search_text(command: models.Command) -> str:
    return " ".join(
        str(value or "")
        for value in [
            command.name,
            command.category,
            command.command_template,
            command.short_description,
            command.long_description,
            command.help_low,
            command.help_high,
            command.where_to_run,
            command.notes,
        ]
    ).lower()


def _service_context_tokens(db: Session, service: models.Service) -> set[str]:
    tokens = _context_tokens(
        service.name,
        service.type,
        service.purpose,
        service.local_url,
        service.public_url,
        service.repo_url,
        service.compose_path,
        service.data_path,
        service.config_path,
        service.log_path,
        service.backup_path,
        service.docker_project,
        service.container_name,
        service.image,
        service.notes,
        _infer_tags_for_service(service),
        " ".join(tags_for(db, "service", service.id)),
    )
    if service.device:
        tokens.update(
            _context_tokens(
                service.device.name,
                service.device.type,
                service.device.hostname,
                service.device.primary_ip,
                service.device.os_name,
                service.device.os_version,
                service.device.purpose,
                _infer_tags_for_device(service.device),
                " ".join(tags_for(db, "device", service.device.id)),
            )
        )
        if service.device.primary_ip or service.device.hostname:
            tokens.update({"host", "ping", "network"})
    if service.repo_url:
        tokens.update({"git", "github", "repo", "repository"})
    if service.compose_path or service.docker_project or service.container_name or service.image:
        tokens.update({"docker", "compose", "container", "logs"})
    if service.ports:
        tokens.update({"port", "ports", "network"})
    if service.local_url or service.public_url:
        tokens.update({"url", "network"})
    if service.backup_path:
        tokens.update({"backup", "storage"})
    if tokens & {"debian", "ubuntu", "raspbian", "raspberry", "pi"}:
        tokens.add("linux")
    return tokens


def _device_context_tokens(db: Session, device: models.Device) -> set[str]:
    tokens = _context_tokens(
        device.name,
        device.type,
        device.purpose,
        device.hostname,
        device.primary_ip,
        device.os_name,
        device.os_version,
        device.location,
        device.notes,
        device.hardware.model if device.hardware else "",
        device.hardware.cpu if device.hardware else "",
        device.hardware.ram if device.hardware else "",
        device.hardware.storage_summary if device.hardware else "",
        _infer_tags_for_device(device),
        " ".join(tags_for(db, "device", device.id)),
    )
    if device.primary_ip or device.hostname:
        tokens.update({"host", "ping", "network"})
    if tokens & {"debian", "ubuntu", "raspbian", "raspberry", "pi"}:
        tokens.add("linux")
    if device.services:
        tokens.update({"service", "services"})
    for service in device.services:
        tokens.update(_service_context_tokens(db, service))
    for port in device.ports:
        tokens.update({"port", "ports", "network", str(port.host_port)})
        if port.host_port == 22:
            tokens.add("ssh")
        if port.host_port in {139, 445}:
            tokens.update({"smb", "samba", "file-sharing"})
    return tokens


def _generic_command_matches_context(command: models.Command, tokens: set[str]) -> bool:
    text = _command_search_text(command)
    category = (command.category or "").strip().lower()
    if category in {"common", "storage", "networking", "ssh"} and tokens & {"host", "network", "linux", "ports"}:
        return True
    if any(term in text for term in ["proxmox", "pveversion", "pvecm", "vzdump", "qm ", "pct "]):
        return "proxmox" in tokens or "pve" in tokens
    if any(term in text for term in ["docker", "compose", "container"]):
        return bool(tokens & {"docker", "compose", "container", "docker-host"})
    if any(term in text for term in ["github", "git ", "git\n", "{{repo", "repo "]):
        return bool(tokens & {"github", "git", "repo", "repository"})
    if any(term in text for term in ["cloudflare", "cloudflared", "trycloudflare", "tunnel"]):
        return bool(tokens & {"cloudflare", "cloudflared", "trycloudflare", "tunnel", "public-url"})
    if any(term in text for term in ["debian", "ubuntu", "apt ", "apt\n"]):
        return bool(tokens & {"debian", "ubuntu", "linux", "raspberry-pi", "raspbian"})
    if any(term in text for term in ["systemctl", "journalctl", "earlyoom", "oom", "reboot-required", "vmstat"]):
        return bool(tokens & {"linux", "debian", "ubuntu", "raspberry-pi", "docker"})
    if any(term in text for term in ["smb", "samba"]):
        return bool(tokens & {"smb", "samba", "file-sharing"})
    if "windows" in text:
        return "windows" in tokens or ("ping" in text and "host" in tokens)
    if "macos" in text:
        return "macos" in tokens or ("ping" in text and "host" in tokens)
    if any(term in text for term in ["port", "ping", "network", "disk", "memory", "load", "uptime", "df -h", "du -h", "free -h"]):
        return bool(tokens & {"host", "network", "linux", "ports", "storage", "docker"})
    return False


def _commands_for_service(db: Session, service: models.Service) -> list[models.Command]:
    tokens = _service_context_tokens(db, service)
    commands = (
        db.query(models.Command)
        .filter(
            or_(
                (models.Command.applies_to_type == "service")
                & (models.Command.applies_to_id == service.id),
                models.Command.applies_to_type == "generic",
            )
        )
        .order_by(models.Command.category, models.Command.name)
        .all()
    )
    return [
        command
        for command in commands
        if command.applies_to_type != "generic" or _generic_command_matches_context(command, tokens)
    ]


def _commands_for_device(db: Session, device: models.Device) -> tuple[list[models.Command], dict[int, models.Service]]:
    service_by_id = {service.id: service for service in device.services}
    service_ids = list(service_by_id) or [0]
    tokens = _device_context_tokens(db, device)
    commands = (
        db.query(models.Command)
        .filter(
            or_(
                (models.Command.applies_to_type == "device")
                & (models.Command.applies_to_id == device.id),
                (models.Command.applies_to_type == "service")
                & (models.Command.applies_to_id.in_(service_ids)),
                models.Command.applies_to_type == "generic",
            )
        )
        .order_by(models.Command.category, models.Command.name)
        .all()
    )
    filtered: list[models.Command] = []
    command_contexts: dict[int, models.Service] = {}
    for command in commands:
        if command.applies_to_type == "generic" and not _generic_command_matches_context(command, tokens):
            continue
        if command.applies_to_type == "service" and command.applies_to_id in service_by_id:
            command_contexts[command.id] = service_by_id[command.applies_to_id]
        filtered.append(command)
    return filtered, command_contexts


def _device_auto_purpose(device: models.Device, *, limit: int = 8) -> str:
    if device.purpose.strip() or not device.services:
        return ""
    names = [service.name for service in sorted(device.services, key=lambda item: item.name.lower())]
    visible = ", ".join(names[:limit])
    if len(names) > limit:
        visible += f", and {len(names) - limit} more"
    return f"Runs: {visible}."


def _notes_with_credentials_marker(notes: str, enabled: bool) -> str:
    cleaned = public_notes(notes)
    if enabled:
        return f"{cleaned}\n{NO_CREDENTIALS_MARKER}".strip()
    return cleaned


def _latest_audit(db: Session, object_type: str, object_id: int, action: str) -> models.AuditLog | None:
    return (
        db.query(models.AuditLog)
        .filter(
            models.AuditLog.object_type == object_type,
            models.AuditLog.object_id == object_id,
            models.AuditLog.action == action,
        )
        .order_by(models.AuditLog.created_at.desc())
        .first()
    )


def _ensure_device_hardware(db: Session, device: models.Device) -> models.DeviceHardware:
    hardware = db.query(models.DeviceHardware).filter_by(device_id=device.id).first()
    if hardware:
        device.hardware = hardware
        return hardware
    hardware = models.DeviceHardware(device_id=device.id)
    db.add(hardware)
    db.flush()
    device.hardware = hardware
    return hardware


def _replace_text_value(value: str | None, old: str, new: str) -> tuple[str, bool]:
    current = value or ""
    if not old:
        return current, False
    boundary = r"0-9A-Fa-f:" if ":" in old else r"A-Za-z0-9."
    pattern = re.compile(rf"(?<![{boundary}]){re.escape(old)}(?![{boundary}])")
    updated, count = pattern.subn(lambda _match: new, current)
    return updated, count > 0


def _replace_device_ip_references(device: models.Device, old_ip: str, new_ip: str) -> dict[str, int]:
    old_ip = old_ip.strip()
    new_ip = new_ip.strip()
    counts = {"services": 0, "urls": 0, "credentials": 0}
    if not old_ip or not new_ip or old_ip == new_ip:
        return counts

    for service in list(device.services):
        changed = False
        for attr in ("local_url", "public_url"):
            updated, did_change = _replace_text_value(getattr(service, attr), old_ip, new_ip)
            if did_change:
                setattr(service, attr, updated)
                changed = True
        if changed:
            counts["services"] += 1

    seen_url_ids: set[int] = set()
    for url in list(device.urls) + [url for service in list(device.services) for url in list(service.urls)]:
        if url.id in seen_url_ids:
            continue
        seen_url_ids.add(url.id)
        updated, changed = _replace_text_value(url.url, old_ip, new_ip)
        if changed:
            url.url = updated
            counts["urls"] += 1

    seen_credential_ids: set[int] = set()
    credentials = list(device.credentials)
    for service in list(device.services):
        credentials.extend(list(service.credentials))
    for credential in credentials:
        if credential.id in seen_credential_ids:
            continue
        seen_credential_ids.add(credential.id)
        updated, changed = _replace_text_value(credential.login_url, old_ip, new_ip)
        if changed:
            credential.login_url = updated
            counts["credentials"] += 1

    return counts


def _device_ping_status(db: Session, device: models.Device) -> dict[str, Any]:
    latest = _latest_audit(db, "device", device.id, "device_ping")
    interval = int_setting(db, "ping_interval_minutes", 60, minimum=5, maximum=999)
    if not latest:
        return {
            "state": "unknown",
            "label": "No ping yet",
            "latency_ms": None,
            "next_at": "Not scheduled yet",
            "next_at_iso": "",
            "last_at": "",
            "last_at_iso": "",
            "overdue": False,
        }
    details = latest.details_json or {}
    latest_at = _utc(latest.created_at)
    next_at = latest_at + timedelta(minutes=interval)
    overdue = next_at <= now_utc()
    if details.get("ok"):
        latency = float(details.get("latency_ms") or 0)
        green = int_setting(db, "ping_green_ms", 3, minimum=1, maximum=999)
        orange = int_setting(db, "ping_orange_ms", 10, minimum=1, maximum=999)
        state = "good" if latency <= green else "slow" if latency <= orange else "bad"
        label = f"{latency:.1f} ms"
    else:
        state = "down"
        label = f"No reply ({int(details.get('failures') or 1)} failed check(s))"
    return {
        "state": state,
        "label": label,
        "latency_ms": details.get("latency_ms"),
        "next_at": "due now" if overdue else format_dt(next_at),
        "next_at_iso": iso_dt(next_at),
        "last_at": format_dt(latest_at),
        "last_at_iso": iso_dt(latest_at),
        "overdue": overdue,
    }


def _device_ping_status_map(db: Session, devices: list[models.Device | None]) -> dict[int, dict[str, Any]]:
    statuses: dict[int, dict[str, Any]] = {}
    for device in devices:
        if device and device.id not in statuses:
            statuses[device.id] = _device_ping_status(db, device)
    return statuses


def _service_validation_status(db: Session, service: models.Service) -> dict[str, str]:
    latest = _latest_audit(db, "service", service.id, "service_validate")
    if not latest:
        return {"state": "unknown", "label": "Not checked", "checked_at": "", "checked_at_iso": ""}
    details = latest.details_json or {}
    if not int(details.get("checked") or 0):
        return {"state": "unknown", "label": "No URL or port documented", "checked_at": format_dt(latest.created_at), "checked_at_iso": iso_dt(latest.created_at)}
    ok = bool(details.get("ok"))
    partial = bool(details.get("partial"))
    targets = details.get("targets") or []
    target_labels = [str(item.get("label") or f"{item.get('host')}:{item.get('port')}") for item in targets if isinstance(item, dict)]
    target_summary = ", ".join(target_labels[:3])
    if len(target_labels) > 3:
        target_summary += f", and {len(target_labels) - 3} more"
    return {
        "state": "slow" if partial else "good" if ok else "bad",
        "label": ("Partial response" if partial else "Reachable" if ok else "No response") + (f" via TCP check: {target_summary}" if target_summary else ""),
        "checked_at": format_dt(latest.created_at),
        "checked_at_iso": iso_dt(latest.created_at),
    }


def _url_tcp_target(raw_url: str) -> tuple[str, int] | None:
    parsed = urlparse(raw_url or "")
    if not parsed.hostname:
        return None
    default_port = 443 if parsed.scheme == "https" else 80
    try:
        return parsed.hostname, parsed.port or default_port
    except ValueError:
        return None


def _service_url_validation_status(db: Session, service: models.Service, raw_url: str, label: str) -> dict[str, str]:
    latest = _latest_audit(db, "service", service.id, "service_validate")
    if not latest:
        return {"state": "unknown", "label": f"{label} not checked", "checked_at": "", "checked_at_iso": "", "title": f"{label} has not been checked yet."}
    checked_at = format_dt(latest.created_at)
    checked_at_iso = iso_dt(latest.created_at)
    details = latest.details_json or {}
    targets = [item for item in details.get("targets") or [] if isinstance(item, dict)]
    match = next((item for item in targets if item.get("label") == raw_url), None)
    url_target = _url_tcp_target(raw_url)
    if not match and url_target:
        host, port = url_target
        match = next(
            (
                item
                for item in targets
                if str(item.get("host") or "").lower() == host.lower()
                and str(item.get("port") or "") == str(port)
            ),
            None,
        )
    if not match:
        base = f"{label} was not part of the latest service check"
        return {
            "state": "unknown",
            "label": base,
            "checked_at": checked_at,
            "checked_at_iso": checked_at_iso,
            "title": f"{base}. Open the Ports tab or History tab for detailed validation logs.",
        }
    ok = bool(match.get("ok"))
    error = str(match.get("error") or "").strip()
    latency = match.get("latency_ms")
    status_label = f"{label} reachable via TCP check" if ok else f"{label} did not respond to TCP check"
    if ok and latency is not None:
        status_label += f" in {latency} ms"
    if error:
        status_label += f": {error}"
    return {
        "state": "good" if ok else "slow",
        "label": status_label,
        "checked_at": checked_at,
        "checked_at_iso": checked_at_iso,
        "title": f"{status_label} · checked {checked_at}. Open the Ports tab or History tab for detailed validation logs.",
    }


def _service_url_validation_statuses(db: Session, service: models.Service) -> dict[str, dict[str, str]]:
    return {
        "local_url": _service_url_validation_status(db, service, service.local_url, "Local URL") if service.local_url else {},
        "public_url": _service_url_validation_status(db, service, service.public_url, "Public URL") if service.public_url else {},
    }


def _service_port_validation_statuses(db: Session, service: models.Service) -> dict[int, dict[str, str]]:
    latest = _latest_audit(db, "service", service.id, "service_validate")
    statuses: dict[int, dict[str, str]] = {}
    if not latest:
        for port in service.ports:
            statuses[port.id] = {"state": "unknown", "label": "Port not checked", "title": "This port has not been checked yet."}
        return statuses
    checked_at = format_dt(latest.created_at)
    details = latest.details_json or {}
    targets = [item for item in details.get("targets") or [] if isinstance(item, dict)]
    host = (service.device.primary_ip or service.device.hostname or "").strip() if service.device else ""
    for port in service.ports:
        expected_label = f"{host}:{port.host_port}/{port.protocol}" if host else ""
        match = next((item for item in targets if expected_label and item.get("label") == expected_label), None)
        if not match and host:
            match = next(
                (
                    item
                    for item in targets
                    if str(item.get("host") or "").lower() == host.lower()
                    and str(item.get("port") or "") == str(port.host_port)
                ),
                None,
            )
        if not match:
            base = f"{port.host_port}/{port.protocol} was not part of the latest service check"
            statuses[port.id] = {
                "state": "unknown",
                "label": base,
                "title": f"{base}. Open the History tab for detailed validation logs.",
            }
            continue
        ok = bool(match.get("ok"))
        error = str(match.get("error") or "").strip()
        latency = match.get("latency_ms")
        label = f"{port.host_port}/{port.protocol} reachable via TCP check" if ok else f"{port.host_port}/{port.protocol} did not respond to TCP check"
        if ok and latency is not None:
            label += f" in {latency} ms"
        if error:
            label += f": {error}"
        statuses[port.id] = {
            "state": "good" if ok else "slow",
            "label": label,
            "title": f"{label} · checked {checked_at}. Open the History tab for detailed validation logs.",
        }
    return statuses


def _port_validation_status_map(db: Session, ports: list[models.Port]) -> dict[int, dict[str, str]]:
    statuses: dict[int, dict[str, str]] = {}
    seen_services: set[int] = set()
    for port in ports:
        if not port.service_id or port.service_id in seen_services or not port.service:
            continue
        seen_services.add(port.service_id)
        statuses.update(_service_port_validation_statuses(db, port.service))
    return statuses


def _service_validation_targets(service: models.Service) -> list[tuple[str, str, int]]:
    targets: list[tuple[str, str, int]] = []
    for raw_url in [service.local_url, service.public_url]:
        if not raw_url:
            continue
        target = _url_tcp_target(raw_url)
        if not target:
            continue
        host, port = target
        targets.append((raw_url, host, port))
    host = (service.device.primary_ip or service.device.hostname or "").strip() if service.device else ""
    if host:
        for port in service.ports:
            targets.append((f"{host}:{port.host_port}/{port.protocol}", host, port.host_port))
    seen: set[tuple[str, int]] = set()
    deduped: list[tuple[str, str, int]] = []
    for label, host, port in targets:
        key = (host, port)
        if key not in seen:
            seen.add(key)
            deduped.append((label, host, port))
    return deduped


def _check_tcp_target(host: str, port: int, timeout: float = 2.0) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency = (time.perf_counter() - started) * 1000
            return {"ok": True, "latency_ms": round(latency, 1)}
    except OSError as exc:
        return {"ok": False, "latency_ms": None, "error": str(exc)}


def _validate_service(db: Session, service: models.Service, user_id: int | None = None) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for label, host, port in _service_validation_targets(service):
        result = _check_tcp_target(host, port)
        result.update({"label": label, "host": host, "port": port})
        results.append(result)
    details = {
        "ok": bool(results) and all(item["ok"] for item in results),
        "partial": any(item["ok"] for item in results) and any(not item["ok"] for item in results),
        "targets": results,
        "checked": len(results),
    }
    db.add(
        models.AuditLog(
            user_id=user_id,
            action="service_validate",
            object_type="service",
            object_id=service.id,
            details_json=details,
        )
    )
    return details


def _dashboard_ping_overview(db: Session) -> list[dict[str, str]]:
    cutoff = now_utc() - timedelta(hours=12)
    items: list[dict[str, str]] = []
    for device in _device_order_query(db).all():
        latest = _latest_audit(db, "device", device.id, "device_ping")
        if not latest:
            items.append({"name": device.name, "state": "unknown", "label": "no ping"})
            continue
        details = latest.details_json or {}
        latest_at = _utc(latest.created_at)
        if details.get("ok") and latest_at >= cutoff:
            status = _device_ping_status(db, device)
            items.append({"name": device.name, "state": status["state"], "label": format_dt(latest_at), "when_iso": iso_dt(latest_at)})
        elif details.get("ok"):
            items.append({"name": device.name, "state": "unknown", "label": "older than 12h"})
        else:
            items.append({"name": device.name, "state": "down", "label": "no reply"})
    return items


def _failed_ping_summary(db: Session) -> dict[str, int]:
    summary = {"devices": 0, "services": 0, "total": 0}
    for suggestion in visible_suggestions(db):
        if suggestion.get("action") != "mute-ping":
            continue
        object_type = suggestion.get("object_type") or suggestion["id"].split(":", 1)[0]
        try:
            count = int(suggestion.get("count") or 1)
        except ValueError:
            count = 1
        if object_type == "device":
            summary["devices"] += count
        elif object_type == "service":
            summary["services"] += count
    summary["total"] = summary["devices"] + summary["services"]
    return summary


def _ping_device(db: Session, device: models.Device) -> dict[str, Any]:
    host = (device.primary_ip or device.hostname or "").strip()
    previous = _latest_audit(db, "device", device.id, "device_ping")
    previous_good = bool((previous.details_json or {}).get("ok")) if previous else None
    previous_failures = int((previous.details_json or {}).get("failures") or 0) if previous else 0
    if not host:
        details = {"ok": False, "latency_ms": None, "failures": previous_failures + 1, "error": "No IP or hostname"}
    else:
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", host],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            latency_match = re.search(r"time[=<]([0-9.]+)\s*ms", result.stdout)
            ok = result.returncode == 0
            details = {
                "ok": ok,
                "latency_ms": float(latency_match.group(1)) if latency_match else None,
                "failures": 0 if ok else previous_failures + 1,
                "host": host,
            }
        except Exception as exc:
            details = {"ok": False, "latency_ms": None, "failures": previous_failures + 1, "host": host, "error": str(exc)}
    db.add(models.AuditLog(action="device_ping", object_type="device", object_id=device.id, details_json=details))
    _send_ping_webhook_event(
        db,
        object_type="device",
        status_text="pass" if details.get("ok") else "fail",
        name=device.name,
        previous_good=previous_good,
        payload={
            "device": device.name,
            "host": host,
            "latency_ms": details.get("latency_ms"),
            "failures": details.get("failures"),
        },
    )
    return details


def _ping_loop() -> None:
    while True:
        try:
            if settings.read_only:
                time.sleep(60)
                continue
            with SessionLocal() as db:
                interval = int_setting(db, "ping_interval_minutes", 60, minimum=5, maximum=999)
                cutoff = now_utc() - timedelta(minutes=interval)
                devices = _device_order_query(db).all()
                for device in devices:
                    if not (device.primary_ip or device.hostname):
                        continue
                    latest = _latest_audit(db, "device", device.id, "device_ping")
                    if latest and _utc(latest.created_at) > cutoff:
                        continue
                    _ping_device(db, device)
                db.commit()
        except Exception:
            pass
        time.sleep(60)


def _run_login_checks(user_id: int | None = None) -> None:
    if settings.read_only:
        return
    try:
        with SessionLocal() as db:
            if bool_setting(db, "ping_on_login", True):
                for device in _device_order_query(db).all():
                    if device.primary_ip or device.hostname:
                        _ping_device(db, device)
                db.commit()
            if bool_setting(db, "validate_services_on_login", True):
                transitions: list[tuple[models.Service, dict[str, Any], bool | None]] = []
                for service in _service_order_query(db).all():
                    previous_good = _latest_service_validation_good(db, service)
                    details = _validate_service(db, service, user_id)
                    transitions.append((service, details, previous_good))
                _notify_service_validation_webhooks(db, transitions)
                db.commit()
    except Exception:
        pass


def _start_login_checks(user_id: int | None = None) -> None:
    threading.Thread(target=_run_login_checks, args=(user_id,), name="kairix-login-checks", daemon=True).start()


IMPORT_MODELS = {
    "devices": models.Device,
    "device_hardware": models.DeviceHardware,
    "services": models.Service,
    "credentials": models.Credential,
    "commands": models.Command,
    "recipes": models.Recipe,
    "recipe_steps": models.RecipeStep,
    "urls": models.Url,
    "ports": models.Port,
    "tags": models.Tag,
    "tag_links": models.TagLink,
    "notes": models.Note,
    "device_images": models.DeviceImage,
    "device_stat_snapshots": models.DeviceStatSnapshot,
    "user_suggestions": models.UserSuggestion,
    "imports": models.ImportRecord,
}


def _coerce_import_row(model: type[Any], row: dict[str, Any]) -> dict[str, Any]:
    coerced = dict(row)
    for column in model.__table__.columns:
        value = coerced.get(column.name)
        if value is None:
            continue
        if "DateTime" in column.type.__class__.__name__ and isinstance(value, str):
            try:
                coerced[column.name] = datetime.fromisoformat(value)
            except ValueError:
                coerced.pop(column.name, None)
    return coerced


def _walk_import_credentials(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    credentials: list[dict[str, Any]] = []
    credentials.extend(parsed.get("credentials", []))
    for service in parsed.get("services", []):
        credentials.extend(service.get("credentials", []))
    return credentials


def _sensitive_values_from_parsed(parsed: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for credential in _walk_import_credentials(parsed):
        secret = str(credential.get("secret") or "").strip()
        if secret:
            values.append(secret)
    for token in parsed.get("tokens", []):
        value = str(token.get("token") or "").strip()
        if value:
            values.append(value)
    return values


def _secure_parsed_for_storage(parsed: dict[str, Any]) -> dict[str, Any]:
    secured = copy.deepcopy(parsed)
    for credential in _walk_import_credentials(secured):
        secret = str(credential.pop("secret", "") or "").strip()
        if secret:
            credential["secret_encrypted"] = encrypt_text(secret)
            credential["secret_detected"] = True
    for token in secured.get("tokens", []):
        value = str(token.pop("token", "") or "").strip()
        if value:
            token["token_encrypted"] = encrypt_text(value)
    return secured


def _decrypted_parsed(record: models.ImportRecord) -> dict[str, Any]:
    parsed = copy.deepcopy(record.parsed_json or {})
    for credential in _walk_import_credentials(parsed):
        if "secret" not in credential and credential.get("secret_encrypted"):
            credential["secret"] = decrypt_text(str(credential.get("secret_encrypted")))
    for token in parsed.get("tokens", []):
        if "token" not in token and token.get("token_encrypted"):
            token["token"] = decrypt_text(str(token.get("token_encrypted")))
    return parsed


def _redact_sensitive_text(raw_text: str, parsed: dict[str, Any]) -> tuple[str, bool]:
    redacted = raw_text
    changed = False
    for value in sorted(_sensitive_values_from_parsed(parsed), key=len, reverse=True):
        if len(value) >= 3 and value in redacted:
            redacted = redacted.replace(value, "[redacted imported secret]")
            changed = True
    redacted = ACCESS_TOKEN_RE.sub("[redacted access token]", redacted)
    if redacted != raw_text:
        changed = True
    return redacted, changed


def _fallback_smart_paste_parse(raw_text: str, exc: Exception) -> dict[str, Any]:
    return {
        "device": {"name": "", "primary_ip": "", "os_name": "", "confidence": "low"},
        "services": [],
        "urls": [],
        "ports": [],
        "commands": [],
        "credentials": [],
        "tokens": [],
        "paths": [],
        "extras": {"parser_error": str(exc), "raw_length": len(raw_text or "")},
        "counts": {
            "ips": 0,
            "urls": 0,
            "ports": 0,
            "services": 0,
            "usernames": 0,
            "tokens": 0,
        },
        "parse_warning": "Smart Paste could not confidently structure this paste, so it was kept as reviewable source text instead of crashing.",
    }


def _safe_parse_smart_paste(raw_text: str) -> dict[str, Any]:
    try:
        return parse_smart_paste(raw_text)
    except Exception as exc:
        logger.exception("Smart Paste parser failed")
        return _fallback_smart_paste_parse(raw_text, exc)


def _id_list(value: str) -> list[int]:
    result: list[int] = []
    for part in (value or "").split(","):
        clean = part.strip()
        if clean.isdigit():
            result.append(int(clean))
    return result


def _normalize_text(value: str) -> str:
    return "\n".join(line.rstrip() for line in (value or "").strip().splitlines()).lower()


def _duplicate_command(db: Session, command_text: str) -> models.Command | None:
    normalized = _normalize_text(command_text)
    if not normalized:
        return None
    for command in db.query(models.Command).all():
        if _normalize_text(command.command_template) == normalized:
            return command
    return None


def _duplicate_credential(
    db: Session,
    *,
    device_id: int | None,
    service_id: int | None,
    label: str,
    username: str,
) -> models.Credential | None:
    label_norm = label.strip().lower()
    username_norm = username.strip().lower()
    query = db.query(models.Credential).filter(models.Credential.secret_type != "API token")
    if service_id:
        query = query.filter(models.Credential.service_id == service_id)
    elif device_id:
        query = query.filter(models.Credential.device_id == device_id)
    for credential in query.all():
        existing_label = credential.label.lower()
        existing_username = credential.username.lower()
        same_label = existing_label == label_norm or label_norm in existing_label or existing_label in label_norm
        same_user = existing_username == username_norm
        if same_user and (same_label or service_id or not label_norm):
            return credential
    return None


def _match_device_for_import(db: Session, parsed_device: dict[str, Any]) -> models.Device | None:
    ip = str(parsed_device.get("primary_ip", "")).strip()
    name = str(parsed_device.get("name", "")).strip()
    if ip:
        match = db.query(models.Device).filter(models.Device.primary_ip == ip).first()
        if match:
            return match
    if name:
        slug = slugify(name)
        for device in _device_order_query(db).all():
            if device.name.lower() == name.lower() or device.slug == slug:
                return device
    return None


def _service_alias(value: str) -> str:
    clean = slugify(value).replace("-git", "").replace("-app", "").replace("-service", "")
    clean = clean.replace("kairix-graphics-builder", "graphics-project")
    clean = clean.replace("kairix-opsbook", "opsbook")
    return clean.strip("-")


GENERIC_SERVICE_ALIAS_TOKENS = {
    "app",
    "backend",
    "container",
    "frontend",
    "git",
    "main",
    "server",
    "service",
    "ui",
    "web",
    "1",
    "2",
    "3",
    "4",
    "5",
}


def _service_alias_tokens(value: str) -> set[str]:
    return {token for token in slugify(value).split("-") if token}


def _service_aliases_compatible(import_alias: str, stored_alias: str) -> bool:
    if import_alias == stored_alias:
        return True
    if len(import_alias) <= 4 or len(stored_alias) <= 4:
        return False
    if import_alias not in stored_alias and stored_alias not in import_alias:
        return False
    import_tokens = _service_alias_tokens(import_alias)
    stored_tokens = _service_alias_tokens(stored_alias)
    if not import_tokens or not stored_tokens or not (import_tokens & stored_tokens):
        return False
    meaningful_difference = (import_tokens ^ stored_tokens) - GENERIC_SERVICE_ALIAS_TOKENS
    return not meaningful_difference


def _url_host(raw_url: str) -> str:
    try:
        return (urlparse(str(raw_url or "").strip()).hostname or "").lower()
    except ValueError:
        return ""


def _service_hint_local_hosts(service_hint: dict[str, Any]) -> set[str]:
    hosts: set[str] = set()
    for url_hint in service_hint.get("urls", []):
        url_value = str(url_hint.get("url") or "").strip()
        url_type = str(url_hint.get("url_type") or "local").lower()
        host = _url_host(url_value)
        if host and (url_type == "local" or host.startswith(("192.168.", "10.", "172."))):
            hosts.add(host)
    return hosts


def _service_local_hosts(service: models.Service) -> set[str]:
    hosts = {_url_host(service.local_url)}
    for url in service.urls:
        url_type = str(url.url_type or "local").lower()
        host = _url_host(url.url)
        if host and (url_type == "local" or host.startswith(("192.168.", "10.", "172."))):
            hosts.add(host)
    return {host for host in hosts if host}


def _service_host_context_conflicts(device: models.Device | None, service: models.Service, service_hint: dict[str, Any]) -> bool:
    hint_hosts = _service_hint_local_hosts(service_hint)
    stored_hosts = _service_local_hosts(service)
    if not hint_hosts or not stored_hosts or hint_hosts & stored_hosts:
        return False
    device_hosts = {str(getattr(device, "primary_ip", "") or "").lower(), str(getattr(device, "hostname", "") or "").lower()}
    device_hosts = {host for host in device_hosts if host}
    return bool(device_hosts and hint_hosts & device_hosts and not stored_hosts & device_hosts)


def _image_repo(value: str) -> str:
    clean = str(value or "").strip().lower()
    if not clean:
        return ""
    if "/" in clean.rsplit(":", 1)[-1]:
        return clean
    return clean.rsplit(":", 1)[0]


def _service_docker_identity_conflicts(service: models.Service, service_hint: dict[str, Any]) -> bool:
    hinted_container = str(service_hint.get("container_name") or "").strip().lower()
    stored_container = str(service.container_name or "").strip().lower()
    if hinted_container and stored_container and hinted_container != stored_container:
        return True
    hinted_image = _image_repo(str(service_hint.get("image") or ""))
    stored_image = _image_repo(service.image)
    return bool(hinted_image and stored_image and hinted_image != stored_image)


def _match_service_for_import(db: Session, device_id: int, service_hint: dict[str, Any]) -> models.Service | None:
    name = str(service_hint.get("name", "")).strip()
    aliases = {_service_alias(name), slugify(name)}
    device = db.get(models.Device, device_id)
    device_services = db.query(models.Service).filter(models.Service.device_id == device_id).all()
    hinted_container = str(service_hint.get("container_name") or "").strip().lower()
    if hinted_container:
        for service in device_services:
            if str(service.container_name or "").strip().lower() == hinted_container and not _service_host_context_conflicts(device, service, service_hint):
                return service
    for url in service_hint.get("urls", []):
        value = str(url.get("url", ""))
        existing_url = db.query(models.Url).filter(models.Url.url == value).first()
        if existing_url and existing_url.service and existing_url.service.device_id == device_id:
            return existing_url.service
        existing_service = (
            db.query(models.Service)
            .filter(
                models.Service.device_id == device_id,
                or_(models.Service.local_url == value, models.Service.public_url == value),
            )
            .first()
        )
        if existing_service:
            return existing_service
    for alias in aliases:
        if not alias:
            continue
        for service in device_services:
            if _service_host_context_conflicts(device, service, service_hint):
                continue
            if _service_docker_identity_conflicts(service, service_hint):
                continue
            service_aliases = {_service_alias(service.name), slugify(service.name)}
            if alias in service_aliases:
                return service
            if alias and any(_service_aliases_compatible(alias, existing) for existing in service_aliases):
                return service
    return None


def _service_import_aliases(value: str) -> set[str]:
    aliases = {_service_alias(value), slugify(value)}
    return {alias for alias in aliases if alias}


def _missing_services_from_import(
    db: Session,
    device: models.Device | None,
    parsed: dict[str, Any],
) -> list[dict[str, Any]]:
    docker_text = str(parsed.get("extras", {}).get("docker_containers", "") or "").strip()
    if not device or not docker_text or not parsed.get("services"):
        return []

    seen_aliases: set[str] = set()
    for item in parsed.get("services", []):
        for value in [item.get("name", ""), item.get("container_name", "")]:
            seen_aliases.update(_service_import_aliases(str(value)))

    missing: list[dict[str, Any]] = []
    for service in sorted(device.services, key=lambda item: item.name.lower()):
        is_docker_documented = bool(
            service.container_name
            or service.image
            or service.compose_path
            or service.docker_project
        )
        if not is_docker_documented:
            continue
        service_aliases: set[str] = set()
        for value in [service.name, service.container_name]:
            service_aliases.update(_service_import_aliases(value))
        if service_aliases & seen_aliases:
            continue
        missing.append(
            {
                "id": service.id,
                "name": service.name,
                "group": service.docker_project or "Ungrouped",
                "compose_path": service.compose_path,
                "credential_count": len(service.credentials),
                "port_count": len(service.ports),
                "url_count": len(service.urls),
            }
        )
    return missing


def _url_port(raw_url: str) -> int | None:
    parsed = urlparse(raw_url or "")
    if not parsed.hostname:
        return None
    try:
        return parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None


def _url_compare_key(raw_url: str) -> str:
    value = str(raw_url or "").strip()
    if not value:
        return ""
    try:
        parsed = urlparse(value)
    except ValueError:
        return value.rstrip("/").lower()
    scheme = (parsed.scheme or "").lower()
    netloc = (parsed.netloc or "").lower()
    path = (parsed.path or "").rstrip("/")
    query = f"?{parsed.query}" if parsed.query else ""
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""
    if not scheme or not netloc:
        return value.rstrip("/").lower()
    return f"{scheme}://{netloc}{path}{query}{fragment}"


def _url_values_match(left: str, right: str) -> bool:
    left_key = _url_compare_key(left)
    right_key = _url_compare_key(right)
    if left_key and left_key == right_key:
        return True
    try:
        left_parsed = urlparse(str(left or "").strip())
        right_parsed = urlparse(str(right or "").strip())
    except ValueError:
        return False
    same_origin = (
        left_parsed.scheme.lower(),
        left_parsed.netloc.lower(),
    ) == (
        right_parsed.scheme.lower(),
        right_parsed.netloc.lower(),
    )
    if not same_origin:
        return False
    root_paths = {left_parsed.path or "/", right_parsed.path or "/"} <= {"/"}
    has_hash_route = (left_parsed.fragment.startswith("!") or right_parsed.fragment.startswith("!"))
    has_non_hash_query = bool(left_parsed.query or right_parsed.query)
    return root_paths and has_hash_route and not has_non_hash_query


def _url_candidate_values(raw_url: str) -> list[str]:
    value = str(raw_url or "").strip()
    if not value:
        return []
    trimmed = value.rstrip("/")
    candidates = [value, trimmed]
    if trimmed:
        candidates.append(f"{trimmed}/")
    return list(dict.fromkeys(candidates))


def _duplicate_url_record(db: Session, raw_url: str) -> models.Url | None:
    candidates = _url_candidate_values(raw_url)
    if not candidates:
        return None
    duplicate = db.query(models.Url).filter(models.Url.url.in_(candidates)).first()
    if duplicate:
        return duplicate
    compare_key = _url_compare_key(raw_url)
    if not compare_key:
        return None
    return next(
        (
            url
            for url in db.query(models.Url).all()
            if _url_compare_key(url.url) == compare_key or _url_values_match(url.url, raw_url)
        ),
        None,
    )


def _service_url_field_match(service: models.Service, raw_url: str) -> str:
    if _url_values_match(service.local_url, raw_url):
        return "local URL"
    if _url_values_match(service.public_url, raw_url):
        return "public URL"
    return ""


def _duplicate_service_url(db: Session, device_id: int | None, raw_url: str) -> models.Service | None:
    if not device_id or not str(raw_url or "").strip():
        return None
    candidates = _url_candidate_values(raw_url)
    exact = (
        db.query(models.Service)
        .filter(
            models.Service.device_id == device_id,
            or_(models.Service.local_url.in_(candidates), models.Service.public_url.in_(candidates)),
        )
        .first()
    )
    if exact:
        return exact
    return next(
        (
            service
            for service in db.query(models.Service).filter(models.Service.device_id == device_id).all()
            if _service_url_field_match(service, raw_url)
        ),
        None,
    )


def _service_known_url_values(service: models.Service) -> list[str]:
    values = [service.local_url, service.public_url]
    values.extend(url.url for url in service.urls)
    return [str(value).strip() for value in values if str(value or "").strip()]


def _service_has_port_for_url(service: models.Service, raw_url: str) -> bool:
    port = _url_port(raw_url)
    if port is None:
        return False
    return any(port_record.host_port == port for port_record in service.ports)


def _primary_url_attr(url_hint: dict[str, Any]) -> str:
    return "public_url" if str(url_hint.get("url_type") or "").lower() == "public" else "local_url"


def _preserve_existing_service_url_paths(service_hint: dict[str, Any], existing: models.Service) -> None:
    existing_urls = [existing.local_url, existing.public_url]
    existing_urls.extend(url.url for url in existing.urls)
    for url_hint in service_hint.get("urls", []):
        suggested = str(url_hint.get("url") or "").strip()
        suggested_port = _url_port(suggested)
        if not suggested or suggested_port is None:
            continue
        try:
            parsed_suggested = urlparse(suggested)
        except ValueError:
            continue
        for old_url in existing_urls:
            try:
                parsed_old = urlparse(old_url or "")
            except ValueError:
                continue
            old_path = parsed_old.path or ""
            has_route_detail = bool((old_path and old_path != "/") or parsed_old.query or parsed_old.fragment)
            if not has_route_detail or _url_port(old_url) != suggested_port:
                continue
            url_hint["url"] = parsed_suggested._replace(
                path=old_path,
                params=parsed_old.params,
                query=parsed_old.query,
                fragment=parsed_old.fragment,
            ).geturl()
            break


def _import_badge(kind: str, label: str, title: str) -> dict[str, str]:
    return {"kind": kind, "label": label, "title": title}


def _import_list_label(values: list[str], *, empty: str = "") -> str:
    clean = [value for value in dict.fromkeys(values) if value]
    if not clean:
        return empty
    if len(clean) == 1:
        return clean[0]
    if len(clean) == 2:
        return f"{clean[0]} and {clean[1]}"
    return f"{', '.join(clean[:2])}, and {len(clean) - 2} more"


TUNNEL_MATCH_STOP_WORDS = {
    "cloudflare",
    "cloudflared",
    "trycloudflare",
    "temporary",
    "temp",
    "tunnel",
    "url",
    "urls",
    "quick",
    "container",
}


def _service_match_tokens(value: str, *, keep_role_words: bool = True) -> list[str]:
    tokens = [token for token in slugify(value).split("-") if token]
    if keep_role_words:
        return [token for token in tokens if token not in TUNNEL_MATCH_STOP_WORDS]
    role_words = {"public", "control", "admin", "web", "app", "db", "database", "postgres", "redis", "mysql"}
    return [token for token in tokens if token not in TUNNEL_MATCH_STOP_WORDS and token not in role_words]


def _service_tunnel_match_score(url_hint: dict[str, Any], service: models.Service) -> int:
    source_label = str(url_hint.get("source_label") or "")
    service_hint = str(url_hint.get("service_hint") or "")
    if not source_label and not service_hint:
        return 0

    source_text = f"{source_label} {service_hint}"
    source_tokens = _service_match_tokens(source_text)
    source_core_tokens = _service_match_tokens(source_text, keep_role_words=False)
    if not source_core_tokens:
        return 0

    service_text = " ".join(
        str(value or "")
        for value in [
            service.name,
            service.docker_project,
            service.container_name,
            service.image,
            service.local_url,
            service.public_url,
        ]
    )
    service_tokens = _service_match_tokens(service_text)
    service_core_tokens = _service_match_tokens(service_text, keep_role_words=False)
    if not service_core_tokens:
        return 0

    common_core = set(source_core_tokens) & set(service_core_tokens)
    score = len(common_core) * 4
    service_slug = slugify(service_text)
    hint_slug = slugify(service_hint)
    if hint_slug and len(hint_slug) > 4 and hint_slug in service_slug:
        score += 7
    if all(token in service_core_tokens for token in source_core_tokens):
        score += 5

    source_roles = set(source_tokens) - set(source_core_tokens)
    service_roles = set(service_tokens) - set(service_core_tokens)
    if "public" in source_roles and "public" in service_roles:
        score += 8
    if {"control", "admin"} & source_roles and {"web", "app", "admin", "control"} & service_roles:
        score += 6
    if "web" in source_roles and {"web", "app"} & service_roles:
        score += 5

    database_roles = {"db", "database", "postgres", "redis", "mysql"}
    if database_roles & service_roles and not (database_roles & source_roles):
        score -= 5
    if "agent" in service_tokens and "agent" not in source_tokens:
        score -= 3
    return score


def _suggest_service_for_tunnel_url(db: Session, url_hint: dict[str, Any]) -> models.Service | None:
    candidates: list[tuple[int, models.Service]] = []
    for service in db.query(models.Service).all():
        score = _service_tunnel_match_score(url_hint, service)
        if score >= 8:
            candidates.append((score, service))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1].id), reverse=True)
    return candidates[0][1]


def _suggested_url_field(url_hint: dict[str, Any]) -> str:
    return "public_url" if str(url_hint.get("url_type") or "").lower() == "public" else "local_url"


def _service_url_review_details(existing: models.Service, service_hint: dict[str, Any]) -> list[dict[str, str]]:
    details: list[dict[str, str]] = []
    known_urls = _service_known_url_values(existing)
    for field, label in [("local_url", "local URL"), ("public_url", "public URL")]:
        current = str(getattr(existing, field) or "").strip()
        if not current:
            continue
        pasted = [
            str(url_hint.get("url") or "").strip()
            for url_hint in service_hint.get("urls", [])
            if _suggested_url_field(url_hint) == field and str(url_hint.get("url") or "").strip()
        ]
        if any(_url_values_match(current, url) for url in pasted):
            continue
        different = [
            url
            for url in dict.fromkeys(pasted)
            if not any(_url_values_match(stored, url) for stored in known_urls)
        ]
        if different:
            details.append(
                {
                    "kind": "conflict",
                    "label": label,
                    "stored": current,
                    "pasted": ", ".join(different),
                    "note": "Opsbook already has a primary value for this service. Smart Paste found different endpoint(s); select them as extra URLs if they are valid, or edit the service if the primary URL should change.",
                }
            )
    return details


def _service_metadata_changes(existing: models.Service, service_hint: dict[str, Any]) -> tuple[list[str], list[str], list[dict[str, str]]]:
    fields = [
        ("docker_project", "stack/group", "stack_group"),
        ("compose_path", "compose path", "compose_path"),
        ("container_name", "container name", "container_name"),
        ("image", "image", "image"),
    ]
    fills: list[str] = []
    updates: list[str] = []
    conflicts: list[dict[str, str]] = []
    for attr, label, hint_key in fields:
        suggested = str(service_hint.get(hint_key) or "").strip()
        current = str(getattr(existing, attr) or "").strip()
        if not suggested:
            continue
        if not current:
            fills.append(label)
        elif attr == "image" and _image_repo(current) and _image_repo(current) == _image_repo(suggested):
            if current != suggested:
                updates.append(label)
        elif current != suggested:
            conflicts.append(
                {
                    "kind": "conflict",
                    "label": label,
                    "stored": current,
                    "pasted": suggested,
                    "note": "Smart Paste matched this service, but this stored metadata differs from the latest paste. Review before applying.",
                }
            )
    return fills, updates, conflicts


def _annotate_service_import_badges(service: dict[str, Any], duplicate: models.Service | None) -> None:
    badges: list[dict[str, str]] = []
    service["review_details"] = service.get("review_details", [])
    if not duplicate:
        badges.append(_import_badge("new", "New service", "Opsbook does not see a matching service on the selected device. Applying will create a new service record."))
    else:
        url_adds = sum(1 for url in service.get("urls", []) if url.get("selected"))
        port_adds = sum(1 for port in service.get("ports", []) if port.get("selected"))
        credential_adds = sum(1 for credential in service.get("credentials", []) if credential.get("selected"))
        metadata_fills, metadata_updates, metadata_conflicts = _service_metadata_changes(duplicate, service)
        conflict_details = _service_url_review_details(duplicate, service) + metadata_conflicts
        service["review_details"] = conflict_details
        conflicts = [detail["label"] for detail in conflict_details]
        additions: list[str] = []
        if url_adds:
            additions.append(f"{url_adds} URL{'s' if url_adds != 1 else ''}")
        if port_adds:
            additions.append(f"{port_adds} port{'s' if port_adds != 1 else ''}")
        if credential_adds:
            additions.append(f"{credential_adds} login{'s' if credential_adds != 1 else ''}")
        if conflicts:
            label = f"Conflict: {_import_list_label(conflicts)}"
            badges.append(_import_badge("conflict", label, "Smart Paste found a matching service, but the pasted value differs from a value already stored. Review before applying."))
        metadata_changes = metadata_fills + metadata_updates
        if metadata_changes:
            label = f"Updating entry: {_import_list_label(metadata_changes)}"
            badges.append(_import_badge("update", label, "A matching service exists and Smart Paste can fill blank Docker metadata or refresh the stored image tag."))
        if additions:
            label = f"Partially exists; adds {_import_list_label(additions)}"
            badges.append(_import_badge("partial", label, "A matching service already exists. Only the listed missing details are new or blank-field fills."))
        elif not conflicts and not metadata_changes:
            badges.append(_import_badge("exists", "Already exists", "A matching service already exists and Smart Paste did not find obvious new details for it."))
    if any("trycloudflare.com" in str(url.get("url") or "").lower() for url in service.get("urls", [])):
        badges.append(_import_badge("temp", "Temporary tunnel", "This service includes a trycloudflare.com quick tunnel URL. It may change after the cloudflared container restarts."))
    service["badges"] = badges


def _annotate_import_suggestions(db: Session, parsed: dict[str, Any]) -> dict[str, Any]:
    parsed = dict(parsed)
    matched_device = _match_device_for_import(db, parsed.get("device", {}))
    parsed["matched_device_id"] = matched_device.id if matched_device else None
    parsed["missing_services"] = _missing_services_from_import(db, matched_device, parsed)
    existing_device_id = matched_device.id if matched_device else None
    for command in parsed.get("commands", []):
        duplicate = _duplicate_command(db, command.get("command_template", ""))
        command["duplicate_id"] = duplicate.id if duplicate else None
        command["selected"] = duplicate is None and bool(command.get("command_template"))
        badges = [
            _import_badge("exists", "Already exists", "This exact command already exists in the command library.")
            if duplicate
            else _import_badge("new", "New command", "This command is not currently in the command library.")
        ]
        command_text = str(command.get("command_template") or "")
        command_name = str(command.get("name") or "")
        risk_level = str(command.get("risk_level") or "").lower()
        where_to_run = str(command.get("where_to_run") or "")
        if "trycloudflare.com" in command_text or "cloudflare tunnel" in command_name.lower():
            badges.append(_import_badge("helper", "Paste-back helper", "Run this on the Docker host, then paste the output back into Smart Paste to attach the discovered URLs."))
        if risk_level == "safe":
            badges.append(_import_badge("safe", "Safe lookup", "This command only reads container logs and prints URLs. It does not change the host."))
        elif risk_level:
            badges.append(_import_badge("risk", f"Risk: {risk_level}", "Review this command carefully before running it."))
        if where_to_run:
            badges.append(_import_badge("context", where_to_run, "Where Smart Paste expects this command to be run."))
        command["badges"] = badges
    for service in parsed.get("services", []):
        has_context = bool(
            service.get("ports")
            or service.get("urls")
            or service.get("credentials")
            or service.get("compose_path")
            or service.get("container_name")
            or service.get("image")
        )
        duplicate = None
        if existing_device_id and service.get("name"):
            duplicate = _match_service_for_import(db, existing_device_id, service)
        if duplicate:
            _preserve_existing_service_url_paths(service, duplicate)
        for url in service.get("urls", []):
            url_value = str(url.get("url", "")).strip()
            duplicate_url = _duplicate_url_record(db, url_value)
            duplicate_service = None
            if existing_device_id and url_value:
                duplicate_service = _duplicate_service_url(db, existing_device_id, url_value)
            primary_attr = _primary_url_attr(url)
            current_primary = str(getattr(duplicate, primary_attr) or "").strip() if duplicate else ""
            optional_endpoint = bool(
                duplicate
                and primary_attr == "local_url"
                and current_primary
                and not _url_values_match(current_primary, url_value)
                and _service_has_port_for_url(duplicate, url_value)
            )
            url["duplicate_id"] = duplicate_url.id if duplicate_url else None
            url["duplicate_service_id"] = duplicate_service.id if duplicate_service else None
            url["selected"] = duplicate_url is None and duplicate_service is None and not optional_endpoint
            url["badges"] = []
            if duplicate_url or duplicate_service:
                existing_location = "Opsbook"
                existing_value = url_value
                if duplicate_url:
                    existing_location = "URL record"
                    if duplicate_url.service:
                        existing_location = f"{duplicate_url.service.name} URL record"
                    elif duplicate_url.device:
                        existing_location = f"{duplicate_url.device.name} URL record"
                    existing_value = duplicate_url.url
                elif duplicate_service:
                    field_label = _service_url_field_match(duplicate_service, url_value) or "service URL"
                    existing_location = f"{duplicate_service.name} {field_label}"
                    existing_value = duplicate_service.local_url if field_label == "local URL" else duplicate_service.public_url
                url["existing_location"] = existing_location
                url["existing_value"] = existing_value
                url["badges"].append(_import_badge("exists", "Already documented", f"This URL is already stored in {existing_location}."))
            elif optional_endpoint:
                port_label = _url_port(url_value)
                url["review_note"] = (
                    f"Optional endpoint inferred from {duplicate.name}'s documented port {port_label}. "
                    "It is left unselected so it does not replace the service's main web UI URL."
                )
                url["badges"].append(
                    _import_badge(
                        "optional",
                        "Optional endpoint",
                        "Smart Paste inferred this URL from a port already documented on the matched service. Select it only if you want it saved as an extra URL.",
                    )
                )
            else:
                url["badges"].append(_import_badge("new", "New URL", "This URL is not stored yet and will be linked to the service if selected."))
            if "trycloudflare.com" in url_value.lower():
                url["badges"].append(_import_badge("temp", "Temporary tunnel", "Quick TryCloudflare URLs are temporary and may change when cloudflared restarts."))
            if len(url.get("history_urls") or []) > 1:
                url["badges"].append(
                    _import_badge(
                        "latest",
                        "Latest from log",
                        "This tunnel section contained older URLs. Smart Paste kept the final URL from that section.",
                    )
                )
            if url.get("source_label"):
                url["badges"].append(
                    _import_badge(
                        "source",
                        f"From: {url['source_label']}",
                        "This shows the container/log heading Smart Paste found immediately before the URL.",
                    )
                )
        for port in service.get("ports", []):
            duplicate_port = None
            if existing_device_id and port.get("host_port"):
                duplicate_port = (
                    db.query(models.Port)
                    .filter(
                        models.Port.device_id == existing_device_id,
                        models.Port.host_port == int(port["host_port"]),
                        models.Port.protocol == str(port.get("protocol", "tcp")),
                    )
                    .first()
                )
            port["duplicate_id"] = duplicate_port.id if duplicate_port else None
            port["selected"] = duplicate_port is None
            port["badges"] = [
                _import_badge("exists", "Already documented", "This port is already stored on the selected device.")
                if duplicate_port
                else _import_badge("new", "New port", "This port is not stored yet and will be linked to the service if selected.")
            ]
        for credential in service.get("credentials", []):
            label = str(credential.get("label", ""))
            username = str(credential.get("username", ""))
            duplicate_credential = None
            if label and username:
                duplicate_credential = _duplicate_credential(
                    db,
                    device_id=existing_device_id,
                    service_id=duplicate.id if duplicate else None,
                    label=label,
                    username=username,
                )
            credential["duplicate_id"] = duplicate_credential.id if duplicate_credential else None
            credential["selected"] = bool(credential.get("secret")) and duplicate_credential is None
            credential["badges"] = [
                _import_badge("exists", "Duplicate login", "A matching login already exists for this service or device.")
                if duplicate_credential
                else _import_badge("new", "New login", "This login does not appear to be stored yet.")
            ]
        service["duplicate_id"] = duplicate.id if duplicate else None
        service["selected"] = has_context
        _annotate_service_import_badges(service, duplicate)
    for port in parsed.get("ports", []):
        port["selected"] = False
        port["badges"] = [_import_badge("skip", "Loose; optional", "This listening port was not tied to a Docker service. Select it only if you want a standalone port record.")]
        if existing_device_id and port.get("host_port"):
            duplicate = (
                db.query(models.Port)
                .filter(models.Port.device_id == existing_device_id, models.Port.host_port == int(port["host_port"]))
                .first()
            )
            port["duplicate_id"] = duplicate.id if duplicate else None
            if duplicate:
                port["badges"] = [_import_badge("exists", "Already documented", "This standalone port is already stored on the selected device.")]
    for url in parsed.get("urls", []):
        url_value = str(url.get("url", "")).strip()
        duplicate = _duplicate_url_record(db, url_value)
        suggested_service = _suggest_service_for_tunnel_url(db, url) if "trycloudflare.com" in url_value.lower() else None
        url["duplicate_id"] = duplicate.id if duplicate else None
        url["selected"] = duplicate is None
        url["badges"] = [
            _import_badge("exists", "Already documented", "This URL is already stored in Opsbook.")
            if duplicate
            else _import_badge("new", "New URL", "This URL is not stored yet.")
        ]
        if "trycloudflare.com" in url_value.lower():
            url["badges"].append(_import_badge("temp", "Temporary tunnel", "Quick TryCloudflare URLs are temporary and may change when cloudflared restarts."))
        if len(url.get("history_urls") or []) > 1:
            url["badges"].append(
                _import_badge(
                    "latest",
                    "Latest from log",
                    "This tunnel section contained older URLs. Smart Paste kept the final URL from that section.",
                )
            )
        if url.get("source_label"):
            url["badges"].append(
                _import_badge(
                    "source",
                    f"From: {url['source_label']}",
                    "This shows the container/log heading Smart Paste found immediately before the URL.",
                )
            )
        if suggested_service:
            url["suggested_service_id"] = suggested_service.id
            url["suggested_service_name"] = suggested_service.name
            url["suggested_device_name"] = suggested_service.device.name if suggested_service.device else ""
            url["badges"].append(
                _import_badge(
                    "link",
                    f"Suggested link: {suggested_service.name}",
                    "Smart Paste matched the tunnel container/source label to this existing service. You can still choose a different service.",
                )
            )
    for credential in parsed.get("credentials", []):
        duplicate = None
        label = str(credential.get("label", ""))
        username = str(credential.get("username", ""))
        if label and username:
            query = db.query(models.Credential).filter(
                models.Credential.label.ilike(label),
                models.Credential.username.ilike(username),
            )
            if existing_device_id:
                query = query.filter(models.Credential.device_id == existing_device_id)
            duplicate = query.first()
        credential["duplicate_id"] = duplicate.id if duplicate else None
        credential["selected"] = bool(credential.get("secret")) and duplicate is None
        credential["badges"] = [
            _import_badge("exists", "Duplicate login", "A matching credential already exists.")
            if duplicate
            else _import_badge("new", "New login", "This credential does not appear to be stored yet.")
        ]
    for token in parsed.get("tokens", []):
        label = str(token.get("label", ""))
        username = str(token.get("username", ""))
        duplicate = None
        if label:
            duplicate = (
                db.query(models.Credential)
                .filter(
                    models.Credential.secret_type == "API token",
                    models.Credential.label.ilike(label),
                    models.Credential.username.ilike(username),
                )
                .first()
            )
        token["duplicate_id"] = duplicate.id if duplicate else None
        token["selected"] = bool(token.get("token")) and duplicate is None
        token["badges"] = [
            _import_badge("exists", "Duplicate token", "A matching token already exists.")
            if duplicate
            else _import_badge("new", "New token", "This token does not appear to be stored yet.")
        ]
    return parsed


def _create_token_credential_from_import(
    db: Session,
    user: models.User,
    form: Any,
    parsed: dict[str, Any],
    index_raw: str,
    record: models.ImportRecord,
    device: models.Device | None,
) -> models.Credential | None:
    item = parsed.get("tokens", [])[int(index_raw)]
    label = str(form.get(f"token_label_{index_raw}") or item.get("label") or "Imported token").strip()
    username = str(form.get(f"token_username_{index_raw}") or item.get("username", "")).strip()
    token_value = str(form.get(f"token_value_{index_raw}") or item.get("token", "")).strip()
    service_name = str(form.get(f"token_service_{index_raw}") or item.get("service_name", "")).strip()
    expires_at = _parse_optional_datetime(str(form.get(f"token_expiry_{index_raw}") or item.get("expires_at", "")))
    notes = str(form.get(f"token_notes_{index_raw}") or item.get("notes", "Imported access token.")).strip()
    if not label or not token_value:
        return None
    resolved_device_id, resolved_service_id, _ = _resolve_service_for_credential(
        db,
        device_id=device.id if device else None,
        service_id=None,
        service_name=service_name,
        label=label,
    )
    duplicate = (
        db.query(models.Credential)
        .filter(
            models.Credential.secret_type == "API token",
            models.Credential.label.ilike(label),
            models.Credential.username.ilike(username),
        )
        .first()
    )
    if duplicate:
        return None
    credential = models.Credential(
        device_id=resolved_device_id or (device.id if device else None),
        service_id=resolved_service_id,
        label=label,
        username=username,
        secret_encrypted=encrypt_text(token_value),
        secret_type="API token",
        security_level=str(item.get("security_level") or "high"),
        expires_at=expires_at,
        notes=notes,
        last_changed_at=now_utc(),
        active=True,
    )
    db.add(credential)
    db.flush()
    set_tags(db, "credential", credential.id, "token, api, temporary")
    if "github" in f"{label} {username} {notes}".lower():
        merge_tags(db, "credential", credential.id, "github")
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="token_created",
            object_type="credential",
            object_id=credential.id,
            details_json={"source": f"smart_paste:{record.id}", "expires_at": expires_at.isoformat() if expires_at else ""},
        )
    )
    return credential


def _apply_loose_urls_from_import(
    db: Session,
    form: Any,
    parsed: dict[str, Any],
    record: models.ImportRecord,
    default_device: models.Device | None,
) -> int:
    created_urls = 0
    for index_raw in form.getlist("urls"):
        item = parsed.get("urls", [])[int(index_raw)]
        url_value = str(form.get(f"url_value_{index_raw}") or item["url"]).strip()
        if not url_value:
            continue
        duplicate = db.query(models.Url).filter(models.Url.url == url_value).first()
        if duplicate:
            continue
        service_id_raw = str(form.get(f"url_service_{index_raw}") or "").strip()
        linked_service = db.get(models.Service, int(service_id_raw)) if service_id_raw.isdigit() else None
        if not linked_service and not default_device:
            continue
        url_type = str(form.get(f"url_type_{index_raw}") or item.get("url_type", "local"))
        if linked_service and "trycloudflare.com" in url_value.lower():
            url_type = "public"
        url_device_id = linked_service.device_id if linked_service else default_device.id
        if linked_service:
            if url_type == "public":
                linked_service.public_url = url_value
            elif url_type == "local":
                linked_service.local_url = url_value
        url_notes = f"Imported from Smart Paste {record.id}."
        if item.get("source_label"):
            url_notes += f" Source: {item['source_label']}."
        db.add(
            models.Url(
                device_id=url_device_id,
                service_id=linked_service.id if linked_service else None,
                url=url_value,
                url_type=url_type,
                notes=url_notes,
            )
        )
        created_urls += 1
    return created_urls


def _quick_credentials_for_device(db: Session, device: models.Device) -> list[models.Credential]:
    order = _id_list(get_app_settings(db).get(f"quick_credential_order:{device.id}", ""))
    hidden = set(_id_list(get_app_settings(db).get(f"quick_credential_hidden:{device.id}", "")))
    if not order:
        return []
    credentials = [
        credential
        for credential in device.credentials
        if credential.id in order and credential.id not in hidden and credential.secret_type != "API token"
    ]
    by_id = {credential.id: credential for credential in credentials}
    ordered = [by_id.pop(credential_id) for credential_id in order if credential_id in by_id]
    ordered.extend(sorted(by_id.values(), key=lambda item: item.label.lower()))
    return ordered


def _favorite_credential_ids_for_device(db: Session, device_id: int) -> set[int]:
    order = set(_id_list(get_app_settings(db).get(f"quick_credential_order:{device_id}", "")))
    hidden = set(_id_list(get_app_settings(db).get(f"quick_credential_hidden:{device_id}", "")))
    return order - hidden


def _favorite_credential_ids(db: Session) -> set[int]:
    ids: set[int] = set()
    for device in db.query(models.Device).all():
        ids.update(_favorite_credential_ids_for_device(db, device.id))
    return ids


def _delete_service_tree(db: Session, service: models.Service) -> None:
    for credential in db.query(models.Credential).filter_by(service_id=service.id).all():
        db.query(models.TagLink).filter_by(object_type="credential", object_id=credential.id).delete()
        db.delete(credential)
    for port in db.query(models.Port).filter_by(service_id=service.id).all():
        db.query(models.TagLink).filter_by(object_type="port", object_id=port.id).delete()
        db.delete(port)
    for url in db.query(models.Url).filter_by(service_id=service.id).all():
        db.query(models.TagLink).filter_by(object_type="url", object_id=url.id).delete()
        db.delete(url)
    db.query(models.Note).filter_by(object_type="service", object_id=service.id).delete()
    for command in db.query(models.Command).filter_by(applies_to_type="service", applies_to_id=service.id).all():
        db.query(models.TagLink).filter_by(object_type="command", object_id=command.id).delete()
        db.query(models.RecipeStep).filter_by(command_id=command.id).update({"command_id": None}, synchronize_session=False)
        db.delete(command)
    db.query(models.TagLink).filter_by(object_type="service", object_id=service.id).delete()
    db.flush()
    db.delete(service)


def _cleanup_obvious_import_misses(db: Session) -> dict[str, int]:
    cleaned = {"services": 0, "credentials": 0, "hardware": 0, "tag_links": 0}
    bad_service_slugs = {
        "checkopenports",
        "portainerfolder",
        "dockercheck",
        "mainfolders",
        "folderrules",
        "smbshares",
        "smbbyip",
        "restartsmb",
        "startstopacomposestack",
        "recommendedcomposepattern",
    }
    for service in list(db.query(models.Service).all()):
        if slugify(service.name).replace("-", "") in bad_service_slugs:
            _delete_service_tree(db, service)
            cleaned["services"] += 1

    service_groups: dict[tuple[int, str], list[models.Service]] = {}
    for service in db.query(models.Service).all():
        alias = _service_alias(service.name)
        if alias:
            service_groups.setdefault((service.device_id, alias), []).append(service)
    for services in service_groups.values():
        if len(services) < 2:
            continue
        ranked = sorted(
            services,
            key=lambda item: (
                bool(item.local_url or item.public_url),
                bool(item.compose_path or item.data_path or item.backup_path),
                len(item.credentials) + len(item.ports) + len(item.urls),
            ),
            reverse=True,
        )
        keeper = ranked[0]
        for duplicate in ranked[1:]:
            if duplicate.credentials or duplicate.ports or duplicate.urls:
                continue
            if duplicate.local_url or duplicate.public_url or duplicate.compose_path:
                continue
            _delete_service_tree(db, duplicate)
            cleaned["services"] += 1

    for loose in list(db.query(models.Credential).filter(models.Credential.service_id.is_(None)).all()):
        if not loose.device_id or not loose.username:
            continue
        loose_slug = slugify(loose.label)
        linked = (
            db.query(models.Credential)
            .join(models.Service, models.Credential.service_id == models.Service.id)
            .filter(
                models.Credential.device_id == loose.device_id,
                models.Credential.username.ilike(loose.username),
                models.Credential.service_id.is_not(None),
            )
            .all()
        )
        for candidate in linked:
            service_slug = slugify(candidate.service.name) if candidate.service else ""
            candidate_slug = slugify(candidate.label)
            if service_slug and (service_slug in loose_slug or service_slug in candidate_slug):
                db.query(models.TagLink).filter_by(object_type="credential", object_id=loose.id).delete()
                db.delete(loose)
                cleaned["credentials"] += 1
                break
    for hardware in db.query(models.DeviceHardware).all():
        changed = False
        cpu_match = re.search(r"Model name:\s*([^\n]+)", hardware.cpu or "")
        if cpu_match and hardware.cpu.strip() != cpu_match.group(1).strip():
            hardware.cpu = cpu_match.group(1).strip()
            changed = True
        ram_match = re.search(r"Mem:\s+(\S+)", hardware.ram or "")
        if ram_match and hardware.ram.strip() != ram_match.group(1).strip():
            hardware.ram = ram_match.group(1).strip()
            changed = True
        for line in (hardware.storage_summary or "").splitlines():
            clean = re.sub(r"^[├└─\s]+", "", line.strip())
            parts = clean.split()
            if len(parts) >= 3 and parts[2] == "disk":
                summary = " ".join(parts[:3])
                if hardware.storage_summary.strip() != summary:
                    hardware.storage_summary = summary
                    changed = True
                break
        if changed:
            cleaned["hardware"] += 1
    seen_links: set[tuple[int, str, int]] = set()
    for link in list(db.query(models.TagLink).order_by(models.TagLink.id).all()):
        key = (link.tag_id, link.object_type, link.object_id)
        if key in seen_links:
            db.delete(link)
            cleaned["tag_links"] += 1
        else:
            seen_links.add(key)
    return cleaned


AUDIT_ACTION_LABELS = {
    "credential_created": "Credential saved",
    "credential_edited": "Credential updated",
    "credential_revealed": "Credential revealed",
    "credential_deleted": "Credential deleted",
    "token_created": "Temporary token stored",
    "device_created": "Device added",
    "device_edited": "Device updated",
    "device_ip_references_updated": "Device IP references updated",
    "device_deleted": "Device deleted",
    "device_ping": "Device ping checked",
    "service_created": "Service added",
    "service_edited": "Service updated",
    "service_deleted": "Service deleted",
    "service_status_changed": "Service state changed",
    "service_validate": "Service validation checked",
    "services_validated": "Services validated",
    "command_created": "Command added",
    "command_edited": "Command updated",
    "command_deleted": "Command deleted",
    "port_added": "Port added",
    "port_edited": "Port updated",
    "port_deleted": "Port deleted",
    "url_added": "URL added",
    "url_edited": "URL updated",
    "url_deleted": "URL deleted",
    "note_added": "Note added",
    "note_edited": "Note edited",
    "note_deleted": "Note deleted",
    "note_tags_updated": "Note tags updated",
    "device_image_added": "Device image added",
    "device_image_edited": "Device image updated",
    "device_image_ocr": "Device image OCR updated",
    "device_image_deleted": "Device image deleted",
    "user_suggestion_created": "Custom suggestion created",
    "user_suggestion_done": "Custom suggestion completed",
    "tag_deleted": "Tag deleted",
    "quick_credentials_updated": "Favorite credentials updated",
    "ping_warning_scheduled": "Ping warning marked scheduled",
    "ping_warning_expected": "Check warning marked expected",
    "ping_warning_known_down": "Check warning marked known down",
    "smart_paste_parsed": "Smart Paste reviewed",
    "smart_paste_applied": "Smart Paste applied",
    "quick_note_saved": "Quick note saved",
    "emergency_export_created": "Emergency export created",
    "emergency_export_imported": "Emergency backup imported",
    "export_deleted": "Export deleted",
    "old_exports_deleted": "Old exports deleted",
    "settings_updated": "Settings changed",
    "device_order_updated": "Device order changed",
    "webhook_settings_updated": "Webhook settings changed",
    "webhook_sent": "Webhook sent",
    "webhook_failed": "Webhook failed",
    "webhook_test": "Webhook tested",
    "totp_setup_started": "2FA setup started",
    "totp_enabled": "2FA enabled",
    "totp_scope_changed": "2FA use changed",
    "totp_disabled": "2FA disabled",
    "password_changed": "Password changed",
    "password_hash_upgraded": "Password hash upgraded",
    "reveal_pin_changed": "Reveal password changed",
    "reveal_pin_removed": "Reveal password removed",
    "reveal_hash_upgraded": "Reveal password hash upgraded",
    "recovery_hash_upgraded": "Recovery phrase hash upgraded",
    "security_hash_upgrade_checked": "Security hashes checked",
    "recovery_phrase_updated": "Recovery phrase updated",
    "recovery_phrase_removed": "Recovery phrase removed",
    "recovery_login": "Recovery login",
}


def _safe_audit_details(details: dict[str, Any] | None) -> str:
    if not details:
        return ""
    hidden_words = ("secret", "password", "token", "key", "encrypted")
    parts: list[str] = []
    for key, value in details.items():
        if any(word in key.lower() for word in hidden_words):
            continue
        if value in (None, "", [], {}):
            continue
        if isinstance(value, list):
            value = f"{len(value)} item(s)"
        elif isinstance(value, dict):
            value = json.dumps(value, sort_keys=True, default=str)
        text_value = str(value)
        if len(text_value) > 120:
            text_value = f"{text_value[:117]}..."
        parts.append(f"{key.replace('_', ' ')}: {text_value}")
    return " · ".join(parts[:4])


def _audit_target_label(db: Session, log: models.AuditLog) -> tuple[str, str]:
    model_map: dict[str, tuple[type[Any], str, str]] = {
        "device": (models.Device, "name", "devices"),
        "service": (models.Service, "name", "services"),
        "credential": (models.Credential, "label", "credentials"),
        "command": (models.Command, "name", "commands"),
        "note": (models.Note, "title", "notes"),
        "url": (models.Url, "label", "urls"),
    }
    if log.object_type == "device_image" and log.object_id:
        image = db.get(models.DeviceImage, log.object_id)
        if image:
            return image.name or image.original_filename or f"Image #{image.id}", f"/devices/{image.device_id}?tab=images"
    if log.object_type == "user_suggestion" and log.object_id:
        suggestion = db.get(models.UserSuggestion, log.object_id)
        if suggestion:
            return suggestion.title or f"Suggestion #{suggestion.id}", "/suggestions"
    if log.object_type == "port" and log.object_id:
        port = db.get(models.Port, log.object_id)
        if port:
            label = f"{port.host_port}/{port.protocol}"
            if port.service:
                label = f"{label} · {port.service.name}"
            return label, f"/ports/{port.id}/edit"
    if log.object_type == "url" and log.object_id:
        url = db.get(models.Url, log.object_id)
        if url:
            return url.label or url.url or f"URL #{url.id}", f"/urls/{url.id}/edit"
    model_info = model_map.get(log.object_type)
    if model_info and log.object_id:
        model, label_attr, path = model_info
        obj = db.get(model, log.object_id)
        if obj:
            href = f"/commands/{log.object_id}/edit" if log.object_type == "command" else f"/{path}/{log.object_id}"
            return str(getattr(obj, label_attr) or f"{log.object_type.title()} #{log.object_id}"), href
    if log.object_type:
        return f"{log.object_type.replace('_', ' ').title()} {log.object_id or ''}".strip(), ""
    return "Opsbook", ""


def _note_target_label(db: Session, note: models.Note) -> tuple[str, str]:
    model_map: dict[str, tuple[type[Any], str, str]] = {
        "device": (models.Device, "name", "devices"),
        "service": (models.Service, "name", "services"),
        "credential": (models.Credential, "label", "credentials"),
        "command": (models.Command, "name", "commands"),
        "quick_note": (models.Note, "title", "notes"),
    }
    model_info = model_map.get(note.object_type)
    if not model_info:
        return note.object_type.replace("_", " ").title(), ""
    model, label_attr, path = model_info
    obj = db.get(model, note.object_id)
    if not obj:
        return note.object_type.replace("_", " ").title(), ""
    href = f"/commands/{note.object_id}/edit" if note.object_type == "command" else f"/{path}/{note.object_id}"
    return str(getattr(obj, label_attr) or f"{note.object_type.title()} #{note.object_id}"), href


def _human_audit_log(db: Session, log: models.AuditLog) -> dict[str, str]:
    target, href = _audit_target_label(db, log)
    raw = json.dumps(log.details_json or {}, indent=2, sort_keys=True, default=str)
    return {
        "title": AUDIT_ACTION_LABELS.get(log.action, log.action.replace("_", " ").title()),
        "target": target,
        "href": href,
        "when": format_dt(log.created_at),
        "details": _safe_audit_details(log.details_json),
        "raw": raw if raw != "{}" else "",
        "action": log.action,
        "object_type": log.object_type,
        "object_id": str(log.object_id or ""),
        "severity": "danger" if "deleted" in log.action else "info",
    }


def _resolve_service_for_credential(
    db: Session,
    *,
    device_id: int | None,
    service_id: int | None,
    service_name: str,
    label: str,
) -> tuple[int | None, int | None, str]:
    if service_id:
        service = db.get(models.Service, service_id)
        if service:
            return service.device_id, service.id, ""
    cleaned_service_name = service_name.strip()
    if cleaned_service_name:
        query = db.query(models.Service)
        if device_id:
            query = query.filter(models.Service.device_id == device_id)
        matches = [
            service
            for service in query.all()
            if service.name.lower() == cleaned_service_name.lower()
            or slugify(service.name) == slugify(cleaned_service_name)
        ]
        if len(matches) == 1:
            return matches[0].device_id, matches[0].id, ""
        if len(matches) > 1:
            return device_id, None, "More than one service matched that name. Pick a device first."
        if not device_id:
            devices = db.query(models.Device).limit(2).all()
            if len(devices) == 1:
                only_device = devices[0]
                device_id = only_device.id
        if not device_id:
            return device_id, None, "Pick a device before creating a service from the credential form."
        service = models.Service(
            device_id=device_id,
            name=cleaned_service_name,
            slug=slugify(cleaned_service_name),
            notes="Created while entering a credential.",
        )
        db.add(service)
        db.flush()
        return device_id, service.id, ""
    if label.strip():
        label_slug = slugify(label)
        query = db.query(models.Service)
        if device_id:
            query = query.filter(models.Service.device_id == device_id)
        services = query.all()
        matches: list[models.Service] = []
        for service in services:
            service_slug = slugify(service.name)
            if service_slug and (service_slug in label_slug or label_slug in service_slug):
                matches.append(service)
        if len(matches) == 1:
            return matches[0].device_id, matches[0].id, ""
    return device_id, None, ""


def _append_note_once(notes: str, line: str) -> str:
    clean_notes = public_notes(notes)
    clean_line = line.strip()
    if not clean_line or clean_line in clean_notes:
        return clean_notes
    return f"{clean_notes}\n{clean_line}".strip()


def _is_private_host(host: str) -> bool:
    clean = host.strip().lower()
    if clean in {"localhost", "127.0.0.1"}:
        return True
    if "." not in clean or clean.endswith(".local"):
        return True
    if clean.startswith("192.168.") or clean.startswith("10."):
        return True
    if clean.startswith("172."):
        parts = clean.split(".")
        if len(parts) >= 2 and parts[1].isdigit():
            return 16 <= int(parts[1]) <= 31
    return False


def _normalize_login_url_for_network(raw_url: str) -> str:
    clean = str(raw_url or "").strip()
    if not clean:
        return ""
    if "://" not in clean and re.match(r"^[A-Za-z0-9_.-]+:\d{2,5}(?:/|$)", clean):
        clean = f"http://{clean}"
    return clean


def _sync_credential_login_endpoint(
    db: Session,
    credential: models.Credential,
    *,
    default_device: models.Device | None = None,
) -> dict[str, int]:
    login_url = _normalize_login_url_for_network(credential.login_url)
    if not login_url:
        return {"urls": 0, "ports": 0, "devices": 0}
    credential.login_url = login_url
    try:
        parsed = urlparse(login_url)
    except ValueError:
        return {"urls": 0, "ports": 0, "devices": 0}
    host = parsed.hostname or ""
    if not host:
        return {"urls": 0, "ports": 0, "devices": 0}
    service = credential.service
    device = service.device if service and service.device else credential.device or default_device
    if not device and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        device = db.query(models.Device).filter(models.Device.primary_ip == host).first()
    changed = {"urls": 0, "ports": 0, "devices": 0}
    if device and not device.primary_ip and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        device.primary_ip = host
        changed["devices"] += 1
    if credential.device_id is None and device:
        credential.device_id = device.id
    url_type = "local" if _is_private_host(host) else "public"
    if service:
        primary_attr = "public_url" if url_type == "public" else "local_url"
        current_primary = str(getattr(service, primary_attr) or "").strip()
        if not current_primary:
            setattr(service, primary_attr, login_url)
            changed["urls"] += 1
        elif not any(_url_values_match(value, login_url) for value in _service_known_url_values(service)):
            duplicate_url = _duplicate_url_record(db, login_url)
            duplicate_service = _duplicate_service_url(db, device.id if device else service.device_id, login_url)
            if duplicate_url:
                if duplicate_url.service_id is None:
                    duplicate_url.service_id = service.id
                if duplicate_url.device_id is None and device:
                    duplicate_url.device_id = device.id
            elif not duplicate_service:
                db.add(
                    models.Url(
                        device_id=device.id if device else service.device_id,
                        service_id=service.id,
                        label=service.name,
                        url=login_url,
                        url_type=url_type,
                        notes=f"Inferred from credential {credential.label}.",
                    )
                )
                changed["urls"] += 1
    elif device:
        duplicate_url = _duplicate_url_record(db, login_url)
        if duplicate_url:
            if duplicate_url.device_id is None:
                duplicate_url.device_id = device.id
        else:
            db.add(
                models.Url(
                    device_id=device.id,
                    label=credential.label,
                    url=login_url,
                    url_type=url_type,
                    notes=f"Inferred from credential {credential.label}.",
                )
            )
            changed["urls"] += 1
    port_number = _url_port(login_url)
    if device and port_number:
        duplicate_port = (
            db.query(models.Port)
            .filter(
                models.Port.device_id == device.id,
                models.Port.host_port == port_number,
                models.Port.protocol == "tcp",
            )
            .first()
        )
        if duplicate_port:
            if service and duplicate_port.service_id is None:
                duplicate_port.service_id = service.id
            if service and not duplicate_port.purpose:
                duplicate_port.purpose = service.name
        else:
            db.add(
                models.Port(
                    device_id=device.id,
                    service_id=service.id if service else None,
                    host_port=port_number,
                    protocol="tcp",
                    purpose=service.name if service else credential.label,
                    notes=f"Inferred from credential {credential.label} login URL.",
                )
            )
            changed["ports"] += 1
    return changed


def _preserved_records_device(db: Session, *, excluding_id: int | None = None) -> models.Device:
    name = "Unassigned / Needs Reassignment"
    slug = slugify(name)
    excluded = db.get(models.Device, excluding_id) if excluding_id else None
    if excluded and excluded.slug == slug:
        name = "Preserved Records"
        slug = slugify(name)
    query = db.query(models.Device).filter(models.Device.slug == slug)
    if excluding_id:
        query = query.filter(models.Device.id != excluding_id)
    device = query.first()
    if device:
        return device
    device = models.Device(
        name=name,
        slug=unique_slug(db, models.Device, name, existing_id=excluding_id),
        type="holding",
        purpose="Preserves records from deleted devices until they are moved to the right machine.",
        display_order=999999,
    )
    db.add(device)
    db.flush()
    return device


def _move_device_records_to_preserved_device(db: Session, device: models.Device) -> models.Device:
    holding = _preserved_records_device(db, excluding_id=device.id)
    note = f"Moved here when device {device.name} was deleted."
    for service in list(device.services):
        service.device = holding
        service.device_id = holding.id
        service.notes = _append_note_once(service.notes, note)
    for credential in list(device.credentials):
        credential.device = holding
        credential.device_id = holding.id
        credential.notes = _append_note_once(credential.notes, note)
    for port in list(device.ports):
        port.device = holding
        port.device_id = holding.id
        port.notes = _append_note_once(port.notes, note)
    for url in list(device.urls):
        url.device = holding
        url.device_id = holding.id
        url.notes = _append_note_once(url.notes, note)
    for image in list(device.images):
        image.device = holding
        image.device_id = holding.id
        image.notes = _append_note_once(image.notes, note)
    db.query(models.Note).filter_by(object_type="device", object_id=device.id).update(
        {"object_id": holding.id, "body": models.Note.body + f"\n\n{note}"},
        synchronize_session=False,
    )
    db.query(models.Command).filter_by(applies_to_type="device", applies_to_id=device.id).update(
        {"applies_to_id": holding.id},
        synchronize_session=False,
    )
    db.flush()
    return holding


def _delete_redirect_target(request: Request, object_type: str, object_id: int) -> str:
    referer = request.headers.get("referer") or ""
    if object_type == "service" and f"/services/{object_id}" in referer:
        return "/services"
    if object_type == "credential" and f"/credentials/{object_id}" in referer:
        return "/credentials"
    if object_type == "note" and f"/notes/{object_id}" in referer:
        return "/notes"
    if object_type in {"port", "url"}:
        return "/ports"
    if object_type == "device" and f"/devices/{object_id}" in referer:
        return "/devices"
    defaults = {
        "device": "/devices",
        "service": "/services",
        "credential": "/credentials",
        "command": "/commands",
        "note": "/notes",
    }
    return referer or defaults.get(object_type, "/")


def _note_return_target(note: models.Note) -> str:
    if note.object_type == "device":
        return f"/devices/{note.object_id}?tab=notes"
    if note.object_type == "service":
        return f"/services/{note.object_id}?tab=notes"
    if note.object_type == "credential":
        return f"/credentials/{note.object_id}"
    if note.object_type == "command":
        return f"/commands/{note.object_id}/edit"
    return f"/notes/{note.id}"


def _safe_return_to(value: str, fallback: str) -> str:
    clean = (value or "").strip()
    if clean.startswith("/") and not clean.startswith("//"):
        return clean
    parsed = urlparse(clean)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        path = parsed.path or "/"
        if path.startswith("/") and not path.startswith("//"):
            return f"{path}?{parsed.query}" if parsed.query else path
    return fallback


def _credential_form_url(
    *,
    device_id: str = "",
    service_id: str = "",
    secret_type: str = "",
    return_to: str = "",
) -> str:
    params: list[str] = []
    if device_id:
        params.append(f"device_id={quote(device_id, safe='')}")
    if service_id:
        params.append(f"service_id={quote(service_id, safe='')}")
    if secret_type:
        params.append(f"secret_type={quote(secret_type, safe='')}")
    if return_to:
        params.append(f"return_to={quote(return_to, safe='')}")
    return "/credentials/new" + (f"?{'&'.join(params)}" if params else "")


def _credential_edit_url(credential_id: int, return_to: str) -> str:
    clean_return = _safe_return_to(return_to, f"/credentials/{credential_id}")
    return f"/credentials/{credential_id}/edit?return_to={quote(clean_return, safe='')}"


def _service_history(db: Session, service: models.Service, *, limit: int = 50) -> list[dict[str, str]]:
    filters = [
        and_(models.AuditLog.object_type == "service", models.AuditLog.object_id == service.id),
    ]
    credential_ids = [credential.id for credential in service.credentials]
    port_ids = [port.id for port in service.ports]
    url_ids = [url.id for url in service.urls]
    note_ids = [
        note_id
        for (note_id,) in db.query(models.Note.id)
        .filter(models.Note.object_type == "service", models.Note.object_id == service.id)
        .all()
    ]
    command_ids = [
        command_id
        for (command_id,) in db.query(models.Command.id)
        .filter(models.Command.applies_to_type == "service", models.Command.applies_to_id == service.id)
        .all()
    ]
    if credential_ids:
        filters.append(and_(models.AuditLog.object_type == "credential", models.AuditLog.object_id.in_(credential_ids)))
    if port_ids:
        filters.append(and_(models.AuditLog.object_type == "port", models.AuditLog.object_id.in_(port_ids)))
    if url_ids:
        filters.append(and_(models.AuditLog.object_type == "url", models.AuditLog.object_id.in_(url_ids)))
    if note_ids:
        filters.append(and_(models.AuditLog.object_type.in_(["note", "quick_note"]), models.AuditLog.object_id.in_(note_ids)))
    if command_ids:
        filters.append(and_(models.AuditLog.object_type == "command", models.AuditLog.object_id.in_(command_ids)))
    logs = (
        db.query(models.AuditLog)
        .filter(or_(*filters))
        .filter(models.AuditLog.action != "agent_stats_received")
        .order_by(models.AuditLog.created_at.desc())
        .limit(limit)
        .all()
    )
    return [_human_audit_log(db, log) for log in logs]


def _device_history(db: Session, device: models.Device, *, limit: int = 50) -> list[dict[str, str]]:
    filters = [
        and_(models.AuditLog.object_type == "device", models.AuditLog.object_id == device.id),
    ]
    service_ids = [service.id for service in device.services]
    credential_ids = [credential.id for credential in device.credentials]
    port_ids = [port.id for port in device.ports]
    url_ids = [url.id for url in device.urls]
    image_ids = [image.id for image in device.images]
    note_ids = [
        note_id
        for (note_id,) in db.query(models.Note.id)
        .filter(models.Note.object_type == "device", models.Note.object_id == device.id)
        .all()
    ]
    command_ids = [
        command_id
        for (command_id,) in db.query(models.Command.id)
        .filter(models.Command.applies_to_type == "device", models.Command.applies_to_id == device.id)
        .all()
    ]
    if service_ids:
        filters.append(and_(models.AuditLog.object_type == "service", models.AuditLog.object_id.in_(service_ids)))
    if credential_ids:
        filters.append(and_(models.AuditLog.object_type == "credential", models.AuditLog.object_id.in_(credential_ids)))
    if port_ids:
        filters.append(and_(models.AuditLog.object_type == "port", models.AuditLog.object_id.in_(port_ids)))
    if url_ids:
        filters.append(and_(models.AuditLog.object_type == "url", models.AuditLog.object_id.in_(url_ids)))
    if image_ids:
        filters.append(and_(models.AuditLog.object_type == "device_image", models.AuditLog.object_id.in_(image_ids)))
    if note_ids:
        filters.append(and_(models.AuditLog.object_type.in_(["note", "quick_note"]), models.AuditLog.object_id.in_(note_ids)))
    if command_ids:
        filters.append(and_(models.AuditLog.object_type == "command", models.AuditLog.object_id.in_(command_ids)))
    logs = (
        db.query(models.AuditLog)
        .filter(or_(*filters))
        .filter(models.AuditLog.action != "agent_stats_received")
        .order_by(models.AuditLog.created_at.desc())
        .limit(limit)
        .all()
    )
    return [_human_audit_log(db, log) for log in logs]


AGENT_PAYLOAD_MAX_BYTES = 256 * 1024


def _agent_token_from_request(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.headers.get("x-opsbook-agent-token", "").strip()


def _require_agent_token(request: Request) -> None:
    expected = settings.agent_ingest_token.strip()
    if settings.read_only:
        raise HTTPException(403, "Stats agent intake is disabled on standby instances.")
    if not expected:
        raise HTTPException(503, "Stats agent intake is not configured. Set OPSBOOK_AGENT_TOKEN on the Opsbook server.")
    supplied = _agent_token_from_request(request)
    rate_key = _rate_limit_key(request, "agent_stats", "token")
    if _rate_limited(rate_key):
        raise HTTPException(429, "Too many failed agent submissions. Try again later.")
    if not supplied or not secrets.compare_digest(supplied, expected):
        locked = _record_rate_failure(rate_key, max_failures=12, window_minutes=10, lock_minutes=10)
        raise HTTPException(429 if locked else 403, "Invalid stats agent token.")
    _clear_rate_limit(rate_key)


def _agent_string(value: Any, limit: int = 180) -> str:
    if value is None:
        return ""
    return str(value).strip()[:limit]


def _agent_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _agent_int(value: Any) -> int | None:
    number = _agent_float(value)
    if number is None:
        return None
    return int(number)


def _agent_percent(value: Any) -> float | None:
    number = _agent_float(value)
    if number is None:
        return None
    return max(0.0, min(100.0, number))


def _agent_rate_per_second(current: int | None, previous: int | None, elapsed_seconds: float | None) -> float | None:
    if current is None or previous is None or not elapsed_seconds or elapsed_seconds <= 0:
        return None
    delta = current - previous
    if delta < 0:
        return None
    return round(delta / elapsed_seconds, 2)


def _parse_agent_datetime(value: Any) -> datetime:
    if not value:
        return now_utc()
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return now_utc()
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _agent_root_disk(disks: Any) -> dict[str, Any]:
    if not isinstance(disks, list):
        return {}
    best: dict[str, Any] = {}
    for item in disks:
        if not isinstance(item, dict):
            continue
        mount = str(item.get("mountpoint") or item.get("mount") or "")
        if mount in {"/", "C:\\", "C:/"}:
            return item
        if not best:
            best = item
    return best


def _agent_identity_candidates(payload: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    for key in ("device_key", "device_name", "hostname"):
        value = _agent_string(payload.get(key), 180)
        if value and value not in candidates:
            candidates.append(value)
    return candidates


def _match_agent_device(db: Session, payload: dict[str, Any]) -> models.Device | None:
    device_id = _agent_int(payload.get("device_id"))
    if device_id:
        device = db.get(models.Device, device_id)
        if device:
            return device
    for candidate in _agent_identity_candidates(payload):
        lowered = candidate.lower()
        slug = slugify(candidate)
        device = (
            db.query(models.Device)
            .filter(
                or_(
                    func.lower(models.Device.hostname) == lowered,
                    func.lower(models.Device.name) == lowered,
                    models.Device.slug == slug,
                )
            )
            .order_by(models.Device.id)
            .first()
        )
        if device:
            return device
    primary_ip = _agent_string(payload.get("primary_ip"), 80)
    if primary_ip:
        device = db.query(models.Device).filter(models.Device.primary_ip == primary_ip).order_by(models.Device.id).first()
        if device:
            return device
    return None


def _create_agent_device(db: Session, payload: dict[str, Any]) -> models.Device:
    name = next(iter(_agent_identity_candidates(payload)), "") or _agent_string(payload.get("primary_ip"), 80) or "Stats Agent Device"
    hostname = _agent_string(payload.get("hostname"), 180)
    primary_ip = _agent_string(payload.get("primary_ip"), 80)
    os_name = _agent_string(payload.get("os_name") or payload.get("platform"), 160)
    device = models.Device(
        name=name,
        slug=unique_slug(db, models.Device, name),
        type="server",
        hostname=hostname,
        primary_ip=primary_ip,
        os_name=os_name,
        purpose="Created from Opsbook stats agent.",
    )
    db.add(device)
    db.flush()
    return device


def _apply_agent_device_metadata(db: Session, device: models.Device, payload: dict[str, Any]) -> None:
    hostname = _agent_string(payload.get("hostname"), 180)
    primary_ip = _agent_string(payload.get("primary_ip"), 80)
    os_name = _agent_string(payload.get("os_name") or payload.get("platform"), 160)
    if hostname and not device.hostname:
        device.hostname = hostname
    if primary_ip and not device.primary_ip:
        device.primary_ip = primary_ip
    if os_name and not device.os_name:
        device.os_name = os_name

    hardware_payload = payload.get("hardware") if isinstance(payload.get("hardware"), dict) else {}
    if not hardware_payload:
        return
    hardware = _ensure_device_hardware(db, device)
    field_map = {
        "model": "model",
        "cpu": "cpu",
        "ram": "ram",
        "storage_summary": "storage_summary",
    }
    for target, source in field_map.items():
        value = _agent_string(hardware_payload.get(source), 2000)
        if value and not getattr(hardware, target):
            setattr(hardware, target, value)


def _stats_snapshot_state(snapshot: models.DeviceStatSnapshot | None, *, expected_minutes: int = 5) -> dict[str, str]:
    if not snapshot:
        return {"state": "unknown", "label": "No agent data yet"}
    age = now_utc() - _utc(snapshot.created_at)
    minutes = max(0, int(age.total_seconds() // 60))
    fresh_limit = max(15, expected_minutes * 3)
    stale_limit = max(60, expected_minutes * 12)
    if minutes < fresh_limit:
        return {"state": "good", "label": f"Fresh · {minutes} min old"}
    if minutes < stale_limit:
        return {"state": "slow", "label": f"Stale · {minutes} min old"}
    hours = minutes // 60
    return {"state": "bad", "label": f"Old · {hours}h old"}


def _latest_stats_by_device(db: Session, devices: list[models.Device]) -> dict[int, models.DeviceStatSnapshot]:
    latest: dict[int, models.DeviceStatSnapshot] = {}
    for device in devices:
        snapshot = (
            db.query(models.DeviceStatSnapshot)
            .filter(models.DeviceStatSnapshot.device_id == device.id)
            .order_by(models.DeviceStatSnapshot.created_at.desc())
            .first()
        )
        if snapshot:
            latest[device.id] = snapshot
    return latest


def _stats_window_hours(db: Session) -> int:
    return int_setting(db, "stats_window_hours", 8, minimum=1, maximum=168)


def _missed_report_count(snapshot: models.DeviceStatSnapshot | None, expected_minutes: int) -> int:
    if not snapshot:
        return 0
    minutes = max(0, int((now_utc() - _utc(snapshot.created_at)).total_seconds() // 60))
    return max(0, minutes // max(1, expected_minutes) - 1)


def _stat_float(value: float | int | None) -> float | None:
    if value is None:
        return None
    try:
        return round(float(value), 2)
    except (TypeError, ValueError):
        return None


def _stat_int(value: float | int | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _stat_rate_value(*values: float | int | None) -> float | None:
    numbers = [float(value) for value in values if value is not None]
    if not numbers:
        return None
    return round(sum(numbers), 2)


def _payload_mapping(snapshot: models.DeviceStatSnapshot, key: str) -> dict[str, Any]:
    payload = snapshot.payload_json if isinstance(snapshot.payload_json, dict) else {}
    value = payload.get(key)
    return value if isinstance(value, dict) else {}


def _payload_list(snapshot: models.DeviceStatSnapshot, key: str) -> list[Any]:
    payload = snapshot.payload_json if isinstance(snapshot.payload_json, dict) else {}
    value = payload.get(key)
    return value if isinstance(value, list) else []


def _stat_disk_details(snapshot: models.DeviceStatSnapshot) -> list[dict[str, str]]:
    disks: list[dict[str, str]] = []
    for item in _payload_list(snapshot, "disks")[:24]:
        if not isinstance(item, dict):
            continue
        mount = str(item.get("mountpoint") or item.get("mount") or "Disk").strip() or "Disk"
        used = _stat_int(item.get("used_bytes"))
        total = _stat_int(item.get("total_bytes"))
        disks.append(
            {
                "label": mount,
                "percent": stat_percent(_stat_float(item.get("percent"))),
                "detail": f"{stat_bytes(used)} / {stat_bytes(total)}",
            }
        )
    return disks


def _stat_network_details(snapshot: models.DeviceStatSnapshot) -> list[dict[str, str]]:
    network = _payload_mapping(snapshot, "network")
    interfaces = network.get("interfaces") if isinstance(network.get("interfaces"), list) else []
    details: list[dict[str, str]] = []
    for item in interfaces[:32]:
        if not isinstance(item, dict):
            continue
        details.append(
            {
                "label": str(item.get("name") or "interface"),
                "detail": f"Totals since boot/reset: RX {stat_bytes(_stat_int(item.get('rx_bytes')))} · TX {stat_bytes(_stat_int(item.get('tx_bytes')))}",
            }
        )
    return details


def _stat_docker_details(snapshot: models.DeviceStatSnapshot) -> dict[str, Any]:
    docker = _payload_mapping(snapshot, "docker")
    containers = docker.get("containers") if isinstance(docker.get("containers"), list) else []
    return {
        "enabled": bool(docker.get("enabled")),
        "running": _stat_int(docker.get("running")),
        "stopped": _stat_int(docker.get("stopped")),
        "unhealthy": _stat_int(docker.get("unhealthy")),
        "total": _stat_int(docker.get("total")),
        "containers": [
            {
                "name": str(item.get("name") or "container") if isinstance(item, dict) else "container",
                "state": str(item.get("state") or "") if isinstance(item, dict) else "",
                "status": str(item.get("status") or "") if isinstance(item, dict) else "",
                "image": str(item.get("image") or "") if isinstance(item, dict) else "",
            }
            for item in containers[:30]
            if isinstance(item, dict)
        ],
    }


def _stat_snapshot_payload(snapshot: models.DeviceStatSnapshot, *, expected_minutes: int = 5) -> dict[str, Any]:
    memory_detail = ""
    if snapshot.memory_used_bytes and snapshot.memory_total_bytes:
        memory_detail = f"{stat_bytes(snapshot.memory_used_bytes)} / {stat_bytes(snapshot.memory_total_bytes)}"
    swap_detail = ""
    if snapshot.swap_total_bytes is not None:
        swap_detail = f"{stat_bytes(snapshot.swap_used_bytes)} / {stat_bytes(snapshot.swap_total_bytes)}"
    disk_detail = ""
    if snapshot.root_disk_used_bytes and snapshot.root_disk_total_bytes:
        disk_detail = f"{stat_bytes(snapshot.root_disk_used_bytes)} / {stat_bytes(snapshot.root_disk_total_bytes)}"
    network_bps = _stat_rate_value(snapshot.network_rx_bps, snapshot.network_tx_bps)
    network_detail = ""
    if snapshot.network_rx_bps is not None or snapshot.network_tx_bps is not None:
        network_detail = f"RX {stat_rate(snapshot.network_rx_bps)} · TX {stat_rate(snapshot.network_tx_bps)}"
    state = _stats_snapshot_state(snapshot, expected_minutes=expected_minutes)
    missed_reports = _missed_report_count(snapshot, expected_minutes)
    docker_detail = ""
    if snapshot.docker_total_count is not None:
        docker_detail = f"{snapshot.docker_running_count or 0} running · {snapshot.docker_stopped_count or 0} stopped"
    return {
        "id": snapshot.id,
        "created_at": iso_dt(snapshot.created_at),
        "observed_at": iso_dt(snapshot.observed_at),
        "cpu_percent": _stat_float(snapshot.cpu_percent),
        "cpu_count": snapshot.cpu_count,
        "memory_percent": _stat_float(snapshot.memory_percent),
        "memory_used_bytes": snapshot.memory_used_bytes,
        "memory_total_bytes": snapshot.memory_total_bytes,
        "swap_percent": _stat_float(snapshot.swap_percent),
        "swap_used_bytes": snapshot.swap_used_bytes,
        "swap_total_bytes": snapshot.swap_total_bytes,
        "root_disk_percent": _stat_float(snapshot.root_disk_percent),
        "root_disk_used_bytes": snapshot.root_disk_used_bytes,
        "root_disk_total_bytes": snapshot.root_disk_total_bytes,
        "load_1": _stat_float(snapshot.load_1),
        "load_5": _stat_float(snapshot.load_5),
        "load_15": _stat_float(snapshot.load_15),
        "load_per_core": _stat_float(snapshot.load_per_core),
        "network_rx_bps": _stat_float(snapshot.network_rx_bps),
        "network_tx_bps": _stat_float(snapshot.network_tx_bps),
        "network_bps": network_bps,
        "missed_reports": missed_reports,
        "docker_unhealthy_count": snapshot.docker_unhealthy_count,
        "docker_running_count": snapshot.docker_running_count,
        "docker_stopped_count": snapshot.docker_stopped_count,
        "docker_total_count": snapshot.docker_total_count,
        "uptime_seconds": _stat_float(snapshot.uptime_seconds),
        "agent_version": snapshot.agent_version,
        "details": {
            "disks": _stat_disk_details(snapshot),
            "network": _stat_network_details(snapshot),
            "docker": _stat_docker_details(snapshot),
        },
        "labels": {
            "cpu": stat_percent(snapshot.cpu_percent),
            "memory": stat_percent(snapshot.memory_percent),
            "memory_detail": memory_detail,
            "disk": stat_percent(snapshot.root_disk_percent),
            "disk_detail": disk_detail,
            "load": f"{snapshot.load_1:.2f}" if snapshot.load_1 is not None else "n/a",
            "load_core": f"{snapshot.load_per_core:.2f}" if snapshot.load_per_core is not None else "n/a",
            "load_core_detail": f"{snapshot.cpu_count} core(s)" if snapshot.cpu_count else "",
            "swap": stat_percent(snapshot.swap_percent),
            "swap_detail": swap_detail,
            "network": stat_rate(network_bps),
            "network_detail": network_detail,
            "freshness": state["label"].split(" · ", 1)[0],
            "freshness_detail": f"{missed_reports} missed report(s)" if missed_reports else "On schedule",
            "docker": f"{snapshot.docker_unhealthy_count or 0} bad" if snapshot.docker_total_count is not None else "n/a",
            "docker_detail": docker_detail,
            "uptime": stat_duration(snapshot.uptime_seconds),
        },
    }


def _stats_monitor_payload(db: Session, devices: list[models.Device], window_hours: int) -> dict[str, Any]:
    window_hours = max(1, min(168, int(window_hours or 8)))
    window_end = now_utc()
    window_start = window_end - timedelta(hours=window_hours)
    expected_minutes = _stats_expected_interval_minutes(db)
    overview_metrics = _stats_overview_metric_keys(db)
    latest_stats = _latest_stats_by_device(db, devices)
    reporting_devices = [device for device in devices if device.id in latest_stats]
    histories: dict[int, list[models.DeviceStatSnapshot]] = {device.id: [] for device in reporting_devices}
    if reporting_devices:
        rows = (
            db.query(models.DeviceStatSnapshot)
            .filter(
                models.DeviceStatSnapshot.device_id.in_([device.id for device in reporting_devices]),
                models.DeviceStatSnapshot.created_at >= window_start,
            )
            .order_by(models.DeviceStatSnapshot.created_at.asc())
            .all()
        )
        for row in rows:
            histories.setdefault(row.device_id, []).append(row)
    device_payloads: list[dict[str, Any]] = []
    stale_count = 0
    for device in reporting_devices:
        latest = latest_stats[device.id]
        state = _stats_snapshot_state(latest, expected_minutes=expected_minutes)
        if state.get("state") in {"slow", "bad"}:
            stale_count += 1
        device_payloads.append(
            {
                "id": device.id,
                "name": device.name,
                "href": f"/devices/{device.id}?tab=stats",
                "state": state,
                "latest": _stat_snapshot_payload(latest, expected_minutes=expected_minutes),
                "series": [
                    _stat_snapshot_payload(snapshot, expected_minutes=expected_minutes)
                    for snapshot in histories.get(device.id, [])
                ],
            }
        )
    return {
        "window_hours": window_hours,
        "window_label": f"{window_hours}h",
        "window_start": iso_dt(window_start),
        "window_end": iso_dt(window_end),
        "generated_at": iso_dt(window_end),
        "counts": {
            "reporting": len(reporting_devices),
            "stale": stale_count,
        },
        "overview_metrics": overview_metrics,
        "detail_metrics": STATS_DETAIL_METRICS,
        "devices": device_payloads,
    }


def require_user(request: Request, db: Session = Depends(get_db)) -> models.User:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Login required.")
    timeout_minutes = int(request.session.get("session_timeout_minutes") or int_setting(db, "session_timeout_minutes", 20, minimum=1, maximum=999))
    extended_raw = request.session.get("session_extended_until")
    if extended_raw:
        try:
            if datetime.fromisoformat(extended_raw) > now_utc():
                timeout_minutes *= 3
        except ValueError:
            request.session.pop("session_extended_until", None)
    last_seen_raw = request.session.get("last_seen")
    if last_seen_raw:
        last_seen = datetime.fromisoformat(last_seen_raw)
        if (now_utc() - last_seen).total_seconds() > timeout_minutes * 60:
            request.session.clear()
            raise HTTPException(status_code=401, detail="Session expired.")
    user = db.get(models.User, int(user_id))
    if not user:
        request.session.clear()
        raise HTTPException(status_code=401, detail="Login required.")
    request.session["last_seen"] = now_utc().isoformat()
    return user


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException) -> Response:
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    if exc.status_code == 401:
        flash(request, "Please log in to continue.", "warning")
        return redirect("/login")
    return templates.TemplateResponse(
        request,
        "error.html",
        {
            "status_code": exc.status_code,
            "detail": exc.detail,
            "csrf": csrf_token(request),
            "flashes": pop_flashes(request),
            "user": None,
            "read_only": settings.read_only,
            "instance_mode": settings.instance_mode,
            "instance_name": settings.instance_name,
        },
        status_code=exc.status_code,
    )


def render(
    request: Request,
    template_name: str,
    context: dict[str, Any] | None = None,
    *,
    user: models.User | None = None,
) -> HTMLResponse:
    payload = {
        "csrf": csrf_token(request),
        "flashes": pop_flashes(request),
        "user": user,
        "read_only": settings.read_only,
        "instance_mode": settings.instance_mode,
        "instance_name": settings.instance_name,
        "app_version": settings.app_version,
        "app_version_label": _app_version_label(),
    }
    payload.update(context or {})
    return templates.TemplateResponse(request, template_name, payload)


def _theme_preset_groups(selected_key: str) -> list[dict[str, Any]]:
    selected = selected_key if selected_key in THEME_PRESETS else THEME_DEFAULTS["theme_preset"]
    groups: list[dict[str, Any]] = []
    for label, keys in THEME_PRESET_GROUPS:
        choices = []
        for key in keys:
            preset = THEME_PRESETS[key]
            choices.append(
                {
                    "key": key,
                    "label": preset["label"],
                    "description": preset["description"],
                    "swatches": preset["swatches"],
                    "selected": key == selected,
                }
            )
        groups.append({"label": label, "choices": choices})
    return groups


def _theme_block(selector: str, tokens: dict[str, str], *, dark: bool = False) -> str:
    bg = css_color(tokens.get("bg", ""), THEME_DEFAULTS["dark_bg" if dark else "light_bg"])
    surface = css_color(tokens.get("surface", ""), THEME_DEFAULTS["dark_surface" if dark else "light_surface"])
    ink = css_color(tokens.get("ink", ""), THEME_DEFAULTS["dark_text" if dark else "light_text"])
    muted = css_color(tokens.get("muted", ""), THEME_DEFAULTS["dark_muted" if dark else "light_muted"])
    line = css_color(tokens.get("line", ""), THEME_DEFAULTS["dark_line" if dark else "light_line"])
    accent = css_color(tokens.get("accent", ""), THEME_DEFAULTS["dark_accent" if dark else "light_accent"])
    accent_ink = css_color(
        tokens.get("accent_ink", ""),
        THEME_DEFAULTS["dark_accent_text" if dark else "light_accent_text"],
    )
    surface_soft = "color-mix(in srgb, var(--surface) 78%, #000000)" if dark else "color-mix(in srgb, var(--surface) 92%, var(--bg))"
    accent_dark = tokens.get("accent_dark") or (
        "color-mix(in srgb, var(--accent) 78%, #ffffff)" if dark else "color-mix(in srgb, var(--accent) 78%, #000000)"
    )
    shadow = "none" if dark else "0 8px 24px rgba(23, 33, 43, 0.08)"
    return f"""
{selector} {{
  --bg: {bg};
  --surface: {surface};
  --surface-raised: {surface};
  --surface-soft: {surface_soft};
  --header-bg: {surface};
  --input-bg: {surface};
  --ink: {ink};
  --text: var(--ink);
  --muted: {muted};
  --line: {line};
  --accent: {accent};
  --accent-ink: {accent_ink};
  --accent-text: var(--accent-ink);
  --accent-dark: {accent_dark};
  --accent-strong: var(--accent-dark);
  --blue: {"#60a5fa" if dark else "#2563eb"};
  --amber: {"#f59e0b" if dark else "#b45309"};
  --red: {"#f87171" if dark else "#b91c1c"};
  --green: {"#34d399" if dark else "#047857"};
  --shadow: {shadow};
}}
"""


def _settings_theme_tokens(values: dict[str, str], prefix: str) -> dict[str, str]:
    return {
        "bg": values.get(f"{prefix}_bg", ""),
        "surface": values.get(f"{prefix}_surface", ""),
        "ink": values.get(f"{prefix}_text", ""),
        "muted": values.get(f"{prefix}_muted", ""),
        "line": values.get(f"{prefix}_line", ""),
        "accent": values.get(f"{prefix}_accent", ""),
        "accent_ink": values.get(f"{prefix}_accent_text", ""),
    }


@app.get("/theme.css")
def theme_css(db: Session = Depends(get_db)) -> PlainTextResponse:
    values = get_app_settings(db)
    preset_key = values.get("theme_preset", THEME_DEFAULTS["theme_preset"])
    preset = THEME_PRESETS.get(preset_key, THEME_PRESETS[THEME_DEFAULTS["theme_preset"]])
    light_tokens = _settings_theme_tokens(values, "light")
    dark_tokens = _settings_theme_tokens(values, "dark")
    light_block_is_dark = False
    dark_block_is_dark = True
    if preset_key != "custom":
        light_tokens = dict(preset.get("light") or preset.get("dark") or light_tokens)
        dark_tokens = dict(preset.get("dark") or preset.get("light") or dark_tokens)
        light_block_is_dark = "dark" in preset and "light" not in preset
        dark_block_is_dark = "dark" in preset
    css = _theme_block(":root:not([data-theme])", light_tokens, dark=light_block_is_dark)
    css += f"""
@media (prefers-color-scheme: dark) {{
  {_theme_block(":root:not([data-theme])", dark_tokens, dark=dark_block_is_dark)}
}}
"""
    css += _theme_block(':root[data-theme="light"]', light_tokens, dark=light_block_is_dark)
    css += _theme_block(':root[data-theme="dark"]', dark_tokens, dark=dark_block_is_dark)
    if values.get("compact_forms", "on") != "off":
        css += """
.panel { padding: 16px; }
.form-grid { gap: 10px 12px; }
label { gap: 4px; }
textarea { min-height: 76px; }
textarea.paste-box { min-height: 240px; }
.page-head { margin-bottom: 14px; }
"""
    return PlainTextResponse(css, media_type="text/css")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {
        "status": "ok",
        "app": settings.app_name,
        "version": settings.app_version,
        "build": settings.app_build,
        "iteration": settings.app_build_iteration,
        "revision": settings.app_revision[:12],
    }


@app.post("/api/agent/stats")
async def agent_stats_ingest(request: Request, db: Session = Depends(get_db)) -> JSONResponse:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > AGENT_PAYLOAD_MAX_BYTES:
                raise HTTPException(413, "Stats payload is too large.")
        except ValueError:
            raise HTTPException(400, "Invalid Content-Length header.") from None
    _require_agent_token(request)
    try:
        payload = await request.json()
    except ValueError:
        raise HTTPException(400, "Stats payload must be JSON.") from None
    if not isinstance(payload, dict):
        raise HTTPException(400, "Stats payload must be a JSON object.")
    device = _match_agent_device(db, payload)
    if not device:
        device = _create_agent_device(db, payload)
    _apply_agent_device_metadata(db, device, payload)
    cpu = payload.get("cpu") if isinstance(payload.get("cpu"), dict) else {}
    memory = payload.get("memory") if isinstance(payload.get("memory"), dict) else {}
    network = payload.get("network") if isinstance(payload.get("network"), dict) else {}
    docker = payload.get("docker") if isinstance(payload.get("docker"), dict) else {}
    load_average = cpu.get("load_average") if isinstance(cpu.get("load_average"), list) else []
    root_disk = _agent_root_disk(payload.get("disks"))
    observed_at = _parse_agent_datetime(payload.get("observed_at"))
    previous = (
        db.query(models.DeviceStatSnapshot)
        .filter(models.DeviceStatSnapshot.device_id == device.id)
        .order_by(models.DeviceStatSnapshot.observed_at.desc(), models.DeviceStatSnapshot.created_at.desc())
        .first()
    )
    cpu_count = _agent_int(cpu.get("count"))
    load_1 = _agent_float(load_average[0] if len(load_average) > 0 else None)
    load_5 = _agent_float(load_average[1] if len(load_average) > 1 else None)
    load_15 = _agent_float(load_average[2] if len(load_average) > 2 else None)
    load_per_core = round(load_1 / cpu_count, 2) if load_1 is not None and cpu_count and cpu_count > 0 else None
    network_rx_bytes = _agent_int(network.get("rx_bytes") if network else None)
    network_tx_bytes = _agent_int(network.get("tx_bytes") if network else None)
    elapsed = None
    if previous:
        elapsed = max(0.0, (observed_at - _utc(previous.observed_at)).total_seconds())
    candidate = models.DeviceStatSnapshot(
        device_id=device.id,
        source=_agent_string(payload.get("source") or "agent", 80),
        agent_version=_agent_string(payload.get("agent_version"), 80),
        hostname=_agent_string(payload.get("hostname") or payload.get("device_name"), 180),
        primary_ip=_agent_string(payload.get("primary_ip"), 80),
        os_name=_agent_string(payload.get("os_name") or payload.get("platform"), 180),
        cpu_percent=_agent_percent(cpu.get("percent") if cpu else payload.get("cpu_percent")),
        cpu_count=cpu_count,
        memory_percent=_agent_percent(memory.get("percent") if memory else payload.get("memory_percent")),
        memory_used_bytes=_agent_int(memory.get("used_bytes") if memory else payload.get("memory_used_bytes")),
        memory_total_bytes=_agent_int(memory.get("total_bytes") if memory else payload.get("memory_total_bytes")),
        swap_percent=_agent_percent(memory.get("swap_percent") if memory else payload.get("swap_percent")),
        swap_used_bytes=_agent_int(memory.get("swap_used_bytes") if memory else payload.get("swap_used_bytes")),
        swap_total_bytes=_agent_int(memory.get("swap_total_bytes") if memory else payload.get("swap_total_bytes")),
        root_disk_percent=_agent_percent(root_disk.get("percent")),
        root_disk_used_bytes=_agent_int(root_disk.get("used_bytes")),
        root_disk_total_bytes=_agent_int(root_disk.get("total_bytes")),
        uptime_seconds=_agent_float(payload.get("uptime_seconds")),
        load_1=load_1,
        load_5=load_5,
        load_15=load_15,
        load_per_core=load_per_core,
        network_rx_bytes=network_rx_bytes,
        network_tx_bytes=network_tx_bytes,
        network_rx_bps=_agent_rate_per_second(
            network_rx_bytes,
            previous.network_rx_bytes if previous else None,
            elapsed,
        ),
        network_tx_bps=_agent_rate_per_second(
            network_tx_bytes,
            previous.network_tx_bytes if previous else None,
            elapsed,
        ),
        docker_running_count=_agent_int(docker.get("running") if docker else None),
        docker_stopped_count=_agent_int(docker.get("stopped") if docker else None),
        docker_unhealthy_count=_agent_int(docker.get("unhealthy") if docker else None),
        docker_total_count=_agent_int(docker.get("total") if docker else None),
        observed_at=observed_at,
        payload_json=payload,
    )
    reuse_previous = _stats_snapshot_can_coalesce(
        previous,
        observed_at,
        now_utc(),
        _stats_storage_interval_minutes(db),
    )
    if reuse_previous:
        snapshot = previous
        for column in models.DeviceStatSnapshot.__table__.columns:
            if column.name in {"id", "created_at"}:
                continue
            setattr(snapshot, column.name, getattr(candidate, column.name))
    else:
        snapshot = candidate
    db.add(snapshot)
    _maybe_prune_stats(db)
    db.commit()
    db.refresh(snapshot)
    return JSONResponse({"status": "ok", "device_id": device.id, "snapshot_id": snapshot.id})


@app.get("/api/stats")
def stats_live_api(
    device_id: int | None = None,
    hours: int | None = None,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    window_hours = max(1, min(168, int(hours or _stats_window_hours(db))))
    if device_id:
        device = db.get(models.Device, device_id)
        if not device:
            raise HTTPException(404, "Device not found.")
        devices = [device]
    else:
        devices = _device_order_query(db).all()
    return JSONResponse(_stats_monitor_payload(db, devices, window_hours))


@app.post("/devices/{device_id}/stats/clear")
async def device_stats_clear(
    device_id: int,
    request: Request,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    form = await request.form()
    check_csrf(request, str(form.get("csrf", "")))
    ensure_writable()
    device = db.get(models.Device, device_id)
    if not device:
        raise HTTPException(404, "Device not found.")
    deleted = (
        db.query(models.DeviceStatSnapshot)
        .filter(models.DeviceStatSnapshot.device_id == device.id)
        .delete(synchronize_session=False)
    )
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="device_stats_cleared",
            object_type="device",
            object_id=device.id,
            details_json={"deleted": deleted},
        )
    )
    db.commit()
    flash(request, f"Cleared {deleted} stats snapshot(s) for {device.name}.", "success")
    return redirect(f"/devices/{device.id}?tab=stats")


@app.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    if user_count(db) > 0:
        return redirect("/login")
    return render(request, "setup.html")


@app.post("/setup")
def setup_owner(
    request: Request,
    csrf: str = Form(...),
    username: str = Form(...),
    display_name: str = Form(""),
    password: str = Form(...),
    secondary_password: str = Form(""),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    if user_count(db) > 0:
        return redirect("/login")
    if len(password) < 10:
        flash(request, "Use at least 10 characters for the owner password.", "warning")
        return redirect("/setup")
    user = models.User(
        username=username.strip().lower(),
        display_name=display_name.strip() or username.strip(),
        password_hash=hash_password(password),
        secondary_password_hash=hash_password(secondary_password)
        if secondary_password.strip()
        else None,
        role="owner",
    )
    db.add(user)
    db.commit()
    flash(request, "Owner account created. You can log in now.", "success")
    return redirect("/login")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    if user_count(db) == 0:
        return redirect("/setup")
    return render(
        request,
        "login.html",
        {"failed_ping_summary": _failed_ping_summary(db), "recovery_enabled": _recovery_enabled(db)},
    )


@app.post("/login")
def login(
    request: Request,
    csrf: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    login_key = _rate_limit_key(request, "login", username)
    if _rate_limited(login_key):
        flash(request, "Too many failed login attempts. Try again in a few minutes.", "danger")
        return redirect("/login")
    locked_raw = request.session.get("login_locked_until")
    if locked_raw:
        try:
            locked_until = datetime.fromisoformat(locked_raw)
            if locked_until > now_utc():
                flash(request, "Too many failed login attempts. Try again in a few minutes.", "danger")
                return redirect("/login")
        except ValueError:
            request.session.pop("login_locked_until", None)
    user = db.query(models.User).filter_by(username=username.strip().lower()).first()
    if not user or not verify_password(password, user.password_hash):
        failures = int(request.session.get("login_failures") or 0) + 1
        request.session["login_failures"] = failures
        if failures >= 5:
            request.session["login_failures"] = 0
            request.session["login_locked_until"] = (now_utc() + timedelta(minutes=5)).isoformat()
            flash(request, "Too many failed login attempts. This browser is paused for 5 minutes.", "danger")
            return redirect("/login")
        if _record_rate_failure(login_key):
            flash(request, "Too many failed login attempts. Try again in a few minutes.", "danger")
            return redirect("/login")
        flash(request, "Login failed. Check the username and password.", "danger")
        return redirect("/login")
    _clear_rate_limit(login_key)
    upgraded = _upgrade_hash_if_needed(db, user, password)
    if upgraded:
        db.commit()
    request.session.clear()
    if user.totp_enabled and _totp_login_enabled(db):
        request.session["pending_2fa_user_id"] = user.id
        request.session["last_seen"] = now_utc().isoformat()
        csrf_token(request)
        return redirect("/login/2fa")
    request.session["user_id"] = user.id
    request.session["last_seen"] = now_utc().isoformat()
    request.session["session_timeout_minutes"] = int_setting(db, "session_timeout_minutes", 20, minimum=1, maximum=999)
    csrf_token(request)
    _start_login_checks(user.id)
    flash(request, f"Welcome back, {user.display_name or user.username}.", "success")
    return redirect("/")


@app.get("/login/2fa", response_class=HTMLResponse)
def login_2fa_page(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    pending_id = request.session.get("pending_2fa_user_id")
    if not pending_id:
        return redirect("/login")
    user = db.get(models.User, int(pending_id))
    if not user:
        request.session.clear()
        return redirect("/login")
    return render(request, "login_2fa.html", {"pending_username": user.username})


@app.post("/login/2fa")
def login_2fa(
    request: Request,
    csrf: str = Form(...),
    code: str = Form(...),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    pending_id = request.session.get("pending_2fa_user_id")
    if not pending_id:
        return redirect("/login")
    user = db.get(models.User, int(pending_id))
    if not user or not user.totp_secret_encrypted:
        request.session.clear()
        return redirect("/login")
    totp_key = _rate_limit_key(request, "login-2fa", str(user.id))
    if _rate_limited(totp_key):
        flash(request, "Too many 2FA attempts. Try again in a few minutes.", "danger")
        return redirect("/login/2fa")
    if not _verify_totp_code(user, code):
        if _record_rate_failure(totp_key, max_failures=6):
            flash(request, "Too many 2FA attempts. Try again in a few minutes.", "danger")
            return redirect("/login/2fa")
        flash(request, "Incorrect 2FA code.", "danger")
        return redirect("/login/2fa")
    _clear_rate_limit(totp_key)
    request.session.clear()
    request.session["user_id"] = user.id
    request.session["last_seen"] = now_utc().isoformat()
    request.session["session_timeout_minutes"] = int_setting(db, "session_timeout_minutes", 20, minimum=1, maximum=999)
    csrf_token(request)
    _start_login_checks(user.id)
    flash(request, f"Welcome back, {user.display_name or user.username}.", "success")
    return redirect("/")


@app.get("/recover", response_class=HTMLResponse)
def recovery_page(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    if user_count(db) == 0:
        return redirect("/setup")
    return render(request, "recover.html", {"recovery_enabled": _recovery_enabled(db)})


@app.post("/recover")
def recovery_start(
    request: Request,
    csrf: str = Form(...),
    recovery_phrase: str = Form(...),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    recovery_hash = _recovery_phrase_hash(db)
    if not recovery_hash:
        flash(request, "Recovery phrase is not configured yet.", "warning")
        return redirect("/login")
    recovery_key = _rate_limit_key(request, "recovery", "phrase")
    if _rate_limited(recovery_key):
        flash(request, "Too many recovery attempts. Try again in a few minutes.", "danger")
        return redirect("/recover")
    locked_raw = request.session.get("recovery_locked_until")
    if locked_raw:
        try:
            if datetime.fromisoformat(locked_raw) > now_utc():
                flash(request, "Too many recovery attempts. Try again in a few minutes.", "danger")
                return redirect("/recover")
        except ValueError:
            request.session.pop("recovery_locked_until", None)
    if not verify_password(recovery_phrase.strip(), recovery_hash):
        failures = int(request.session.get("recovery_failures") or 0) + 1
        request.session["recovery_failures"] = failures
        if failures >= 5:
            request.session["recovery_failures"] = 0
            request.session["recovery_locked_until"] = (now_utc() + timedelta(minutes=5)).isoformat()
        _record_rate_failure(recovery_key, max_failures=5)
        flash(request, "Recovery phrase was not accepted.", "danger")
        return redirect("/recover")
    _clear_rate_limit(recovery_key)
    if password_hash_needs_upgrade(recovery_hash):
        set_app_setting(db, RECOVERY_PHRASE_HASH_SETTING, hash_password(recovery_phrase.strip()))
        db.commit()
    expected, options = _recovery_challenge_options(db)
    if not expected or not options:
        flash(request, "Recovery challenge needs at least six saved services. Log in normally and add more service records first.", "warning")
        return redirect("/login")
    request.session.clear()
    request.session["recovery_expected_service_ids"] = expected
    request.session["recovery_options"] = options
    request.session["last_seen"] = now_utc().isoformat()
    csrf_token(request)
    return redirect("/recover/challenge")


@app.get("/recover/challenge", response_class=HTMLResponse)
def recovery_challenge_page(request: Request) -> HTMLResponse:
    options = request.session.get("recovery_options")
    expected = request.session.get("recovery_expected_service_ids")
    if not options or not expected:
        return redirect("/recover")
    return render(request, "recover_challenge.html", {"options": options})


@app.post("/recover/challenge")
async def recovery_challenge_verify(
    request: Request,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    form = await request.form()
    check_csrf(request, str(form.get("csrf", "")))
    expected = {int(value) for value in request.session.get("recovery_expected_service_ids", [])}
    selected: set[int] = set()
    for raw in form.getlist("service_id"):
        value = str(raw)
        if value.isdigit():
            selected.add(int(value))
    if not expected or selected != expected:
        request.session.pop("recovery_expected_service_ids", None)
        request.session.pop("recovery_options", None)
        flash(request, "Service recognition challenge did not match.", "danger")
        return redirect("/recover")
    user = db.query(models.User).order_by(models.User.id).first()
    if not user:
        request.session.clear()
        return redirect("/setup")
    request.session.clear()
    request.session["user_id"] = user.id
    request.session["last_seen"] = now_utc().isoformat()
    request.session["session_timeout_minutes"] = int_setting(db, "session_timeout_minutes", 20, minimum=1, maximum=999)
    csrf_token(request)
    _start_login_checks(user.id)
    db.add(models.AuditLog(user_id=user.id, action="recovery_login", object_type="user", object_id=user.id))
    db.commit()
    flash(request, "Recovery verified. Update your password or 2FA settings now.", "success")
    return redirect("/settings#account-security")


@app.post("/logout")
def logout(request: Request, csrf: str = Form(...)) -> RedirectResponse:
    check_csrf(request, csrf)
    request.session.clear()
    return redirect("/login")


@app.post("/session/keepalive")
async def session_keepalive(
    request: Request,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    check_csrf(request, request.headers.get("x-csrf-token", ""))
    payload = await request.json()
    timeout = int_setting(db, "session_timeout_minutes", 20, minimum=1, maximum=999)
    request.session["session_timeout_minutes"] = timeout
    request.session["last_seen"] = now_utc().isoformat()
    if payload.get("extend"):
        request.session["session_extended_until"] = (now_utc() + timedelta(minutes=timeout * 3)).isoformat()
    return JSONResponse({"ok": True, "timeout_minutes": timeout})


@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    recent_limit = int_setting(db, "dashboard_recent_limit", 6, minimum=3, maximum=20)
    devices = _device_order_query(db).limit(recent_limit).all()
    services = _service_order_query(db).limit(recent_limit).all()
    recent_logs = db.query(models.AuditLog).order_by(models.AuditLog.created_at.desc()).limit(8).all()
    active_suggestions = visible_suggestions(db)
    suggestions = active_suggestions[:6]
    return render(
        request,
        "dashboard.html",
        {
            "devices": devices,
            "services": services,
            "service_statuses": {service.id: _service_validation_status(db, service) for service in services},
            "device_ping_statuses": _device_ping_status_map(
                db,
                list(devices) + [service.device for service in services],
            ),
            "recent_logs": recent_logs,
            "suggestions": suggestions,
            "suggestion_count": len(active_suggestions),
            "ping_overview": _dashboard_ping_overview(db),
            "counts": {
                "devices": db.query(models.Device).count(),
                "services": db.query(models.Service).count(),
                "credentials": db.query(models.Credential).count(),
                "commands": db.query(models.Command).count(),
            },
        },
        user=user,
    )


@app.get("/stats", response_class=HTMLResponse)
def stats_page(
    request: Request,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    all_devices = _device_order_query(db).all()
    latest_stats = _latest_stats_by_device(db, all_devices)
    devices = [device for device in all_devices if device.id in latest_stats]
    expected_minutes = _stats_expected_interval_minutes(db)
    stale = [
        device
        for device in devices
        if _stats_snapshot_state(latest_stats.get(device.id), expected_minutes=expected_minutes).get("state") in {"slow", "bad"}
    ]
    window_hours = _stats_window_hours(db)
    overview_metric_keys = _stats_overview_metric_keys(db)
    return render(
        request,
        "stats.html",
        {
            "devices": devices,
            "latest_stats": latest_stats,
            "stats_states": {
                device.id: _stats_snapshot_state(latest_stats.get(device.id), expected_minutes=expected_minutes)
                for device in devices
            },
            "counts": {
                "devices": len(devices),
                "reporting": len(devices),
                "stale": len(stale),
            },
            "stats_window_hours": window_hours,
            "stats_window_label": f"{window_hours}h",
            "stats_overview_metric_keys": overview_metric_keys,
        },
        user=user,
    )


@app.get("/devices", response_class=HTMLResponse)
def devices_page(
    request: Request,
    q: str = "",
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    query = db.query(models.Device)
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                models.Device.name.ilike(like),
                models.Device.primary_ip.ilike(like),
                models.Device.hostname.ilike(like),
                models.Device.purpose.ilike(like),
                models.Device.notes.ilike(like),
            )
        )
    devices = query.order_by(models.Device.display_order, models.Device.name).all()
    service_counts = {
        device_id: count
        for device_id, count in db.query(
            models.Service.device_id, func.count(models.Service.id)
        )
        .group_by(models.Service.device_id)
        .all()
    }
    credential_counts = {
        device_id: count
        for device_id, count in db.query(
            models.Credential.device_id, func.count(models.Credential.id)
        )
        .group_by(models.Credential.device_id)
        .all()
    }
    command_counts = {
        device_id: count
        for device_id, count in db.query(
            models.Command.applies_to_id, func.count(models.Command.id)
        )
        .filter(models.Command.applies_to_type == "device")
        .group_by(models.Command.applies_to_id)
        .all()
    }
    return render(
        request,
        "devices.html",
        {
            "devices": devices,
            "q": q,
            "tags": tag_map(db, "device"),
            "service_counts": service_counts,
            "credential_counts": credential_counts,
            "command_counts": command_counts,
            "ping_statuses": {device.id: _device_ping_status(db, device) for device in devices},
            "device_ping_statuses": _device_ping_status_map(db, list(devices)),
        },
        user=user,
    )


@app.get("/devices/new", response_class=HTMLResponse)
def device_new_page(
    request: Request,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    return render(request, "device_form.html", {"device": None, "hardware": None, "tag_text": ""}, user=user)


@app.post("/devices/new")
def device_create(
    request: Request,
    csrf: str = Form(...),
    name: str = Form(...),
    type: str = Form("server"),
    purpose: str = Form(""),
    hostname: str = Form(""),
    primary_ip: str = Form(""),
    os_name: str = Form(""),
    os_version: str = Form(""),
    location: str = Form(""),
    status_manual: str = Form(""),
    notes: str = Form(""),
    hw_model: str = Form(""),
    hw_cpu: str = Form(""),
    hw_ram: str = Form(""),
    hw_gpu: str = Form(""),
    hw_storage: str = Form(""),
    tags: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    device = models.Device(
        name=name.strip(),
        slug=unique_slug(db, models.Device, name),
        type=type.strip() or "server",
        purpose=purpose,
        hostname=hostname,
        primary_ip=primary_ip,
        os_name=os_name,
        os_version=os_version,
        location=location,
        status_manual=status_manual,
        display_order=_next_device_order(db),
        notes=notes,
    )
    db.add(device)
    db.flush()
    hardware = _ensure_device_hardware(db, device)
    hardware.model = hw_model
    hardware.cpu = hw_cpu
    hardware.ram = hw_ram
    hardware.gpu = hw_gpu
    hardware.storage_summary = hw_storage
    set_tags(db, "device", device.id, tags)
    merge_tags(db, "device", device.id, _infer_tags_for_device(device))
    db.add(models.AuditLog(user_id=user.id, action="device_created", object_type="device", object_id=device.id))
    db.commit()
    flash(request, f"Device {device.name} created.", "success")
    return redirect(f"/devices/{device.id}")


@app.get("/devices/{device_id}", response_class=HTMLResponse)
def device_detail(
    request: Request,
    device_id: int,
    tab: str = "overview",
    favorites: str = "",
    highlight: str = "",
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    device = db.get(models.Device, device_id)
    if not device:
        raise HTTPException(404, "Device not found.")
    commands, command_contexts = _commands_for_device(db, device)
    notes = (
        db.query(models.Note)
        .filter(models.Note.object_type == "device", models.Note.object_id == device.id)
        .order_by(models.Note.updated_at.desc())
        .all()
    )
    images = (
        db.query(models.DeviceImage)
        .filter(models.DeviceImage.device_id == device.id)
        .order_by(models.DeviceImage.created_at.desc())
        .all()
    )
    stat_snapshots = (
        db.query(models.DeviceStatSnapshot)
        .filter(models.DeviceStatSnapshot.device_id == device.id)
        .order_by(models.DeviceStatSnapshot.created_at.desc())
        .limit(24)
        .all()
    )
    stats_window_hours = _stats_window_hours(db)
    stats_expected_minutes = _stats_expected_interval_minutes(db)
    grouped_services: dict[str, list[models.Service]] = {}
    for service in sorted(device.services, key=lambda item: (item.docker_project or "Ungrouped", item.name.lower())):
        grouped_services.setdefault(service.docker_project or "Ungrouped", []).append(service)
    service_groups = [
        {"name": name, "services": services}
        for name, services in grouped_services.items()
    ]
    auto_purpose = _device_auto_purpose(device)
    validation_status = {service.id: _service_validation_status(db, service) for service in device.services}
    quick_network_limit = int_setting(db, "dashboard_recent_limit", 6, minimum=3, maximum=20)
    quick_network_items: list[dict[str, str]] = []
    for service in sorted(device.services, key=lambda item: item.name.lower()):
        service_url = service.local_url or service.public_url
        if service_url:
            quick_network_items.append(
                {
                    "title": service.name,
                    "subtitle": service_url,
                    "href": service_url,
                    "external": "true",
                }
            )
        for port in sorted(service.ports, key=lambda item: (item.host_port, item.protocol)):
            open_url = port_open_url(port)
            quick_network_items.append(
                {
                    "title": service.name,
                    "subtitle": f"{port.host_port}/{port.protocol} · {port.purpose or 'service port'}",
                    "href": open_url or f"/ports/{port.id}/edit?return_to=/devices/{device.id}",
                    "external": "true" if open_url else "",
                }
            )
    for port in sorted((port for port in device.ports if not port.service), key=lambda item: (item.host_port, item.protocol)):
        open_url = port_open_url(port)
        quick_network_items.append(
            {
                "title": f"{port.host_port}/{port.protocol}",
                "subtitle": port.purpose or port.notes or "device port",
                "href": open_url or f"/ports/{port.id}/edit?return_to=/devices/{device.id}",
                "external": "true" if open_url else "",
            }
        )
    return render(
        request,
        "device_detail.html",
        {
            "device": device,
            "tab": tab,
            "commands": commands,
            "command_contexts": command_contexts,
            "history": _device_history(db, device),
            "notes": notes,
            "images": images,
            "stat_snapshots": stat_snapshots,
            "latest_stats": stat_snapshots[0] if stat_snapshots else None,
            "stats_state": _stats_snapshot_state(
                stat_snapshots[0] if stat_snapshots else None,
                expected_minutes=stats_expected_minutes,
            ),
            "agent_enabled": bool(settings.agent_ingest_token.strip()) and not settings.read_only,
            "stats_window_hours": stats_window_hours,
            "stats_window_label": f"{stats_window_hours}h",
            "stats_detail_metric_keys": STATS_DETAIL_METRICS,
            "image_tags": tag_map(db, "device_image"),
            "tag_list": tags_for(db, "device", device.id),
            "service_groups": service_groups,
            "quick_credentials": _quick_credentials_for_device(db, device),
            "favorite_ids": _favorite_credential_ids_for_device(db, device.id),
            "favorite_edit": favorites == "edit",
            "ping_status": _device_ping_status(db, device),
            "status_log": _latest_audit(db, "device", device.id, "device_status_changed"),
            "validation_status": validation_status,
            "port_validation_statuses": _port_validation_status_map(db, list(device.ports)),
            "validation_log": _latest_audit(db, "device", device.id, "services_validated"),
            "auto_purpose": auto_purpose,
            "quick_network_items": quick_network_items[:quick_network_limit],
            "quick_network_total": len(quick_network_items),
            "quick_network_limit": quick_network_limit,
            "highlight": highlight,
            "device_ping_statuses": _device_ping_status_map(db, [device]),
        },
        user=user,
    )


@app.post("/devices/{device_id}/ping")
def device_ping_now(
    request: Request,
    device_id: int,
    csrf: str = Form(...),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    device = db.get(models.Device, device_id)
    if not device:
        raise HTTPException(404, "Device not found.")
    result = _ping_device(db, device)
    db.commit()
    flash(request, f"Ping checked: {'reply received' if result.get('ok') else 'no reply'}.", "success" if result.get("ok") else "warning")
    return redirect(request.headers.get("referer") or f"/devices/{device.id}")


@app.get("/device-images/{image_id}/file")
def device_image_file(
    image_id: int,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> FileResponse:
    image = db.get(models.DeviceImage, image_id)
    if not image:
        raise HTTPException(404, "Image not found.")
    path = _stored_upload_path(DEVICE_IMAGE_DIR, image.stored_filename)
    if not path.exists() or not path.is_file():
        raise HTTPException(404, "Image file not found.")
    return FileResponse(path, media_type=image.mime_type or "application/octet-stream")


@app.post("/devices/{device_id}/images")
async def device_image_create(
    request: Request,
    device_id: int,
    csrf: str = Form(...),
    name: str = Form(""),
    image_date: str = Form(""),
    tags: str = Form(""),
    notes: str = Form(""),
    ocr_text: str = Form(""),
    image_file: UploadFile = File(...),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    device = db.get(models.Device, device_id)
    if not device:
        raise HTTPException(404, "Device not found.")
    try:
        saved = await _save_image_upload(image_file, DEVICE_IMAGE_DIR)
    except ValueError as exc:
        flash(request, str(exc), "warning")
        return redirect(f"/devices/{device.id}?tab=images")
    title = name.strip() or Path(saved["original_filename"]).stem or "Device image"
    image_path = _stored_upload_path(DEVICE_IMAGE_DIR, saved["stored_filename"])
    extracted_text, ocr_error = _extract_ocr_text(image_path)
    final_ocr_text = ocr_text.strip() or extracted_text
    record = models.DeviceImage(
        device_id=device.id,
        name=title,
        image_date=_parse_optional_datetime(image_date),
        notes=notes,
        ocr_text=final_ocr_text,
        **saved,
    )
    db.add(record)
    db.flush()
    set_tags(db, "device_image", record.id, tags)
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="device_image_added",
            object_type="device_image",
            object_id=record.id,
            details_json={
                "device_id": device.id,
                "filename": saved["original_filename"],
                "ocr": "manual" if ocr_text.strip() else "auto" if extracted_text else "none",
                "ocr_error": ocr_error,
            },
        )
    )
    db.commit()
    if final_ocr_text:
        flash(request, "Image saved and OCR text extracted.", "success")
    elif ocr_error:
        flash(request, f"Image saved. {ocr_error}", "warning")
    else:
        flash(request, "Image saved to this device.", "success")
    return redirect(f"/devices/{device.id}?tab=images")


@app.post("/device-images/{image_id}/edit")
def device_image_update(
    request: Request,
    image_id: int,
    csrf: str = Form(...),
    name: str = Form(""),
    image_date: str = Form(""),
    tags: str = Form(""),
    notes: str = Form(""),
    ocr_text: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    image = db.get(models.DeviceImage, image_id)
    if not image:
        raise HTTPException(404, "Image not found.")
    image.name = name.strip() or Path(image.original_filename).stem or "Device image"
    image.image_date = _parse_optional_datetime(image_date)
    image.notes = notes
    image.ocr_text = ocr_text
    set_tags(db, "device_image", image.id, tags)
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="device_image_edited",
            object_type="device_image",
            object_id=image.id,
        )
    )
    db.commit()
    flash(request, "Image details saved.", "success")
    return redirect(f"/devices/{image.device_id}?tab=images")


@app.post("/device-images/{image_id}/ocr")
def device_image_ocr(
    request: Request,
    image_id: int,
    csrf: str = Form(...),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    image = db.get(models.DeviceImage, image_id)
    if not image:
        raise HTTPException(404, "Image not found.")
    path = _stored_upload_path(DEVICE_IMAGE_DIR, image.stored_filename)
    if not path.exists() or not path.is_file():
        flash(request, "The image file is missing, so OCR could not run.", "warning")
        return redirect(f"/devices/{image.device_id}?tab=images")
    extracted_text, ocr_error = _extract_ocr_text(path)
    if extracted_text:
        image.ocr_text = extracted_text
        db.add(
            models.AuditLog(
                user_id=user.id,
                action="device_image_ocr",
                object_type="device_image",
                object_id=image.id,
                details_json={"device_id": image.device_id},
            )
        )
        db.commit()
        flash(request, "OCR text updated.", "success")
    else:
        flash(request, ocr_error or "OCR did not find readable text.", "warning")
    return redirect(f"/devices/{image.device_id}?tab=images")


@app.post("/device-images/{image_id}/delete")
def device_image_delete(
    request: Request,
    image_id: int,
    csrf: str = Form(...),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    image = db.get(models.DeviceImage, image_id)
    if not image:
        raise HTTPException(404, "Image not found.")
    device_id = image.device_id
    path = _stored_upload_path(DEVICE_IMAGE_DIR, image.stored_filename)
    db.query(models.TagLink).filter_by(object_type="device_image", object_id=image.id).delete()
    db.delete(image)
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="device_image_deleted",
            object_type="device_image",
            object_id=image_id,
            details_json={"device_id": device_id},
        )
    )
    db.commit()
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
    flash(request, "Image deleted.", "success")
    return redirect(f"/devices/{device_id}?tab=images")


@app.post("/devices/{device_id}/validate-services")
def device_validate_services(
    request: Request,
    device_id: int,
    csrf: str = Form(...),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    device = db.get(models.Device, device_id)
    if not device:
        raise HTTPException(404, "Device not found.")
    checked = 0
    reachable = 0
    transitions: list[tuple[models.Service, dict[str, Any], bool | None]] = []
    for service in device.services:
        previous_good = _latest_service_validation_good(db, service)
        details = _validate_service(db, service, user.id)
        transitions.append((service, details, previous_good))
        if details["checked"]:
            checked += 1
        if details["ok"] or details.get("partial"):
            reachable += 1
    _notify_service_validation_webhooks(db, transitions)
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="services_validated",
            object_type="device",
            object_id=device.id,
            details_json={"checked": checked, "reachable": reachable},
        )
    )
    db.commit()
    flash(request, f"Validated {checked} service(s); {reachable} reachable.", "success")
    return redirect(request.headers.get("referer") or f"/devices/{device.id}")


@app.post("/devices/{device_id}/quick-credentials")
def device_quick_credentials_update(
    request: Request,
    device_id: int,
    csrf: str = Form(...),
    credential_id: int = Form(...),
    action: str = Form("show"),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> Response:
    check_csrf(request, csrf)
    ensure_writable()
    device = db.get(models.Device, device_id)
    credential = db.get(models.Credential, credential_id)
    context_device = _credential_context_device(credential) if credential else None
    if not device or not credential or not context_device or context_device.id != device.id or credential.secret_type == "API token":
        raise HTTPException(404, "Credential not found on this device.")
    order_key = f"quick_credential_order:{device.id}"
    hidden_key = f"quick_credential_hidden:{device.id}"
    current = _id_list(get_app_settings(db).get(order_key, ""))
    if action == "show" and credential.id not in current:
        current.append(credential.id)
    if credential.id not in current:
        current.append(credential.id)
    index = current.index(credential.id)
    if action == "up" and index > 0:
        current[index - 1], current[index] = current[index], current[index - 1]
    elif action == "down" and index < len(current) - 1:
        current[index + 1], current[index] = current[index], current[index + 1]
    elif action == "hide":
        hidden = set(_id_list(get_app_settings(db).get(hidden_key, "")))
        hidden.add(credential.id)
        current = [item for item in current if item != credential.id]
        set_app_setting(db, hidden_key, ",".join(str(item) for item in sorted(hidden)))
    elif action == "show":
        hidden = set(_id_list(get_app_settings(db).get(hidden_key, "")))
        hidden.discard(credential.id)
        set_app_setting(db, hidden_key, ",".join(str(item) for item in sorted(hidden)))
    set_app_setting(db, order_key, ",".join(str(item) for item in current))
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="quick_credentials_updated",
            object_type="device",
            object_id=device.id,
            details_json={"credential_id": credential.id, "action": action},
        )
    )
    db.commit()
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse(
            {
                "ok": True,
                "device_id": device.id,
                "credential_id": credential.id,
                "favorite": action == "show",
            }
        )
    return redirect(request.headers.get("referer") or f"/devices/{device.id}")


@app.get("/devices/{device_id}/edit", response_class=HTMLResponse)
def device_edit_page(
    request: Request,
    device_id: int,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    device = db.get(models.Device, device_id)
    if not device:
        raise HTTPException(404, "Device not found.")
    return render(
        request,
        "device_form.html",
        {
            "device": device,
            "hardware": device.hardware,
            "tag_text": ", ".join(tags_for(db, "device", device.id)),
            "auto_purpose": _device_auto_purpose(device),
        },
        user=user,
    )


@app.post("/devices/{device_id}/edit")
def device_update(
    request: Request,
    device_id: int,
    csrf: str = Form(...),
    name: str = Form(...),
    type: str = Form("server"),
    purpose: str = Form(""),
    hostname: str = Form(""),
    primary_ip: str = Form(""),
    os_name: str = Form(""),
    os_version: str = Form(""),
    location: str = Form(""),
    status_manual: str = Form(""),
    notes: str = Form(""),
    hw_model: str = Form(""),
    hw_cpu: str = Form(""),
    hw_ram: str = Form(""),
    hw_gpu: str = Form(""),
    hw_storage: str = Form(""),
    tags: str = Form(""),
    update_linked_ip_refs: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    device = db.get(models.Device, device_id)
    if not device:
        raise HTTPException(404, "Device not found.")
    old_primary_ip = (device.primary_ip or "").strip()
    new_primary_ip = primary_ip.strip()
    device.name = name.strip()
    device.slug = unique_slug(db, models.Device, name, existing_id=device.id)
    device.type = type
    device.purpose = purpose
    device.hostname = hostname
    device.primary_ip = new_primary_ip
    device.os_name = os_name
    device.os_version = os_version
    device.location = location
    old_status = device.status_manual or ""
    device.status_manual = status_manual
    device.notes = notes
    hardware = _ensure_device_hardware(db, device)
    hardware.model = hw_model
    hardware.cpu = hw_cpu
    hardware.ram = hw_ram
    hardware.gpu = hw_gpu
    hardware.storage_summary = hw_storage
    set_tags(db, "device", device.id, tags)
    ip_reference_counts = {"services": 0, "urls": 0, "credentials": 0}
    if update_linked_ip_refs == "on":
        ip_reference_counts = _replace_device_ip_references(device, old_primary_ip, new_primary_ip)
        if sum(ip_reference_counts.values()):
            db.add(
                models.AuditLog(
                    user_id=user.id,
                    action="device_ip_references_updated",
                    object_type="device",
                    object_id=device.id,
                    details_json={
                        "old_ip": old_primary_ip,
                        "new_ip": new_primary_ip,
                        "counts": ip_reference_counts,
                    },
                )
            )
    if old_status != (status_manual or ""):
        db.add(
            models.AuditLog(
                user_id=user.id,
                action="device_status_changed",
                object_type="device",
                object_id=device.id,
                details_json={"old": old_status, "new": status_manual or ""},
            )
        )
    db.add(models.AuditLog(user_id=user.id, action="device_edited", object_type="device", object_id=device.id))
    db.commit()
    updated_total = sum(ip_reference_counts.values())
    if updated_total:
        parts = [
            f"{count} {label}"
            for label, count in (
                ("service record(s)", ip_reference_counts["services"]),
                ("linked URL record(s)", ip_reference_counts["urls"]),
                ("credential login URL(s)", ip_reference_counts["credentials"]),
            )
            if count
        ]
        flash(request, f"Device {device.name} saved. Updated {', '.join(parts)}.", "success")
    else:
        flash(request, f"Device {device.name} saved.", "success")
    return redirect(f"/devices/{device.id}")


@app.get("/services", response_class=HTMLResponse)
def services_page(
    request: Request,
    q: str = "",
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    query = db.query(models.Service)
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                models.Service.name.ilike(like),
                models.Service.purpose.ilike(like),
                models.Service.local_url.ilike(like),
                models.Service.public_url.ilike(like),
                models.Service.repo_url.ilike(like),
                models.Service.compose_path.ilike(like),
                models.Service.notes.ilike(like),
            )
        )
    if q:
        services = query.order_by(models.Service.name).all()
    else:
        services = _service_order_query(db).all()
    service_groups: dict[str, list[models.Service]] = {}
    for service in services:
        group_name = service.device.name if service.device else "Unlinked"
        service_groups.setdefault(group_name, []).append(service)
    return render(
        request,
        "services.html",
        {
            "services": services,
            "service_groups": service_groups,
            "q": q,
            "tags": tag_map(db, "service"),
            "validation_statuses": {service.id: _service_validation_status(db, service) for service in services},
            "device_ping_statuses": _device_ping_status_map(db, [service.device for service in services]),
        },
        user=user,
    )


@app.get("/services/new", response_class=HTMLResponse)
def service_new_page(
    request: Request,
    device_id: int | None = None,
    name: str = "",
    local_url: str = "",
    purpose: str = "",
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    devices = _device_order_query(db).all()
    return render(
        request,
        "service_form.html",
        {
            "service": None,
            "devices": devices,
            "device_id": device_id,
            "tag_text": "",
            "prefill_name": name,
            "prefill_local_url": local_url,
            "prefill_purpose": purpose,
        },
        user=user,
    )


@app.post("/services/new")
def service_create(
    request: Request,
    csrf: str = Form(...),
    device_id: int = Form(...),
    name: str = Form(...),
    type: str = Form(""),
    purpose: str = Form(""),
    status_manual: str = Form(""),
    local_url: str = Form(""),
    public_url: str = Form(""),
    repo_url: str = Form(""),
    compose_path: str = Form(""),
    data_path: str = Form(""),
    config_path: str = Form(""),
    log_path: str = Form(""),
    backup_path: str = Form(""),
    docker_project: str = Form(""),
    container_name: str = Form(""),
    image: str = Form(""),
    notes: str = Form(""),
    credentials_not_needed: str = Form(""),
    tags: str = Form(""),
    next_action: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    device = db.get(models.Device, device_id)
    if not device:
        raise HTTPException(404, "Device not found.")
    service = models.Service(
        device_id=device_id,
        name=name.strip(),
        slug=slugify(name),
        type=type,
        purpose=purpose,
        status_manual=status_manual,
        local_url=local_url,
        public_url=public_url,
        repo_url=repo_url,
        compose_path=compose_path,
        data_path=data_path,
        config_path=config_path,
        log_path=log_path,
        backup_path=backup_path,
        docker_project=docker_project,
        container_name=container_name,
        image=image,
        notes=_notes_with_credentials_marker(notes, credentials_not_needed == "on"),
    )
    db.add(service)
    db.flush()
    set_tags(db, "service", service.id, tags)
    merge_tags(db, "service", service.id, _infer_tags_for_service(service))
    merge_tags(db, "device", device.id, _infer_tags_for_device(device))
    db.add(models.AuditLog(user_id=user.id, action="service_created", object_type="service", object_id=service.id))
    db.commit()
    flash(request, f"Service {service.name} created.", "success")
    if next_action == "add_credential":
        return redirect(f"/credentials/new?device_id={service.device_id}&service_id={service.id}&return_to=/services/{service.id}")
    return redirect(f"/services/{service.id}")


@app.get("/services/{service_id}", response_class=HTMLResponse)
def service_detail(
    request: Request,
    service_id: int,
    tab: str = "overview",
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    service = db.get(models.Service, service_id)
    if not service:
        raise HTTPException(404, "Service not found.")
    if tab == "login":
        tab = "creds"
    commands = _commands_for_service(db, service)
    notes = (
        db.query(models.Note)
        .filter(models.Note.object_type == "service", models.Note.object_id == service.id)
        .order_by(models.Note.updated_at.desc())
        .all()
    )
    return render(
        request,
        "service_detail.html",
        {
            "service": service,
            "tab": tab,
            "commands": commands,
            "history": _service_history(db, service),
            "notes": notes,
            "tag_list": tags_for(db, "service", service.id),
            "status_log": _latest_audit(db, "service", service.id, "service_status_changed"),
            "validation_status": _service_validation_status(db, service),
            "validation_targets": _service_url_validation_statuses(db, service),
            "port_validation_statuses": _service_port_validation_statuses(db, service),
            "device_ping_statuses": _device_ping_status_map(db, [service.device]),
            "device_ping_status": _device_ping_status(db, service.device),
            "backup_ready": bool(service.backup_path or "backup" in (service.notes or "").lower()),
            "token_credentials": _service_tokens(service),
            "login_credentials": _service_login_credentials(service),
        },
        user=user,
    )


@app.post("/services/{service_id}/validate")
def service_validate_now(
    request: Request,
    service_id: int,
    csrf: str = Form(...),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    service = db.get(models.Service, service_id)
    if not service:
        raise HTTPException(404, "Service not found.")
    previous_good = _latest_service_validation_good(db, service)
    details = _validate_service(db, service, user.id)
    _notify_service_validation_webhooks(db, [(service, details, previous_good)])
    db.commit()
    status_text = "partially reachable" if details.get("partial") else "reachable" if details["ok"] else "not responding"
    flash(request, f"{service.name} is {status_text}.", "success" if details["ok"] else "warning")
    return redirect(request.headers.get("referer") or f"/services/{service.id}")


@app.get("/services/{service_id}/edit", response_class=HTMLResponse)
def service_edit_page(
    request: Request,
    service_id: int,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    service = db.get(models.Service, service_id)
    if not service:
        raise HTTPException(404, "Service not found.")
    devices = _device_order_query(db).all()
    return render(
        request,
        "service_form.html",
        {
            "service": service,
            "devices": devices,
            "device_id": service.device_id,
            "tag_text": ", ".join(tags_for(db, "service", service.id)),
        },
        user=user,
    )


@app.post("/services/{service_id}/edit")
def service_update(
    request: Request,
    service_id: int,
    csrf: str = Form(...),
    device_id: int = Form(...),
    name: str = Form(...),
    type: str = Form(""),
    purpose: str = Form(""),
    status_manual: str = Form(""),
    local_url: str = Form(""),
    public_url: str = Form(""),
    repo_url: str = Form(""),
    compose_path: str = Form(""),
    data_path: str = Form(""),
    config_path: str = Form(""),
    log_path: str = Form(""),
    backup_path: str = Form(""),
    docker_project: str = Form(""),
    container_name: str = Form(""),
    image: str = Form(""),
    notes: str = Form(""),
    credentials_not_needed: str = Form(""),
    tags: str = Form(""),
    next_action: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    service = db.get(models.Service, service_id)
    if not service:
        raise HTTPException(404, "Service not found.")
    service.device_id = device_id
    service.name = name.strip()
    service.slug = slugify(name)
    service.type = type
    service.purpose = purpose
    old_status = service.status_manual or ""
    service.status_manual = status_manual
    service.local_url = local_url
    service.public_url = public_url
    service.repo_url = repo_url
    service.compose_path = compose_path
    service.data_path = data_path
    service.config_path = config_path
    service.log_path = log_path
    service.backup_path = backup_path
    service.docker_project = docker_project
    service.container_name = container_name
    service.image = image
    service.notes = _notes_with_credentials_marker(notes, credentials_not_needed == "on")
    set_tags(db, "service", service.id, tags)
    merge_tags(db, "service", service.id, _infer_tags_for_service(service))
    if service.device:
        merge_tags(db, "device", service.device.id, _infer_tags_for_device(service.device))
    if old_status != (status_manual or ""):
        db.add(
            models.AuditLog(
                user_id=user.id,
                action="service_status_changed",
                object_type="service",
                object_id=service.id,
                details_json={"old": old_status, "new": status_manual or ""},
            )
        )
    db.add(models.AuditLog(user_id=user.id, action="service_edited", object_type="service", object_id=service.id))
    db.commit()
    flash(request, f"Service {service.name} saved.", "success")
    if next_action == "add_credential":
        return redirect(f"/credentials/new?device_id={service.device_id}&service_id={service.id}&return_to=/services/{service.id}")
    return redirect(f"/services/{service.id}")


@app.get("/credentials", response_class=HTMLResponse)
def credentials_page(
    request: Request,
    q: str = "",
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    query = db.query(models.Credential).filter(models.Credential.secret_type != "API token")
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                models.Credential.label.ilike(like),
                models.Credential.username.ilike(like),
                models.Credential.login_url.ilike(like),
                models.Credential.notes.ilike(like),
            )
        )
    credentials = sorted(query.all(), key=_credential_sort_key)
    groups: dict[str, list[models.Credential]] = {}
    for credential in credentials:
        device_name = (
            credential.service.device.name
            if credential.service and credential.service.device
            else credential.device.name
            if credential.device
            else "Unlinked"
        )
        groups.setdefault(device_name, []).append(credential)
    return render(
        request,
        "credentials.html",
        {
            "credentials": credentials,
            "credential_groups": groups,
            "q": q,
            "tags": tag_map(db, "credential"),
            "favorite_ids": _favorite_credential_ids(db),
            "device_ping_statuses": _device_ping_status_map(
                db,
                [
                    credential.service.device if credential.service and credential.service.device else credential.device
                    for credential in credentials
                ],
            ),
        },
        user=user,
    )


@app.get("/tokens", response_class=HTMLResponse)
def tokens_page(
    request: Request,
    q: str = "",
    service_id: int | None = None,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    tokens = _token_credentials(db)
    if service_id:
        tokens = [token for token in tokens if token.service_id == service_id]
    if q:
        needle = q.lower()
        tokens = [
            token
            for token in tokens
            if needle in token.label.lower()
            or needle in token.username.lower()
            or needle in (token.notes or "").lower()
            or (token.service and needle in token.service.name.lower())
        ]
    return render(
        request,
        "tokens.html",
        {
            "tokens": tokens,
            "q": q,
            "service_id": service_id,
            "tags": tag_map(db, "credential"),
            "device_ping_statuses": _device_ping_status_map(
                db,
                [
                    token.service.device if token.service and token.service.device else token.device
                    for token in tokens
                ],
            ),
        },
        user=user,
    )


@app.get("/credentials/new", response_class=HTMLResponse)
def credential_new_page(
    request: Request,
    device_id: int | None = None,
    service_id: int | None = None,
    secret_type: str = "",
    return_to: str = "",
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    selected_service = db.get(models.Service, service_id) if service_id else None
    selected_device = db.get(models.Device, device_id) if device_id else selected_service.device if selected_service else None
    fallback = "/tokens" if secret_type == "API token" else "/credentials"
    return_target = _safe_return_to(return_to, _safe_return_to(request.headers.get("referer", ""), fallback))
    return render(
        request,
        "credential_form.html",
        {
            "credential": None,
            "devices": _device_order_query(db).all(),
            "services": _service_order_query(db).all(),
            "device_id": selected_device.id if selected_device else device_id,
            "service_id": selected_service.id if selected_service else service_id,
            "service_name_prefill": selected_service.name if selected_service else "",
            "login_url_prefill": (selected_service.local_url or selected_service.public_url) if selected_service else "",
            "secret_type_prefill": secret_type,
            "tag_text": "",
            "return_to": return_target,
        },
        user=user,
    )


@app.get("/credentials/{credential_id}", response_class=HTMLResponse)
def credential_detail_page(
    request: Request,
    credential_id: int,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    credential = db.get(models.Credential, credential_id)
    if not credential:
        raise HTTPException(404, "Credential not found.")
    return render(
        request,
        "credential_detail.html",
        {
            "credential": credential,
            "tag_list": tags_for(db, "credential", credential.id),
            "device_ping_statuses": _device_ping_status_map(
                db,
                [credential.service.device if credential.service and credential.service.device else credential.device],
            ),
        },
        user=user,
    )


@app.post("/credentials/new")
def credential_create(
    request: Request,
    csrf: str = Form(...),
    label: str = Form(...),
    username: str = Form(""),
    secret: str = Form(...),
    secret_type: str = Form("password"),
    security_level: str = Form("low"),
    device_id: str = Form(""),
    service_id: str = Form(""),
    service_name: str = Form(""),
    login_url: str = Form(""),
    expires_at: str = Form(""),
    notes: str = Form(""),
    tags: str = Form(""),
    return_to: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    fallback = "/tokens" if secret_type == "API token" else "/credentials"
    return_target = _safe_return_to(return_to, fallback)
    resolved_device_id, resolved_service_id, error = _resolve_service_for_credential(
        db,
        device_id=int(device_id) if device_id else None,
        service_id=int(service_id) if service_id else None,
        service_name=service_name,
        label=label,
    )
    if error:
        flash(request, error, "warning")
        return redirect(
            _credential_form_url(
                device_id=device_id,
                service_id=service_id,
                secret_type=secret_type,
                return_to=return_target,
            )
        )
    if _duplicate_credential(
        db,
        device_id=resolved_device_id,
        service_id=resolved_service_id,
        label=label,
        username=username,
    ):
        flash(request, "That credential already appears to exist. Edit the existing one if it needs changes.", "warning")
        return redirect(return_target)
    resolved_service = db.get(models.Service, resolved_service_id) if resolved_service_id else None
    if not login_url and resolved_service:
        login_url = resolved_service.local_url or resolved_service.public_url or ""
    login_url = _normalize_login_url_for_network(login_url)
    credential = models.Credential(
        label=label.strip(),
        username=username.strip(),
        secret_encrypted=encrypt_text(secret),
        secret_type=secret_type,
        security_level=security_level,
        device_id=resolved_device_id,
        service_id=resolved_service_id,
        login_url=login_url,
        expires_at=_parse_optional_datetime(expires_at),
        notes=notes,
        last_changed_at=now_utc(),
    )
    db.add(credential)
    db.flush()
    set_tags(db, "credential", credential.id, tags)
    sync_details = _sync_credential_login_endpoint(db, credential)
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="credential_created",
            object_type="credential",
            object_id=credential.id,
            details_json=sync_details,
        )
    )
    db.commit()
    flash(request, "Credential stored encrypted at rest.", "success")
    return redirect(return_target)


@app.get("/credentials/{credential_id}/edit", response_class=HTMLResponse)
def credential_edit_page(
    request: Request,
    credential_id: int,
    return_to: str = "",
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    credential = db.get(models.Credential, credential_id)
    if not credential:
        raise HTTPException(404, "Credential not found.")
    return_target = _safe_return_to(return_to, _safe_return_to(request.headers.get("referer", ""), f"/credentials/{credential.id}"))
    return render(
        request,
        "credential_form.html",
        {
            "credential": credential,
            "devices": _device_order_query(db).all(),
            "services": _service_order_query(db).all(),
            "device_id": credential.device_id,
            "service_id": credential.service_id,
            "service_name_prefill": credential.service.name if credential.service else "",
            "tag_text": ", ".join(tags_for(db, "credential", credential.id)),
            "return_to": return_target,
        },
        user=user,
    )


@app.post("/credentials/{credential_id}/edit")
def credential_update(
    request: Request,
    credential_id: int,
    csrf: str = Form(...),
    label: str = Form(...),
    username: str = Form(""),
    secret: str = Form(""),
    secret_type: str = Form("password"),
    security_level: str = Form("low"),
    device_id: str = Form(""),
    service_id: str = Form(""),
    service_name: str = Form(""),
    login_url: str = Form(""),
    expires_at: str = Form(""),
    notes: str = Form(""),
    active: str = Form("on"),
    tags: str = Form(""),
    return_to: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    credential = db.get(models.Credential, credential_id)
    if not credential:
        raise HTTPException(404, "Credential not found.")
    resolved_device_id, resolved_service_id, error = _resolve_service_for_credential(
        db,
        device_id=int(device_id) if device_id else None,
        service_id=int(service_id) if service_id else None,
        service_name=service_name,
        label=label,
    )
    if error:
        flash(request, error, "warning")
        return redirect(_credential_edit_url(credential.id, return_to))
    duplicate = _duplicate_credential(
        db,
        device_id=resolved_device_id,
        service_id=resolved_service_id,
        label=label,
        username=username,
    )
    if duplicate and duplicate.id != credential.id:
        flash(request, "Another credential already uses that label and username in this scope.", "warning")
        return redirect(_credential_edit_url(credential.id, return_to))
    credential.label = label.strip()
    credential.username = username.strip()
    if secret:
        credential.secret_encrypted = encrypt_text(secret)
        credential.last_changed_at = now_utc()
    credential.secret_type = secret_type
    credential.security_level = security_level
    credential.device_id = resolved_device_id
    credential.service_id = resolved_service_id
    credential.login_url = _normalize_login_url_for_network(login_url)
    credential.expires_at = _parse_optional_datetime(expires_at)
    credential.notes = notes
    credential.active = active == "on"
    set_tags(db, "credential", credential.id, tags)
    sync_details = _sync_credential_login_endpoint(db, credential)
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="credential_edited",
            object_type="credential",
            object_id=credential.id,
            details_json=sync_details,
        )
    )
    db.commit()
    flash(request, "Credential saved.", "success")
    return redirect(_safe_return_to(return_to, f"/credentials/{credential.id}"))


@app.post("/delete/{object_type}/{object_id}")
def delete_object(
    request: Request,
    object_type: str,
    object_id: int,
    csrf: str = Form(...),
    delete_services: str = Form(""),
    delete_credentials: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    model_map = {
        "device": models.Device,
        "service": models.Service,
        "credential": models.Credential,
        "command": models.Command,
        "port": models.Port,
        "url": models.Url,
        "note": models.Note,
    }
    model = model_map.get(object_type)
    if not model:
        raise HTTPException(404, "Delete is not enabled for that object yet.")
    obj = db.get(model, object_id)
    if not obj:
        raise HTTPException(404, "Object not found.")
    return_to = _delete_redirect_target(request, object_type, object_id)
    if object_type == "device" and isinstance(obj, models.Device):
        remove_services = delete_services.lower() in {"on", "true", "1", "yes"}
        remove_credentials = delete_credentials.lower() in {"on", "true", "1", "yes"}
        service_ids = [service.id for service in obj.services]
        credential_filter = models.Credential.device_id == obj.id
        if service_ids:
            credential_filter = or_(credential_filter, models.Credential.service_id.in_(service_ids))
        related_credentials = db.query(models.Credential).filter(credential_filter).all()
        preserved_device = None if remove_services else _move_device_records_to_preserved_device(db, obj)
        if remove_credentials:
            for credential in related_credentials:
                db.query(models.TagLink).filter_by(object_type="credential", object_id=credential.id).delete()
                db.delete(credential)
        else:
            for credential in related_credentials:
                if preserved_device:
                    credential.device_id = preserved_device.id
                else:
                    credential.device_id = None
                if not preserved_device and credential.service_id in service_ids:
                    credential.service_id = None
                credential.notes = _append_note_once(credential.notes, f"Unlinked when device {obj.name} was deleted.")
        if remove_services:
            for service_id in service_ids:
                db.query(models.TagLink).filter_by(object_type="service", object_id=service_id).delete()
                db.query(models.Note).filter_by(object_type="service", object_id=service_id).delete()
                for command in db.query(models.Command).filter_by(applies_to_type="service", applies_to_id=service_id).all():
                    db.query(models.TagLink).filter_by(object_type="command", object_id=command.id).delete()
                    db.delete(command)
        for port in list(obj.ports):
            if port.device_id != obj.id:
                continue
            db.query(models.TagLink).filter_by(object_type="port", object_id=port.id).delete()
            db.delete(port)
        for url in list(obj.urls):
            if url.device_id != obj.id:
                continue
            db.query(models.TagLink).filter_by(object_type="url", object_id=url.id).delete()
            db.delete(url)
        for image in list(obj.images):
            if image.device_id != obj.id:
                continue
            db.query(models.TagLink).filter_by(object_type="device_image", object_id=image.id).delete()
            try:
                _stored_upload_path(DEVICE_IMAGE_DIR, image.stored_filename).unlink(missing_ok=True)
            except OSError:
                pass
            db.delete(image)
        db.query(models.Note).filter_by(object_type="device", object_id=obj.id).delete()
        for command in db.query(models.Command).filter_by(applies_to_type="device", applies_to_id=obj.id).all():
            db.query(models.TagLink).filter_by(object_type="command", object_id=command.id).delete()
            db.delete(command)
    elif object_type == "service" and isinstance(obj, models.Service):
        _delete_service_tree(db, obj)
        db.add(models.AuditLog(user_id=user.id, action=f"{object_type}_deleted", object_type=object_type, object_id=object_id))
        db.commit()
        flash(request, f"{object_type.title()} deleted.", "success")
        return redirect(return_to)
    tag_object_types = [object_type]
    if object_type == "note" and isinstance(obj, models.Note):
        tag_object_types.append(obj.object_type)
    db.query(models.TagLink).filter(
        models.TagLink.object_type.in_(tag_object_types),
        models.TagLink.object_id == object_id,
    ).delete()
    db.delete(obj)
    delete_details = {}
    if object_type == "device":
        delete_details = {
            "delete_services": delete_services,
            "delete_credentials": delete_credentials,
        }
    db.add(
        models.AuditLog(
            user_id=user.id,
            action=f"{object_type}_deleted",
            object_type=object_type,
            object_id=object_id,
            details_json=delete_details,
        )
    )
    db.commit()
    flash(request, f"{object_type.title()} deleted.", "success")
    return redirect(return_to)


def medium_unlocked(request: Request) -> bool:
    raw = request.session.get("credential_unlock_until")
    if not raw:
        return False
    try:
        return datetime.fromisoformat(raw) > now_utc()
    except ValueError:
        return False


def _reveal_failure_response(
    request: Request,
    *,
    json_response: bool = False,
    message_prefix: str = "Incorrect password or reveal PIN.",
    requires_totp: bool = False,
) -> JSONResponse | RedirectResponse:
    failures = int(request.session.get("reveal_failures") or 0) + 1
    if failures >= 5:
        request.session.clear()
        if json_response:
            return JSONResponse(
                {
                    "detail": "Too many wrong password attempts. You have been logged out for security.",
                    "logged_out": True,
                },
                status_code=403,
            )
        flash(request, "Too many wrong password attempts. You have been logged out for security.", "danger")
        return redirect("/login")
    request.session["reveal_failures"] = failures
    message = f"{message_prefix} {5 - failures} attempt(s) left."
    if json_response:
        return JSONResponse(
            {
                "detail": message,
                "requires_challenge": True,
                "requires_totp": requires_totp,
                "message": "Security check" if requires_totp else "Password or reveal PIN",
            },
            status_code=403,
        )
    flash(request, message, "danger")
    return redirect(request.headers.get("referer") or "/credentials")


def _reset_reveal_failures(request: Request) -> None:
    request.session.pop("reveal_failures", None)


@app.get("/credentials/{credential_id}/reveal", response_class=HTMLResponse)
def credential_reveal_page(
    request: Request,
    credential_id: int,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    credential = db.get(models.Credential, credential_id)
    if not credential:
        raise HTTPException(404, "Credential not found.")
    can_reveal_without_challenge = credential.security_level == "low" or (
        credential.security_level == "medium" and medium_unlocked(request)
    )
    return render(
        request,
        "credential_reveal.html",
        {
            "credential": credential,
            "revealed_secret": None,
            "can_reveal_without_challenge": can_reveal_without_challenge,
            "requires_totp": _credential_requires_totp(db, user, credential),
        },
        user=user,
    )


@app.post("/credentials/{credential_id}/reveal", response_class=HTMLResponse)
def credential_reveal_post(
    request: Request,
    credential_id: int,
    csrf: str = Form(...),
    challenge: str = Form(""),
    totp_code: str = Form(""),
    reason: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    check_csrf(request, csrf)
    credential = db.get(models.Credential, credential_id)
    if not credential:
        raise HTTPException(404, "Credential not found.")
    needs_challenge = credential.security_level in {"high", "extreme"} or (
        credential.security_level == "medium" and not medium_unlocked(request)
    )
    needs_totp = _credential_requires_totp(db, user, credential)
    if needs_challenge and not challenge.strip():
        flash(request, "Enter your account password or reveal PIN.", "warning")
        return redirect(f"/credentials/{credential.id}/reveal")
    if needs_challenge and not _challenge_ok_and_upgrade(db, user, challenge):
        return _reveal_failure_response(request)
    if needs_totp and not totp_code.strip():
        flash(request, "Enter your 2FA code.", "warning")
        return redirect(f"/credentials/{credential.id}/reveal")
    if needs_totp and not _verify_totp_code(user, totp_code):
        return _reveal_failure_response(request, message_prefix="Incorrect 2FA code.")
    if credential.security_level == "medium" and needs_challenge:
        request.session["credential_unlock_until"] = unlock_expiry().isoformat()
    _reset_reveal_failures(request)
    return reveal_credential(request, credential, user, db, reason=reason)


def reveal_credential(
    request: Request,
    credential: models.Credential,
    user: models.User,
    db: Session,
    *,
    reason: str = "",
) -> HTMLResponse:
    credential.last_revealed_at = now_utc()
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="credential_revealed",
            object_type="credential",
            object_id=credential.id,
            details_json={"level": credential.security_level, "reason": reason},
        )
    )
    db.commit()
    return render(
        request,
        "credential_reveal.html",
        {"credential": credential, "revealed_secret": decrypt_text(credential.secret_encrypted)},
        user=user,
    )


@app.post("/credentials/{credential_id}/reveal-json")
async def credential_reveal_json(
    request: Request,
    credential_id: int,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    check_csrf(request, request.headers.get("x-csrf-token", ""))
    payload = await request.json()
    credential = db.get(models.Credential, credential_id)
    if not credential:
        return JSONResponse({"detail": "Credential not found."}, status_code=404)
    needs_challenge = credential.security_level in {"high", "extreme"} or (
        credential.security_level == "medium" and not medium_unlocked(request)
    )
    needs_totp = _credential_requires_totp(db, user, credential)
    challenge_value = str(payload.get("challenge", ""))
    totp_code = str(payload.get("totp_code", ""))
    if (needs_challenge and not challenge_value) or (needs_totp and not totp_code):
        return JSONResponse(
            {
                "detail": "Password or reveal PIN and 2FA code required." if needs_totp else "Password or reveal PIN required.",
                "requires_challenge": True,
                "requires_totp": needs_totp,
                "requires_reason": False,
                "message": "Security check" if needs_totp else "Password or reveal PIN",
            },
            status_code=403,
        )
    if needs_challenge and not _challenge_ok_and_upgrade(db, user, challenge_value):
        response = _reveal_failure_response(request, json_response=True)
        if isinstance(response, JSONResponse):
            return response
    if needs_totp and not _verify_totp_code(user, totp_code):
        response = _reveal_failure_response(
            request,
            json_response=True,
            message_prefix="Incorrect 2FA code.",
            requires_totp=True,
        )
        if isinstance(response, JSONResponse):
            return response
    if credential.security_level == "medium" and needs_challenge:
        request.session["credential_unlock_until"] = unlock_expiry().isoformat()
    _reset_reveal_failures(request)
    credential.last_revealed_at = now_utc()
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="credential_revealed",
            object_type="credential",
            object_id=credential.id,
            details_json={
                "level": credential.security_level,
                "reason": str(payload.get("reason", "")),
                "surface": "inline",
            },
        )
    )
    db.commit()
    return JSONResponse(
        {
            "id": credential.id,
            "username": credential.username,
            "secret": decrypt_text(credential.secret_encrypted),
            "login_url": credential.login_url,
            "last_revealed_at": format_dt(credential.last_revealed_at),
        }
    )


@app.get("/commands", response_class=HTMLResponse)
def commands_page(
    request: Request,
    q: str = "",
    category: str = "",
    risk: str = "",
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    query = db.query(models.Command)
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                models.Command.name.ilike(like),
                models.Command.category.ilike(like),
                models.Command.short_description.ilike(like),
                models.Command.long_description.ilike(like),
                models.Command.command_template.ilike(like),
                models.Command.notes.ilike(like),
            )
        )
    if category:
        query = query.filter(models.Command.category == category)
    if risk:
        query = query.filter(models.Command.risk_level == risk)
    commands = query.order_by(models.Command.category, models.Command.name).all()
    categories = [row[0] for row in db.query(models.Command.category).distinct().order_by(models.Command.category).all()]
    return render(
        request,
        "commands.html",
        {
            "commands": commands,
            "q": q,
            "category": category,
            "risk": risk,
            "categories": categories,
            "tags": tag_map(db, "command"),
        },
        user=user,
    )


@app.get("/commands/new", response_class=HTMLResponse)
def command_new_page(
    request: Request,
    applies_to_type: str = "generic",
    applies_to_id: int | None = None,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    return render(
        request,
        "command_form.html",
        {
            "command": None,
            "applies_to_type": applies_to_type,
            "applies_to_id": applies_to_id,
            "tag_text": "",
            "devices": _device_order_query(db).all(),
            "services": _service_order_query(db).all(),
        },
        user=user,
    )


@app.post("/commands/new")
def command_create(
    request: Request,
    csrf: str = Form(...),
    name: str = Form(...),
    category: str = Form("Common"),
    applies_to_type: str = Form("generic"),
    applies_to_id: str = Form(""),
    command_template: str = Form(...),
    short_description: str = Form(""),
    long_description: str = Form(""),
    where_to_run: str = Form("Remote SSH host"),
    risk_level: str = Form("safe"),
    help_low: str = Form(""),
    help_high: str = Form(""),
    notes: str = Form(""),
    tags: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    if _duplicate_command(db, command_template):
        flash(request, "That command already exists in the library.", "warning")
        return redirect("/commands")
    command = models.Command(
        name=name,
        category=category,
        applies_to_type=applies_to_type,
        applies_to_id=int(applies_to_id) if applies_to_id else None,
        command_template=command_template,
        short_description=short_description,
        long_description=long_description,
        where_to_run=where_to_run,
        risk_level=risk_level,
        help_low=help_low,
        help_high=help_high,
        notes=notes,
    )
    db.add(command)
    db.flush()
    set_tags(db, "command", command.id, tags)
    db.add(models.AuditLog(user_id=user.id, action="command_created", object_type="command", object_id=command.id))
    db.commit()
    flash(request, "Command saved.", "success")
    return redirect("/commands")


@app.get("/commands/{command_id}/edit", response_class=HTMLResponse)
def command_edit_page(
    request: Request,
    command_id: int,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    command = db.get(models.Command, command_id)
    if not command:
        raise HTTPException(404, "Command not found.")
    return render(
        request,
        "command_form.html",
        {
            "command": command,
            "applies_to_type": command.applies_to_type,
            "applies_to_id": command.applies_to_id,
            "tag_text": ", ".join(tags_for(db, "command", command.id)),
            "devices": _device_order_query(db).all(),
            "services": _service_order_query(db).all(),
        },
        user=user,
    )


@app.post("/commands/{command_id}/edit")
def command_update(
    request: Request,
    command_id: int,
    csrf: str = Form(...),
    name: str = Form(...),
    category: str = Form("Common"),
    applies_to_type: str = Form("generic"),
    applies_to_id: str = Form(""),
    command_template: str = Form(...),
    short_description: str = Form(""),
    long_description: str = Form(""),
    where_to_run: str = Form("Remote SSH host"),
    risk_level: str = Form("safe"),
    help_low: str = Form(""),
    help_high: str = Form(""),
    notes: str = Form(""),
    tags: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    command = db.get(models.Command, command_id)
    if not command:
        raise HTTPException(404, "Command not found.")
    duplicate = _duplicate_command(db, command_template)
    if duplicate and duplicate.id != command.id:
        flash(request, "Another command already uses that exact command text.", "warning")
        return redirect(f"/commands/{command.id}/edit")
    command.name = name
    command.category = category
    command.applies_to_type = applies_to_type
    command.applies_to_id = int(applies_to_id) if applies_to_id else None
    command.command_template = command_template
    command.short_description = short_description
    command.long_description = long_description
    command.where_to_run = where_to_run
    command.risk_level = risk_level
    command.help_low = help_low
    command.help_high = help_high
    command.notes = notes
    set_tags(db, "command", command.id, tags)
    db.add(models.AuditLog(user_id=user.id, action="command_edited", object_type="command", object_id=command.id))
    db.commit()
    flash(request, "Command saved.", "success")
    return redirect("/commands")


@app.get("/ports", response_class=HTMLResponse)
def ports_page(
    request: Request,
    device_id: int | None = None,
    service_id: int | None = None,
    add: str = "",
    return_to: str = "",
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    ports = db.query(models.Port).order_by(models.Port.host_port).all()
    devices = _device_order_query(db).all()
    selected_service = db.get(models.Service, service_id) if service_id else None
    selected_device_id = device_id or (selected_service.device_id if selected_service else None)
    return render(
        request,
        "ports.html",
        {
            "ports": ports,
            "urls": db.query(models.Url).order_by(models.Url.url).all(),
            "devices": devices,
            "services": _service_order_query(db).all(),
            "device_ping_statuses": _device_ping_status_map(db, devices),
            "port_validation_statuses": _port_validation_status_map(db, ports),
            "selected_device_id": selected_device_id,
            "selected_service_id": selected_service.id if selected_service else None,
            "add_panel": add if add in {"port", "url"} else "",
            "return_to": _safe_return_to(return_to, "/ports") if return_to else "",
        },
        user=user,
    )


@app.get("/tags", response_class=HTMLResponse)
def tags_page(
    request: Request,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    links = db.query(models.TagLink).all()
    grouped: dict[int, list[dict[str, Any]]] = {}
    related_devices: list[models.Device | None] = []
    for link in links:
        href = "#"
        label = f"#{link.object_id}"
        subtitle = ""
        related_device: models.Device | None = None
        kind = link.object_type.replace("_", " ").title()
        if link.object_type == "device":
            obj = db.get(models.Device, link.object_id)
            if obj:
                href, label = f"/devices/{obj.id}", obj.name
                related_device = obj
        elif link.object_type == "service":
            obj = db.get(models.Service, link.object_id)
            if obj:
                href, label = f"/services/{obj.id}", obj.name
                subtitle = obj.device.name if obj.device else ""
                related_device = obj.device
        elif link.object_type == "credential":
            obj = db.get(models.Credential, link.object_id)
            if obj:
                href, label = f"/credentials/{obj.id}", obj.label
                context_device = obj.service.device if obj.service and obj.service.device else obj.device
                subtitle = context_device.name if context_device else ""
                related_device = context_device
        elif link.object_type == "command":
            obj = db.get(models.Command, link.object_id)
            if obj:
                href, label = "/commands", obj.name
        elif link.object_type == "port":
            obj = db.get(models.Port, link.object_id)
            if obj:
                href, label = f"/ports/{obj.id}/edit?return_to=/tags", f"{obj.host_port}/{obj.protocol}"
                subtitle = obj.device.name if obj.device else ""
                related_device = obj.device
        elif link.object_type == "url":
            obj = db.get(models.Url, link.object_id)
            if obj:
                href, label = f"/urls/{obj.id}/edit?return_to=/tags", obj.label or obj.url
                context_device = obj.service.device if obj.service and obj.service.device else obj.device
                subtitle = context_device.name if context_device else ""
                related_device = context_device
        elif link.object_type == "quick_note":
            obj = db.get(models.Note, link.object_id)
            if obj:
                href, label = f"/notes/{obj.id}", obj.title or "Quick note"
        elif link.object_type == "note":
            obj = db.get(models.Note, link.object_id)
            if obj:
                href, label = f"/notes/{obj.id}", obj.title or "Note"
        elif link.object_type == "device_image":
            obj = db.get(models.DeviceImage, link.object_id)
            if obj:
                href, label = f"/devices/{obj.device_id}?tab=images", obj.name or obj.original_filename or "Device image"
                subtitle = obj.device.name if obj.device else ""
                related_device = obj.device
        elif link.object_type == "user_suggestion":
            obj = db.get(models.UserSuggestion, link.object_id)
            if obj:
                href, label = "/suggestions#custom-suggestions", obj.title or "Custom suggestion"
                if obj.object_type == "device" and obj.object_id:
                    related_device = db.get(models.Device, obj.object_id)
                    subtitle = related_device.name if related_device else ""
                elif obj.object_type == "service" and obj.object_id:
                    service = db.get(models.Service, obj.object_id)
                    related_device = service.device if service and service.device else None
                    subtitle = service.name if service else ""
        if href == "#":
            continue
        if related_device:
            related_devices.append(related_device)
        grouped.setdefault(link.tag_id, []).append(
            {"kind": kind, "href": href, "label": label, "subtitle": subtitle, "device": related_device}
        )
    used_tag_ids = set(grouped)
    tags = (
        db.query(models.Tag)
        .filter(models.Tag.id.in_(used_tag_ids))
        .order_by(models.Tag.name)
        .all()
        if used_tag_ids
        else []
    )
    tag_cards: list[dict[str, Any]] = []
    kind_order = ["Device", "Service", "Credential", "Command", "Port", "Url", "Device Image", "Note", "Quick Note", "User Suggestion"]
    for tag in tags:
        by_kind: dict[str, list[dict[str, Any]]] = {}
        for item in grouped.get(tag.id, []):
            by_kind.setdefault(item["kind"], []).append(item)
        sorted_groups = [
            {"kind": kind, "items": sorted(by_kind[kind], key=lambda row: row["label"].lower())}
            for kind in kind_order
            if kind in by_kind
        ]
        sorted_groups.extend(
            {"kind": kind, "items": sorted(items, key=lambda row: row["label"].lower())}
            for kind, items in sorted(by_kind.items())
            if kind not in kind_order
        )
        tag_cards.append({"tag": tag, "count": len(grouped.get(tag.id, [])), "groups": sorted_groups})
    return render(
        request,
        "tags.html",
        {
            "tags": tags,
            "grouped": grouped,
            "tag_cards": tag_cards,
            "device_ping_statuses": _device_ping_status_map(db, related_devices),
        },
        user=user,
    )


@app.post("/tags/{tag_id}/delete")
def tag_delete(
    request: Request,
    tag_id: int,
    csrf: str = Form(...),
    password: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    tag = db.get(models.Tag, tag_id)
    if not tag:
        raise HTTPException(404, "Tag not found.")
    if not _account_password_ok_and_upgrade(db, user, password):
        flash(request, "Enter your account password to delete a tag from all records.", "danger")
        return redirect("/tags")
    link_count = db.query(models.TagLink).filter_by(tag_id=tag.id).count()
    tag_name = tag.name
    db.query(models.TagLink).filter_by(tag_id=tag.id).delete()
    db.delete(tag)
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="tag_deleted",
            object_type="tag",
            object_id=tag_id,
            details_json={"name": tag_name, "links_removed": link_count},
        )
    )
    db.commit()
    flash(request, f"Deleted #{tag_name} from {link_count} linked item(s).", "success")
    return redirect("/tags")


@app.post("/ports/add")
def add_port(
    request: Request,
    csrf: str = Form(...),
    device_id: int = Form(...),
    service_id: str = Form(""),
    host_port: int = Form(...),
    internal_port: str = Form(""),
    protocol: str = Form("tcp"),
    purpose: str = Form(""),
    tags: str = Form(""),
    notes: str = Form(""),
    return_to: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    return_target = _safe_return_to(return_to, "/ports")
    resolved_service_id = int(service_id) if service_id else None
    if resolved_service_id:
        service = db.get(models.Service, resolved_service_id)
        if service:
            device_id = service.device_id
        else:
            resolved_service_id = None
    duplicate = (
        db.query(models.Port)
        .filter(
            models.Port.device_id == device_id,
            models.Port.host_port == host_port,
            models.Port.protocol == protocol,
        )
        .first()
    )
    if duplicate:
        flash(request, "That port is already documented for this device.", "warning")
        return redirect(return_target)
    port = models.Port(
        device_id=device_id,
        service_id=resolved_service_id,
        host_port=host_port,
        internal_port=int(internal_port) if internal_port else None,
        protocol=protocol,
        purpose=purpose,
        notes=notes,
    )
    db.add(port)
    db.flush()
    set_tags(db, "port", port.id, tags)
    if tags:
        merge_tags(db, "device", port.device_id, tags)
    db.add(models.AuditLog(user_id=user.id, action="port_added", object_type="port", object_id=port.id))
    db.commit()
    flash(request, "Port added.", "success")
    return redirect(return_target)


@app.post("/urls/add")
def add_url(
    request: Request,
    csrf: str = Form(...),
    device_id: str = Form(""),
    service_id: str = Form(""),
    label: str = Form(""),
    url: str = Form(...),
    url_type: str = Form("local"),
    tags: str = Form(""),
    notes: str = Form(""),
    return_to: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    return_target = _safe_return_to(return_to, "/ports")
    resolved_service_id = int(service_id) if service_id else None
    resolved_device_id = int(device_id) if device_id else None
    if resolved_service_id:
        service = db.get(models.Service, resolved_service_id)
        if service:
            resolved_device_id = service.device_id
        else:
            resolved_service_id = None
    row = models.Url(
        device_id=resolved_device_id,
        service_id=resolved_service_id,
        label=label,
        url=url,
        url_type=url_type,
        notes=notes,
    )
    db.add(row)
    db.flush()
    set_tags(db, "url", row.id, tags)
    if tags and row.device_id:
        merge_tags(db, "device", row.device_id, tags)
    db.add(models.AuditLog(user_id=user.id, action="url_added", object_type="url", object_id=row.id))
    db.commit()
    flash(request, "URL added.", "success")
    return redirect(return_target)


@app.get("/ports/{port_id}/edit", response_class=HTMLResponse)
def port_edit_page(
    request: Request,
    port_id: int,
    return_to: str = "",
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    port = db.get(models.Port, port_id)
    if not port:
        raise HTTPException(404, "Port not found.")
    return render(
        request,
        "port_form.html",
        {
            "port": port,
            "devices": _device_order_query(db).all(),
            "services": _service_order_query(db).all(),
            "tag_text": ", ".join(tags_for(db, "port", port.id)),
            "return_to": _safe_return_to(return_to, "/ports"),
        },
        user=user,
    )


@app.post("/ports/{port_id}/edit")
def port_update(
    request: Request,
    port_id: int,
    csrf: str = Form(...),
    device_id: int = Form(...),
    service_id: str = Form(""),
    host_port: int = Form(...),
    internal_port: str = Form(""),
    protocol: str = Form("tcp"),
    purpose: str = Form(""),
    tags: str = Form(""),
    notes: str = Form(""),
    return_to: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    port = db.get(models.Port, port_id)
    if not port:
        raise HTTPException(404, "Port not found.")
    resolved_service_id = int(service_id) if service_id else None
    if resolved_service_id:
        service = db.get(models.Service, resolved_service_id)
        if service:
            device_id = service.device_id
        else:
            resolved_service_id = None
    port.device_id = device_id
    port.service_id = resolved_service_id
    port.host_port = host_port
    port.internal_port = int(internal_port) if internal_port else None
    port.protocol = protocol
    port.purpose = purpose
    port.notes = notes
    set_tags(db, "port", port.id, tags)
    if tags:
        merge_tags(db, "device", device_id, tags)
    db.add(models.AuditLog(user_id=user.id, action="port_edited", object_type="port", object_id=port.id))
    db.commit()
    flash(request, "Port saved.", "success")
    return redirect(_safe_return_to(return_to, "/ports"))


@app.get("/urls/{url_id}/edit", response_class=HTMLResponse)
def url_edit_page(
    request: Request,
    url_id: int,
    return_to: str = "",
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    url = db.get(models.Url, url_id)
    if not url:
        raise HTTPException(404, "URL not found.")
    return render(
        request,
        "url_form.html",
        {
            "url": url,
            "devices": _device_order_query(db).all(),
            "services": _service_order_query(db).all(),
            "tag_text": ", ".join(tags_for(db, "url", url.id)),
            "return_to": _safe_return_to(return_to, "/ports"),
        },
        user=user,
    )


@app.post("/urls/{url_id}/edit")
def url_update(
    request: Request,
    url_id: int,
    csrf: str = Form(...),
    device_id: str = Form(""),
    service_id: str = Form(""),
    label: str = Form(""),
    url: str = Form(...),
    url_type: str = Form("local"),
    tags: str = Form(""),
    notes: str = Form(""),
    return_to: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    row = db.get(models.Url, url_id)
    if not row:
        raise HTTPException(404, "URL not found.")
    resolved_service_id = int(service_id) if service_id else None
    resolved_device_id = int(device_id) if device_id else None
    if resolved_service_id:
        service = db.get(models.Service, resolved_service_id)
        if service:
            resolved_device_id = service.device_id
        else:
            resolved_service_id = None
    row.device_id = resolved_device_id
    row.service_id = resolved_service_id
    row.label = label
    row.url = url
    row.url_type = url_type
    row.notes = notes
    set_tags(db, "url", row.id, tags)
    if tags and row.device_id:
        merge_tags(db, "device", row.device_id, tags)
    db.add(models.AuditLog(user_id=user.id, action="url_edited", object_type="url", object_id=row.id))
    db.commit()
    flash(request, "URL saved.", "success")
    return redirect(_safe_return_to(return_to, "/ports"))


@app.post("/notes/add")
def add_note(
    request: Request,
    csrf: str = Form(...),
    object_type: str = Form(...),
    object_id: int = Form(...),
    title: str = Form(""),
    body: str = Form(...),
    source: str = Form("manual"),
    return_to: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    note = models.Note(object_type=object_type, object_id=object_id, title=title, body=body, source=source)
    db.add(note)
    db.flush()
    note_audit_type = "quick_note" if object_type == "quick_note" else "note"
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="note_added",
            object_type=note_audit_type,
            object_id=note.id,
            details_json={"linked_type": object_type, "linked_id": object_id},
        )
    )
    db.commit()
    flash(request, "Note added.", "success")
    return redirect(_safe_return_to(return_to, _note_return_target(note)))


@app.get("/notes", response_class=HTMLResponse)
def notes_page(
    request: Request,
    q: str = "",
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    query = db.query(models.Note)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(models.Note.title.ilike(like), models.Note.body.ilike(like), models.Note.source.ilike(like)))
    notes = query.order_by(models.Note.updated_at.desc()).limit(200).all()
    note_tags = tag_map(db, "quick_note")
    for note_id, values in tag_map(db, "note").items():
        note_tags.setdefault(note_id, []).extend(values)
    return render(request, "notes.html", {"notes": notes, "q": q, "tags": note_tags}, user=user)


@app.get("/notes/{note_id}", response_class=HTMLResponse)
def note_detail_page(
    request: Request,
    note_id: int,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    note = db.get(models.Note, note_id)
    if not note:
        raise HTTPException(404, "Note not found.")
    target, href = _note_target_label(db, note)
    return render(
        request,
        "note_detail.html",
        {
            "note": note,
            "target": target,
            "target_href": href,
            "tag_text": ", ".join(tags_for(db, "quick_note" if note.object_type == "quick_note" else "note", note.id)),
        },
        user=user,
    )


@app.get("/notes/{note_id}/edit", response_class=HTMLResponse)
def note_edit_page(
    request: Request,
    note_id: int,
    return_to: str = "",
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    note = db.get(models.Note, note_id)
    if not note:
        raise HTTPException(404, "Note not found.")
    target, href = _note_target_label(db, note)
    return render(
        request,
        "note_form.html",
        {"note": note, "target": target, "target_href": href, "return_to": _safe_return_to(return_to, _note_return_target(note))},
        user=user,
    )


@app.post("/notes/{note_id}/edit")
def note_update(
    request: Request,
    note_id: int,
    csrf: str = Form(...),
    title: str = Form(""),
    body: str = Form(...),
    return_to: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    note = db.get(models.Note, note_id)
    if not note:
        raise HTTPException(404, "Note not found.")
    note.title = title.strip()
    note.body = body
    note_audit_type = "quick_note" if note.object_type == "quick_note" else "note"
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="note_edited",
            object_type=note_audit_type,
            object_id=note.id,
            details_json={"linked_type": note.object_type, "linked_id": note.object_id},
        )
    )
    db.commit()
    flash(request, "Note saved.", "success")
    return redirect(_safe_return_to(return_to, f"/notes/{note.id}"))


@app.post("/notes/{note_id}/tags")
def note_tags_update(
    request: Request,
    note_id: int,
    csrf: str = Form(...),
    tags: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    note = db.get(models.Note, note_id)
    if not note:
        raise HTTPException(404, "Note not found.")
    tag_object_type = "quick_note" if note.object_type == "quick_note" else "note"
    set_tags(db, tag_object_type, note.id, tags)
    db.add(models.AuditLog(user_id=user.id, action="note_tags_updated", object_type=tag_object_type, object_id=note.id))
    db.commit()
    flash(request, "Note tags saved.", "success")
    return redirect(request.headers.get("referer") or "/notes")


@app.get("/smart-paste", response_class=HTMLResponse)
def smart_paste_page(
    request: Request,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    return render(
        request,
        "smart_paste.html",
        {
            "inventory_command": INVENTORY_COMMAND,
            "devices": _device_order_query(db).all(),
        },
        user=user,
    )


@app.post("/smart-paste", response_class=HTMLResponse)
def smart_paste_parse(
    request: Request,
    csrf: str = Form(...),
    raw_text: str = Form(...),
    source_type: str = Form("raw_text"),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    check_csrf(request, csrf)
    ensure_writable()
    parsed = _annotate_import_suggestions(db, _safe_parse_smart_paste(raw_text))
    if parsed.get("parse_warning"):
        flash(request, str(parsed["parse_warning"]), "warning")
    safe_raw_text, secrets_redacted = _redact_sensitive_text(raw_text, parsed)
    record = models.ImportRecord(
        source_type=source_type,
        raw_text=safe_raw_text,
        parsed_json=_secure_parsed_for_storage(parsed),
        status="review",
    )
    db.add(record)
    db.flush()
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="smart_paste_parsed",
            object_type="import",
            object_id=record.id,
            details_json={"secrets_redacted": secrets_redacted},
        )
    )
    db.commit()
    return redirect(f"/smart-paste/{record.id}")


@app.post("/quick-note")
def quick_note_parse(
    request: Request,
    csrf: str = Form(...),
    raw_text: str = Form(...),
    title: str = Form(""),
    tags: str = Form(""),
    action: str = Form("save"),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    parsed = _annotate_import_suggestions(db, _safe_parse_smart_paste(raw_text))
    if parsed.get("parse_warning"):
        flash(request, str(parsed["parse_warning"]), "warning")
    safe_raw_text, secrets_redacted = _redact_sensitive_text(raw_text, parsed)
    note = models.Note(
        object_type="quick_note",
        object_id=0,
        title=title.strip() or "Quick note",
        body=safe_raw_text,
        source="quick_note",
    )
    db.add(note)
    db.flush()
    set_tags(db, "quick_note", note.id, tags)
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="quick_note_saved",
            object_type="quick_note",
            object_id=note.id,
            details_json={"secrets_redacted": secrets_redacted},
        )
    )
    if action != "smart_paste":
        db.commit()
        flash(request, "Quick note saved.", "success")
        return redirect(request.headers.get("referer") or "/notes")
    record = models.ImportRecord(
        source_type="quick_note",
        raw_text=safe_raw_text,
        parsed_json=_secure_parsed_for_storage(parsed),
        status="review",
    )
    db.add(record)
    db.flush()
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="quick_note_parsed",
            object_type="import",
            object_id=record.id,
            details_json={"secrets_redacted": secrets_redacted},
        )
    )
    db.commit()
    return redirect(f"/smart-paste/{record.id}")


@app.get("/smart-paste/{import_id}", response_class=HTMLResponse)
def smart_paste_review(
    request: Request,
    import_id: int,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    record = db.get(models.ImportRecord, import_id)
    if not record:
        raise HTTPException(404, "Import not found.")
    return render(
        request,
        "smart_paste_review.html",
        {
            "record": record,
            "parsed": _annotate_import_suggestions(db, _decrypted_parsed(record)),
            "devices": _device_order_query(db).all(),
            "services": _service_order_query(db).all(),
        },
        user=user,
    )


@app.post("/smart-paste/{import_id}/apply")
async def smart_paste_apply(
    request: Request,
    import_id: int,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    form = await request.form()
    check_csrf(request, str(form.get("csrf", "")))
    ensure_writable()
    record = db.get(models.ImportRecord, import_id)
    if not record:
        raise HTTPException(404, "Import not found.")
    parsed = _decrypted_parsed(record)
    target_raw = str(form.get("target_device_id", "new"))
    apply_device = bool(form.get("apply_device"))
    has_selected_items = any(
        form.getlist(name)
        for name in ["services", "ports", "urls", "commands", "credentials", "tokens", "delete_missing_services"]
    ) or bool(form.get("apply_hardware")) or apply_device
    if not has_selected_items:
        record.status = "reviewed"
        db.add(models.AuditLog(user_id=user.id, action="smart_paste_reviewed_no_changes", object_type="import", object_id=record.id))
        db.commit()
        flash(request, "Smart Paste review saved with no changes applied.", "success")
        return redirect("/smart-paste")
    selected_url_indexes = [str(value) for value in form.getlist("urls")]
    unlinked_url_selected = any(not str(form.get(f"url_service_{index}") or "").strip().isdigit() for index in selected_url_indexes)
    device_bound_selected = any(
        form.getlist(name)
        for name in ["services", "ports", "credentials", "service_credentials", "service_urls", "delete_missing_services"]
    ) or unlinked_url_selected or bool(form.get("apply_hardware"))
    if target_raw == "new" and device_bound_selected and not apply_device:
        flash(
            request,
            "Nothing was applied. Choose an existing device, or check Create/update this device before importing services, ports, URLs, credentials, or hardware.",
            "warning",
        )
        return redirect(f"/smart-paste/{record.id}")
    requires_device = device_bound_selected or target_raw != "new" or apply_device
    if not requires_device and (form.getlist("tokens") or form.getlist("commands") or form.getlist("urls")):
        created_tokens = 0
        for index_raw in form.getlist("tokens"):
            if _create_token_credential_from_import(db, user, form, parsed, str(index_raw), record, None):
                created_tokens += 1
        created_urls = _apply_loose_urls_from_import(db, form, parsed, record, None)
        created_commands = 0
        for index_raw in form.getlist("commands"):
            item = parsed.get("commands", [])[int(index_raw)]
            command_text = str(form.get(f"command_text_{index_raw}") or item["command_template"]).strip()
            if not command_text or _duplicate_command(db, command_text):
                continue
            applies_to_type = str(form.get(f"command_applies_to_type_{index_raw}") or "generic")
            if applies_to_type == "device":
                applies_to_type = "generic"
            db.add(
                models.Command(
                    name=str(form.get(f"command_name_{index_raw}") or item["name"]),
                    category=str(form.get(f"command_category_{index_raw}") or "Imported"),
                    applies_to_type=applies_to_type,
                    applies_to_id=None,
                    command_template=command_text,
                    where_to_run=str(form.get(f"command_where_{index_raw}") or "Remote SSH host"),
                    risk_level=str(form.get(f"command_risk_{index_raw}") or "safe"),
                    help_low=str(form.get(f"command_help_low_{index_raw}") or "Imported from pasted notes. Review before running."),
                    help_high="This command was detected by Smart Paste. Confirm the folder, host, and intent before copying.",
                    notes=str(form.get(f"command_notes_{index_raw}") or f"Imported from Smart Paste {record.id}."),
                )
            )
            created_commands += 1
        record.status = "applied"
        db.add(models.AuditLog(user_id=user.id, action="smart_paste_applied", object_type="import", object_id=record.id, details_json={"tokens": created_tokens, "commands": created_commands, "urls": created_urls}))
        db.commit()
        flash(request, f"Stored {created_tokens} token/API item(s), {created_commands} command(s), and {created_urls} URL(s).", "success")
        return redirect("/commands" if created_commands else "/tokens" if created_tokens else "/ports")
    device: models.Device | None = None
    if target_raw and target_raw != "new":
        device = db.get(models.Device, int(target_raw))
    if device is None:
        detected = parsed.get("device", {})
        name = str(form.get("device_name") or detected.get("name") or "Imported Device").strip()
        device = models.Device(
            name=name,
            slug=unique_slug(db, models.Device, name),
            type="server",
            primary_ip=str(form.get("device_ip") or detected.get("primary_ip", "")),
            os_name=str(form.get("device_os") or detected.get("os_name", "")),
            display_order=_next_device_order(db),
        )
        db.add(device)
        db.flush()
        _ensure_device_hardware(db, device)
    else:
        overwrite_identity = form.get("update_device_identity") == "on"
        if apply_device and overwrite_identity and form.get("device_name"):
            new_device_name = str(form.get("device_name")).strip()
            if new_device_name and new_device_name.lower() != device.name.lower():
                device.name = new_device_name
                device.slug = unique_slug(db, models.Device, device.name, existing_id=device.id)
        if apply_device and form.get("device_ip") and (overwrite_identity or not device.primary_ip):
            device.primary_ip = str(form.get("device_ip")).strip()
        if apply_device and form.get("device_os") and (overwrite_identity or not device.os_name):
            device.os_name = str(form.get("device_os")).strip()
    note_body, secrets_redacted = _redact_sensitive_text(record.raw_text, parsed)
    db.add(
        models.Note(
            object_type="device",
            object_id=device.id,
            title="Original Smart Paste import" + (" (secrets redacted)" if secrets_redacted else ""),
            body=note_body,
            source=f"smart_paste:{record.id}",
        )
    )
    extras = parsed.get("extras", {})
    if apply_device and form.get("apply_hardware"):
        hardware = _ensure_device_hardware(db, device)
        if extras.get("model_summary") and not hardware.model:
            hardware.model = extras["model_summary"]
        if extras.get("cpu_summary") and not hardware.cpu:
            hardware.cpu = extras["cpu_summary"]
        if extras.get("memory_summary") and not hardware.ram:
            hardware.ram = extras["memory_summary"]
        if extras.get("disk_summary") and not hardware.storage_summary:
            hardware.storage_summary = extras["disk_summary"]
    for index_raw in form.getlist("services"):
        item = parsed.get("services", [])[int(index_raw)]
        service_name = str(form.get(f"service_name_{index_raw}") or item["name"]).strip()
        if not service_name:
            continue
        exists = _match_service_for_import(db, device.id, {**item, "name": service_name})
        if not exists:
            exists = models.Service(
                device_id=device.id,
                name=service_name,
                slug=slugify(service_name),
                docker_project=str(form.get(f"service_group_{index_raw}") or item.get("stack_group", "")),
                compose_path=str(form.get(f"service_compose_{index_raw}") or item.get("compose_path", "")),
                container_name=item.get("container_name", ""),
                image=item.get("image", ""),
                notes=f"Imported from Smart Paste {record.id}.",
            )
            db.add(exists)
            db.flush()
        else:
            group_value = str(form.get(f"service_group_{index_raw}") or item.get("stack_group", "")).strip()
            compose_value = str(form.get(f"service_compose_{index_raw}") or item.get("compose_path", "")).strip()
            if group_value and not exists.docker_project:
                exists.docker_project = group_value
            if compose_value and not exists.compose_path:
                exists.compose_path = compose_value
            container_value = str(item.get("container_name", "") or "").strip()
            image_value = str(item.get("image", "") or "").strip()
            if container_value and not exists.container_name:
                exists.container_name = container_value
            if image_value and not exists.image:
                exists.image = image_value
            elif image_value and _image_repo(exists.image) and _image_repo(exists.image) == _image_repo(image_value):
                exists.image = image_value
        merge_tags(db, "service", exists.id, _infer_tags_for_service(exists))
        for url_value_raw in form.getlist("service_urls"):
            try:
                service_index_value, url_index_raw = str(url_value_raw).split(":", 1)
            except ValueError:
                continue
            if service_index_value != str(index_raw):
                continue
            try:
                url_item = item.get("urls", [])[int(url_index_raw)]
            except (IndexError, ValueError):
                continue
            url_value = str(form.get(f"service_url_{index_raw}_{url_index_raw}") or url_item.get("url", "")).strip()
            if not url_value:
                continue
            url_type = str(url_item.get("url_type", "local"))
            primary_attr = "public_url" if url_type == "public" else "local_url"
            current_primary = str(getattr(exists, primary_attr) or "").strip()
            if not current_primary:
                setattr(exists, primary_attr, url_value)
            duplicate_url = _duplicate_url_record(db, url_value)
            duplicate_service = _duplicate_service_url(db, device.id, url_value)
            if not duplicate_url and not duplicate_service:
                url_notes = f"Imported from Smart Paste {record.id}."
                if url_item.get("source_label"):
                    url_notes += f" Source: {url_item['source_label']}."
                db.add(
                    models.Url(
                        device_id=device.id,
                        service_id=exists.id,
                        label=service_name,
                        url=url_value,
                        url_type=url_type,
                        notes=url_notes,
                    )
                )
        for port_value in form.getlist(f"service_port_{index_raw}"):
            try:
                _, host_port, protocol = str(port_value).split(":", 2)
            except ValueError:
                continue
            if not host_port.isdigit():
                continue
            port_item = next(
                (
                    port
                    for port in item.get("ports", [])
                    if str(port.get("host_port")) == host_port and str(port.get("protocol", "tcp")) == protocol
                ),
                {},
            )
            duplicate = (
                db.query(models.Port)
                .filter(
                    models.Port.device_id == device.id,
                    models.Port.service_id == exists.id,
                    models.Port.host_port == int(host_port),
                    models.Port.protocol == protocol,
                )
                .first()
            )
            if not duplicate:
                db.add(
                    models.Port(
                        device_id=device.id,
                        service_id=exists.id,
                        internal_port=int(port_item["internal_port"]) if str(port_item.get("internal_port", "")).isdigit() else None,
                        host_port=int(host_port),
                        protocol=protocol,
                        purpose=service_name,
                        notes=f"Imported from Smart Paste {record.id}.",
                    )
                )
        for credential_value in form.getlist("service_credentials"):
            try:
                service_index_value, credential_index_raw = str(credential_value).split(":", 1)
            except ValueError:
                continue
            if service_index_value != str(index_raw):
                continue
            try:
                credential_item = item.get("credentials", [])[int(credential_index_raw)]
            except (IndexError, ValueError):
                continue
            label = str(form.get(f"service_credential_label_{index_raw}_{credential_index_raw}") or credential_item.get("label") or f"{service_name} login").strip()
            username = str(form.get(f"service_credential_username_{index_raw}_{credential_index_raw}") or credential_item.get("username", "")).strip()
            secret = str(form.get(f"service_credential_secret_{index_raw}_{credential_index_raw}") or credential_item.get("secret", "")).strip()
            login_url = str(form.get(f"service_credential_login_url_{index_raw}_{credential_index_raw}") or credential_item.get("login_url", "") or exists.local_url or exists.public_url).strip()
            if not label or not secret:
                continue
            if _duplicate_credential(db, device_id=device.id, service_id=exists.id, label=label, username=username):
                continue
            credential = models.Credential(
                device_id=device.id,
                service_id=exists.id,
                label=label,
                username=username,
                secret_encrypted=encrypt_text(secret),
                secret_type="password",
                security_level=str(credential_item.get("security_level", "medium")),
                login_url=login_url,
                notes=f"Imported from Smart Paste {record.id}.",
                last_changed_at=now_utc(),
                active=True,
            )
            db.add(credential)
            db.flush()
            endpoint_sync = _sync_credential_login_endpoint(db, credential, default_device=device)
            db.add(
                models.AuditLog(
                    user_id=user.id,
                    action="credential_created",
                    object_type="credential",
                    object_id=credential.id,
                    details_json={"source": f"smart_paste:{record.id}", **endpoint_sync},
                )
            )
    for index_raw in form.getlist("ports"):
        item = parsed.get("ports", [])[int(index_raw)]
        host_port = str(form.get(f"port_host_{index_raw}") or item["host_port"]).strip()
        if not host_port.isdigit():
            continue
        protocol = str(form.get(f"port_protocol_{index_raw}") or item.get("protocol", "tcp"))
        duplicate = (
            db.query(models.Port)
            .filter(
                models.Port.device_id == device.id,
                models.Port.host_port == int(host_port),
                models.Port.protocol == protocol,
            )
            .first()
        )
        if not duplicate:
            port = models.Port(
                device_id=device.id,
                host_port=int(host_port),
                protocol=protocol,
                purpose=str(form.get(f"port_purpose_{index_raw}") or item.get("purpose", "")),
                notes=f"Imported from Smart Paste {record.id}.",
            )
            db.add(port)
            db.flush()
            port_tags = str(form.get(f"port_tags_{index_raw}") or item.get("tags", ""))
            if port_tags:
                set_tags(db, "port", port.id, port_tags)
                merge_tags(db, "device", device.id, port_tags)
    _apply_loose_urls_from_import(db, form, parsed, record, device)
    for index_raw in form.getlist("commands"):
        item = parsed.get("commands", [])[int(index_raw)]
        command_text = str(form.get(f"command_text_{index_raw}") or item["command_template"]).strip()
        if not command_text:
            continue
        if _duplicate_command(db, command_text):
            continue
        applies_to_type = str(form.get(f"command_applies_to_type_{index_raw}") or "device")
        applies_to_id = device.id if applies_to_type == "device" else None
        db.add(
            models.Command(
                name=str(form.get(f"command_name_{index_raw}") or item["name"]),
                category=str(form.get(f"command_category_{index_raw}") or "Imported"),
                applies_to_type=applies_to_type,
                applies_to_id=applies_to_id,
                command_template=command_text,
                where_to_run=str(form.get(f"command_where_{index_raw}") or "Remote SSH host"),
                risk_level=str(form.get(f"command_risk_{index_raw}") or "safe"),
                help_low=str(form.get(f"command_help_low_{index_raw}") or "Imported from pasted notes. Review before running."),
                help_high="This command was detected by Smart Paste. Confirm the folder, host, and intent before copying.",
                notes=str(form.get(f"command_notes_{index_raw}") or f"Imported from Smart Paste {record.id}."),
            )
        )
    for index_raw in form.getlist("credentials"):
        item = parsed.get("credentials", [])[int(index_raw)]
        label = str(form.get(f"credential_label_{index_raw}") or item.get("label") or "Imported login").strip()
        username = str(form.get(f"credential_username_{index_raw}") or item.get("username", "")).strip()
        secret = str(form.get(f"credential_secret_{index_raw}") or item.get("secret", "")).strip()
        service_name = str(form.get(f"credential_service_{index_raw}") or item.get("service_name", "")).strip()
        login_url = str(form.get(f"credential_login_url_{index_raw}") or item.get("login_url", "")).strip()
        security_level = str(form.get(f"credential_security_{index_raw}") or item.get("security_level", "medium")).strip()
        if not label or not secret:
            continue
        resolved_device_id, resolved_service_id, error = _resolve_service_for_credential(
            db,
            device_id=device.id,
            service_id=None,
            service_name=service_name,
            label=label,
        )
        if error:
            resolved_device_id, resolved_service_id = device.id, None
        if _duplicate_credential(
            db,
            device_id=resolved_device_id or device.id,
            service_id=resolved_service_id,
            label=label,
            username=username,
        ):
            continue
        credential = models.Credential(
            device_id=resolved_device_id or device.id,
            service_id=resolved_service_id,
            label=label,
            username=username,
            secret_encrypted=encrypt_text(secret),
            secret_type="password",
            security_level=security_level if security_level in {"low", "medium", "high", "extreme"} else "medium",
            login_url=login_url,
            notes=f"Imported from Smart Paste {record.id}.",
            last_changed_at=now_utc(),
            active=True,
        )
        db.add(credential)
        db.flush()
        endpoint_sync = _sync_credential_login_endpoint(db, credential, default_device=device)
        db.add(
            models.AuditLog(
                user_id=user.id,
                action="credential_created",
                object_type="credential",
                object_id=credential.id,
                details_json={"source": f"smart_paste:{record.id}", **endpoint_sync},
            )
        )
    for index_raw in form.getlist("tokens"):
        _create_token_credential_from_import(db, user, form, parsed, str(index_raw), record, device)
    deleted_missing_services = 0
    for service_id_raw in form.getlist("delete_missing_services"):
        if not str(service_id_raw).isdigit():
            continue
        service = db.get(models.Service, int(service_id_raw))
        if not service or service.device_id != device.id:
            continue
        details = {
            "source": f"smart_paste:{record.id}",
            "reason": "not_seen_in_latest_docker_paste",
            "name": service.name,
            "credentials": len(service.credentials),
            "ports": len(service.ports),
            "urls": len(service.urls),
        }
        _delete_service_tree(db, service)
        db.add(
            models.AuditLog(
                user_id=user.id,
                action="service_deleted",
                object_type="service",
                object_id=int(service_id_raw),
                details_json=details,
            )
        )
        deleted_missing_services += 1
    record.status = "applied"
    merge_tags(db, "device", device.id, _infer_tags_for_device(device))
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="smart_paste_applied",
            object_type="import",
            object_id=record.id,
            details_json={"deleted_missing_services": deleted_missing_services} if deleted_missing_services else {},
        )
    )
    db.commit()
    flash(request, f"Smart Paste applied to {device.name}. Original text was preserved as a note.", "success")
    return redirect(f"/devices/{device.id}")


@app.get("/suggestions", response_class=HTMLResponse)
def suggestions_page(
    request: Request,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    fill_candidates: list[dict[str, Any]] = []
    for device in _device_order_query(db).limit(20).all():
        missing = []
        if not device.purpose.strip():
            missing.append("purpose")
        if not tags_for(db, "device", device.id):
            missing.append("tags")
        if missing:
            fill_candidates.append(
                {
                    "type": "Device",
                    "name": device.name,
                    "href": f"/devices/{device.id}/edit?focus={missing[0]}",
                    "missing": missing,
                    "suggested": _device_auto_purpose(device) or _infer_tags_for_device(device),
                }
            )
    for service in _service_order_query(db).limit(40).all():
        missing = []
        if not service.purpose.strip():
            missing.append("purpose")
        if not service.backup_path and "backup" not in service.notes.lower():
            missing.append("backup")
        if not tags_for(db, "service", service.id):
            missing.append("tags")
        if missing:
            fill_candidates.append(
                {
                    "type": "Service",
                    "name": service.name,
                    "href": f"/services/{service.id}/edit?focus={'backup_path' if missing[0] == 'backup' else missing[0]}",
                    "missing": missing,
                    "suggested": _infer_tags_for_service(service),
                }
            )
    return render(
        request,
        "suggestions.html",
        {
            "suggestions": visible_suggestions(db),
            "tag_ideas": TAG_IDEAS,
            "fill_candidates": fill_candidates[:40],
            "devices": _device_order_query(db).all(),
            "services": _service_order_query(db).all(),
            "custom_suggestions": db.query(models.UserSuggestion)
            .order_by(models.UserSuggestion.done, models.UserSuggestion.due_at, models.UserSuggestion.created_at.desc())
            .limit(50)
            .all(),
            "suggestion_tags": tag_map(db, "user_suggestion"),
        },
        user=user,
    )


@app.get("/suggestion-images/{suggestion_id}/file")
def suggestion_image_file(
    suggestion_id: int,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> FileResponse:
    suggestion = db.get(models.UserSuggestion, suggestion_id)
    if not suggestion or not suggestion.image_filename:
        raise HTTPException(404, "Suggestion image not found.")
    path = _stored_upload_path(SUGGESTION_IMAGE_DIR, suggestion.image_filename)
    if not path.exists() or not path.is_file():
        raise HTTPException(404, "Suggestion image file not found.")
    return FileResponse(
        path,
        media_type=suggestion.image_mime_type or "application/octet-stream",
        filename=suggestion.image_original_filename or Path(suggestion.image_filename).name,
    )


@app.post("/suggestions/custom")
async def suggestions_custom_create(
    request: Request,
    csrf: str = Form(...),
    title: str = Form(...),
    subtitle: str = Form(""),
    due_at: str = Form(""),
    severity: str = Form("info"),
    target: str = Form(""),
    tags: str = Form(""),
    notes: str = Form(""),
    image_file: UploadFile | None = File(None),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    clean_title = title.strip()
    if not clean_title:
        flash(request, "Custom suggestions need a title.", "warning")
        return redirect("/suggestions#custom-suggestion-form")
    object_type = ""
    object_id: int | None = None
    if ":" in target:
        target_type, target_id = target.split(":", 1)
        if target_type in {"device", "service"} and target_id.isdigit():
            model = models.Device if target_type == "device" else models.Service
            if db.get(model, int(target_id)):
                object_type = target_type
                object_id = int(target_id)
    image_data: dict[str, Any] = {}
    if image_file and image_file.filename:
        try:
            saved = await _save_image_upload(image_file, SUGGESTION_IMAGE_DIR)
        except ValueError as exc:
            flash(request, str(exc), "warning")
            return redirect("/suggestions#custom-suggestion-form")
        image_data = {
            "image_filename": saved["stored_filename"],
            "image_original_filename": saved["original_filename"],
            "image_mime_type": saved["mime_type"],
        }
    suggestion = models.UserSuggestion(
        title=clean_title,
        subtitle=subtitle.strip(),
        due_at=_parse_optional_datetime(due_at),
        severity=severity if severity in {"info", "warning", "danger"} else "info",
        object_type=object_type,
        object_id=object_id,
        notes=notes,
        **image_data,
    )
    db.add(suggestion)
    db.flush()
    set_tags(db, "user_suggestion", suggestion.id, tags)
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="user_suggestion_created",
            object_type="user_suggestion",
            object_id=suggestion.id,
            details_json={"due_at": suggestion.due_at.isoformat() if suggestion.due_at else ""},
        )
    )
    db.commit()
    flash(request, "Custom suggestion saved.", "success")
    return redirect("/suggestions#active-suggestions")


@app.post("/suggestions/apply")
def suggestions_apply(
    request: Request,
    csrf: str = Form(...),
    suggestion_id: str = Form(...),
    action: str = Form(...),
    object_type: str = Form(...),
    object_id: int = Form(...),
    value: str = Form(""),
    mute_event_id: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    cleaned = value.strip()
    if action == "user-suggestion-done" and object_type == "user_suggestion":
        suggestion = db.get(models.UserSuggestion, object_id)
        if not suggestion:
            raise HTTPException(404, "Suggestion not found.")
        suggestion.done = True
        dismiss_suggestion(db, suggestion_id)
        db.add(
            models.AuditLog(
                user_id=user.id,
                action="user_suggestion_done",
                object_type="user_suggestion",
                object_id=suggestion.id,
            )
        )
        db.commit()
        flash(request, "Custom suggestion marked done.", "success")
        return redirect("/suggestions#custom-suggestions")
    if action == "mute-ping":
        if not mute_event_id:
            flash(request, "That check warning could not be marked known down.", "warning")
            return redirect((request.headers.get("referer") or "/suggestions") + "#active-suggestions")
        mute_ping_failure(db, suggestion_id, mute_event_id)
        db.add(
            models.AuditLog(
                user_id=user.id,
                action="ping_warning_known_down",
                object_type=object_type,
                object_id=object_id,
                details_json={"id": suggestion_id, "event_id": mute_event_id},
            )
        )
        db.commit()
        flash(request, "Check warning marked known down and hidden from suggestions.", "success")
        return redirect((request.headers.get("referer") or "/suggestions") + "#active-suggestions")
    if action == "duplicate-port-cleanup" and object_type == "port":
        match = re.match(r"device:(\d+):port:(\d+):([^:]+):duplicate", suggestion_id)
        if not match:
            flash(request, "That duplicate-port suggestion could not be read.", "warning")
            return redirect((request.headers.get("referer") or "/suggestions") + "#active-suggestions")
        device_id, host_port, protocol = int(match.group(1)), int(match.group(2)), match.group(3)
        matches = (
            db.query(models.Port)
            .filter(
                models.Port.device_id == device_id,
                models.Port.host_port == host_port,
                models.Port.protocol == protocol,
            )
            .order_by(models.Port.service_id.is_(None), models.Port.id)
            .all()
        )
        keep = next((port for port in matches if port.service_id), matches[0] if matches else None)
        removed = 0
        if keep:
            for port in matches:
                if port.id == keep.id:
                    continue
                if not port.service_id or port.service_id == keep.service_id:
                    db.delete(port)
                    removed += 1
        if not removed:
            flash(request, "No loose duplicate port was safe to remove. Open Ports & URLs to choose manually.", "warning")
            return redirect("/ports")
        dismiss_suggestion(db, suggestion_id)
        db.add(
            models.AuditLog(
                user_id=user.id,
                action="suggestion_applied",
                object_type="port",
                object_id=keep.id if keep else None,
                details_json={"id": suggestion_id, "action": action, "removed": removed},
            )
        )
        db.commit()
        flash(request, f"Removed {removed} loose duplicate port entr{'y' if removed == 1 else 'ies'}.", "success")
        return redirect("/ports")
    if not cleaned:
        flash(request, "Add a little text before applying that suggestion.", "warning")
        return redirect((request.headers.get("referer") or "/suggestions") + "#active-suggestions")
    target = ""
    if action == "service-purpose" and object_type == "service":
        service = db.get(models.Service, object_id)
        if not service:
            raise HTTPException(404, "Service not found.")
        service.purpose = cleaned
        merge_tags(db, "service", service.id, _infer_tags_for_service(service))
        merge_tags(db, "device", service.device_id, _infer_tags_for_device(service.device))
        target = f"/services/{service.id}"
    elif action == "service-backup" and object_type == "service":
        service = db.get(models.Service, object_id)
        if not service:
            raise HTTPException(404, "Service not found.")
        if cleaned.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:\\", cleaned):
            service.backup_path = cleaned
        else:
            prefix = "\n" if service.notes.strip() else ""
            service.notes = f"{service.notes.rstrip()}{prefix}Backup notes: {cleaned}"
        merge_tags(db, "service", service.id, "backup-documented")
        target = f"/services/{service.id}"
    elif action == "device-purpose" and object_type == "device":
        device = db.get(models.Device, object_id)
        if not device:
            raise HTTPException(404, "Device not found.")
        device.purpose = cleaned
        merge_tags(db, "device", device.id, _infer_tags_for_device(device))
        target = f"/devices/{device.id}"
    else:
        flash(request, "That suggestion action is not available yet.", "warning")
        return redirect((request.headers.get("referer") or "/suggestions") + "#active-suggestions")
    dismiss_suggestion(db, suggestion_id)
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="suggestion_applied",
            object_type=object_type,
            object_id=object_id,
            details_json={"id": suggestion_id, "action": action},
        )
    )
    db.commit()
    flash(request, "Suggestion applied.", "success")
    return redirect(target)


@app.post("/suggestions/dismiss")
def suggestions_dismiss(
    request: Request,
    csrf: str = Form(...),
    suggestion_id: str = Form(...),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    dismiss_suggestion(db, suggestion_id)
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="suggestion_dismissed",
            object_type="suggestion",
            details_json={"id": suggestion_id},
        )
    )
    db.commit()
    flash(request, "Suggestion dismissed.", "success")
    referer = request.headers.get("referer") or "/suggestions"
    if "/suggestions" in referer and "#" not in referer:
        referer = f"{referer}#active-suggestions"
    return redirect(referer)


@app.get("/settings", response_class=HTMLResponse)
def settings_page(
    request: Request,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    pending_totp_secret = ""
    pending_totp_uri = ""
    pending_totp_qr_svg = ""
    if user.totp_secret_encrypted and not user.totp_enabled:
        pending_totp_secret = decrypt_text(user.totp_secret_encrypted)
        pending_totp_uri = pyotp.TOTP(pending_totp_secret).provisioning_uri(
            name=user.username,
            issuer_name=settings.app_name,
        )
        qr_image = qrcode.make(pending_totp_uri, image_factory=qrcode.image.svg.SvgPathImage)
        buffer = io.BytesIO()
        qr_image.save(buffer)
        pending_totp_qr_svg = buffer.getvalue().decode("utf-8")
    totp_scope = _totp_scope(db)
    devices = _device_order_query(db).all()
    security_posture = _security_posture(user, db)
    stats_overview_metric_keys = _stats_overview_metric_keys(db)
    return render(
        request,
        "settings.html",
        {
            "app_settings": get_app_settings(db),
            "pending_totp_secret": pending_totp_secret,
            "pending_totp_uri": pending_totp_uri,
            "pending_totp_qr_svg": pending_totp_qr_svg,
            "devices": devices,
            "device_ping_statuses": _device_ping_status_map(db, devices),
            "webhook_url_saved": bool(_webhook_url(db)),
            "webhook_scope": _webhook_scope(db),
            "webhook_send_recovery": _webhook_recovery_enabled(db),
            "recovery_enabled": _recovery_enabled(db),
            "suggested_recovery_phrase": _suggested_recovery_phrase(),
            "totp_scope": totp_scope,
            "totp_scope_label": _totp_scope_label(totp_scope),
            "security_posture": security_posture,
            "security_posture_counts": _posture_counts(security_posture),
            "theme_preset_groups": _theme_preset_groups(get_app_settings(db).get("theme_preset", THEME_DEFAULTS["theme_preset"])),
            "stats_metric_catalog": _stats_metric_catalog(stats_overview_metric_keys),
            "stats_overview_metric_keys": stats_overview_metric_keys,
        },
        user=user,
    )


@app.post("/settings")
async def settings_save(
    request: Request,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    form = await request.form()
    check_csrf(request, str(form.get("csrf", "")))
    ensure_writable()
    for key in THEME_DEFAULTS:
        if key == "theme_mode":
            continue
        if key == "stats_overview_metrics":
            selected_metrics = _clean_stats_metric_keys(
                [str(item) for item in form.getlist("stats_overview_metrics")],
                limit=4,
            )
            set_app_setting(db, key, ",".join(selected_metrics))
            continue
        value = str(form.get(key, THEME_DEFAULTS[key])).strip()
        if key == "theme_preset":
            value = value if value in THEME_PRESETS else THEME_DEFAULTS[key]
        if key in {"compact_forms", "ping_on_login", "validate_services_on_login"}:
            value = "on" if form.get(key) == "on" else "off"
        if key == "dashboard_recent_limit":
            try:
                value = str(max(3, min(20, int(value))))
            except ValueError:
                value = THEME_DEFAULTS[key]
        if key == "session_timeout_minutes":
            try:
                value = str(max(1, min(999, int(value))))
            except ValueError:
                value = THEME_DEFAULTS[key]
            request.session["session_timeout_minutes"] = int(value)
        if key in {"ping_interval_minutes", "ping_green_ms", "ping_orange_ms"}:
            try:
                value = str(max(1, min(999, int(value))))
            except ValueError:
                value = THEME_DEFAULTS[key]
        if key == "ping_failures_before_warning":
            try:
                value = str(max(1, min(10, int(value))))
            except ValueError:
                value = THEME_DEFAULTS[key]
        if key == "history_retention_days":
            try:
                value = str(max(1, min(99999, int(value))))
            except ValueError:
                value = THEME_DEFAULTS[key]
        if key == "stats_window_hours":
            try:
                value = str(max(1, min(168, int(value))))
            except ValueError:
                value = THEME_DEFAULTS[key]
        if key == "stats_expected_interval_minutes":
            try:
                value = str(max(1, min(1440, int(value))))
            except ValueError:
                value = THEME_DEFAULTS[key]
        if key == "stats_storage_interval_minutes":
            try:
                value = str(max(1, min(1440, int(value))))
            except ValueError:
                value = THEME_DEFAULTS[key]
        if key == "stats_retention_days":
            try:
                value = str(max(1, min(3650, int(value))))
            except ValueError:
                value = THEME_DEFAULTS[key]
        set_app_setting(db, key, value)
    history_removed = _prune_history(db)
    stats_removed = _prune_stats(db)
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="settings_updated",
            object_type="app_settings",
            details_json={"section": "theme", "history_pruned": history_removed, "stats_pruned": stats_removed},
        )
    )
    db.commit()
    message = "Settings saved."
    if history_removed:
        message += f" Deleted {history_removed} old history item(s)."
    if stats_removed:
        message += f" Deleted {stats_removed} expired stats snapshot(s)."
    flash(request, message, "success")
    return redirect("/settings")


@app.post("/settings/webhook")
async def settings_webhook_save(
    request: Request,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    form = await request.form()
    check_csrf(request, str(form.get("csrf", "")))
    ensure_writable()
    try:
        if form.get("clear_webhook") == "on":
            _set_webhook_url(db, "")
        else:
            new_url = str(form.get("webhook_url", "")).strip()
            if new_url:
                _set_webhook_url(db, new_url)
    except ValueError as exc:
        flash(request, str(exc), "warning")
        return redirect("/settings#ping-webhook")
    both = form.get("webhook_scope_both") == "on"
    devices = form.get("webhook_scope_devices") == "on"
    services = form.get("webhook_scope_services") == "on"
    if both or (devices and services) or (not devices and not services):
        scope = "both"
    elif devices:
        scope = "devices"
    else:
        scope = "services"
    set_app_setting(db, WEBHOOK_SCOPE_SETTING, scope)
    set_app_setting(db, WEBHOOK_RECOVERY_SETTING, "on" if form.get("webhook_send_recovery") == "on" else "off")
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="webhook_settings_updated",
            object_type="app_settings",
            details_json={"scope": scope, "send_recovery": form.get("webhook_send_recovery") == "on"},
        )
    )
    db.commit()
    flash(request, "Webhook settings saved.", "success")
    return redirect("/settings#ping-webhook")


@app.post("/settings/webhook/test")
def settings_webhook_test(
    request: Request,
    csrf: str = Form(...),
    event: str = Form(...),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    status_text = "pass" if event == "pass" else "fail"
    sent = _send_webhook_payload(
        db,
        {
            "event": "webhook_test",
            "object_type": "test",
            "status": status_text,
            "name": f"Test {status_text}",
            "message": f"Kairix Opsbook test {status_text} webhook from {settings.instance_name}.",
        },
    )
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="webhook_test",
            object_type="app_settings",
            details_json={"status": status_text, "sent": sent},
        )
    )
    db.commit()
    flash(request, f"Webhook test {status_text} {'sent' if sent else 'could not be sent. Check the saved URL'}.", "success" if sent else "warning")
    return redirect("/settings#ping-webhook")


@app.post("/settings/device-order")
async def settings_device_order(
    request: Request,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    form = await request.form()
    check_csrf(request, str(form.get("csrf", "")))
    ensure_writable()
    for device in db.query(models.Device).all():
        raw_value = str(form.get(f"device_order_{device.id}", device.display_order)).strip()
        try:
            device.display_order = max(0, min(999999, int(raw_value)))
        except ValueError:
            continue
    db.add(models.AuditLog(user_id=user.id, action="device_order_updated", object_type="settings"))
    db.commit()
    flash(request, "Device order saved.", "success")
    return redirect("/settings")


@app.post("/settings/security/password")
def settings_password_change(
    request: Request,
    csrf: str = Form(...),
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    if not _account_password_ok_and_upgrade(db, user, current_password):
        flash(request, "Current password was incorrect.", "danger")
        return redirect("/settings#password-security")
    if new_password != confirm_password:
        flash(request, "New passwords did not match.", "warning")
        return redirect("/settings#password-security")
    if len(new_password) < 10:
        flash(request, "Use at least 10 characters for the new password.", "warning")
        return redirect("/settings#password-security")
    user.password_hash = hash_password(new_password)
    db.add(models.AuditLog(user_id=user.id, action="password_changed", object_type="user", object_id=user.id))
    db.commit()
    flash(request, "Password changed.", "success")
    return redirect("/settings#password-security")


@app.post("/settings/security/reveal-pin")
def settings_reveal_pin_change(
    request: Request,
    csrf: str = Form(...),
    current_password: str = Form(...),
    new_reveal_pin: str = Form(""),
    confirm_reveal_pin: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    if not _account_password_ok_and_upgrade(db, user, current_password):
        flash(request, "Account password was incorrect.", "danger")
        return redirect("/settings#password-security")
    if new_reveal_pin != confirm_reveal_pin:
        flash(request, "Reveal password or PIN values did not match.", "warning")
        return redirect("/settings#password-security")
    if new_reveal_pin and len(new_reveal_pin) < 6:
        flash(request, "Use at least 6 characters for a reveal password or PIN.", "warning")
        return redirect("/settings#password-security")
    user.secondary_password_hash = hash_password(new_reveal_pin) if new_reveal_pin else None
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="reveal_pin_changed" if new_reveal_pin else "reveal_pin_removed",
            object_type="user",
            object_id=user.id,
        )
    )
    db.commit()
    flash(request, "Reveal password or PIN updated." if new_reveal_pin else "Reveal password or PIN removed.", "success")
    return redirect("/settings#password-security")


@app.post("/settings/security/hash-upgrade")
def settings_hash_upgrade(
    request: Request,
    csrf: str = Form(...),
    current_password: str = Form(...),
    reveal_password: str = Form(""),
    recovery_phrase: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    if not verify_password(current_password, user.password_hash):
        flash(request, "Account password was incorrect.", "danger")
        return redirect("/settings#password-security")

    reveal_value = reveal_password.strip()
    recovery_value = recovery_phrase.strip()
    recovery_hash = _recovery_phrase_hash(db)
    if reveal_value:
        if not user.secondary_password_hash:
            flash(request, "No separate reveal password is configured.", "warning")
            return redirect("/settings#password-security")
        if not verify_password(reveal_value, user.secondary_password_hash):
            flash(request, "Reveal password or PIN did not match.", "danger")
            return redirect("/settings#password-security")
    if recovery_value:
        if not recovery_hash:
            flash(request, "No recovery phrase is configured.", "warning")
            return redirect("/settings#password-security")
        if not verify_password(recovery_value, recovery_hash):
            flash(request, "Recovery phrase did not match.", "danger")
            return redirect("/settings#password-security")

    upgraded: list[str] = []
    if _upgrade_hash_if_needed(db, user, current_password):
        upgraded.append("account password")
    if reveal_value and _upgrade_hash_if_needed(db, user, reveal_value, field="secondary_password_hash"):
        upgraded.append("reveal password")
    if recovery_value and password_hash_needs_upgrade(recovery_hash):
        set_app_setting(db, RECOVERY_PHRASE_HASH_SETTING, hash_password(recovery_value))
        db.add(
            models.AuditLog(
                user_id=user.id,
                action="recovery_hash_upgraded",
                object_type="user",
                object_id=user.id,
            )
        )
        upgraded.append("recovery phrase")
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="security_hash_upgrade_checked",
            object_type="user",
            object_id=user.id,
            details_json={"upgraded": upgraded, "checked_reveal": bool(reveal_value), "checked_recovery": bool(recovery_value)},
        )
    )
    db.commit()
    if upgraded:
        flash(request, f"Upgraded {', '.join(upgraded)} hash strength.", "success")
    else:
        flash(request, "No legacy hashes needed upgrading for the values you entered.", "success")
    return redirect("/settings#password-security")


@app.post("/settings/security/recovery")
def settings_recovery_change(
    request: Request,
    csrf: str = Form(...),
    current_password: str = Form(...),
    recovery_phrase: str = Form(""),
    confirm_recovery_phrase: str = Form(""),
    clear_recovery: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    if not _account_password_ok_and_upgrade(db, user, current_password):
        flash(request, "Account password was incorrect.", "danger")
        return redirect("/settings#account-security")
    if clear_recovery.lower() in {"on", "true", "1", "yes"}:
        set_app_setting(db, RECOVERY_PHRASE_HASH_SETTING, "")
        db.add(models.AuditLog(user_id=user.id, action="recovery_phrase_removed", object_type="user", object_id=user.id))
        db.commit()
        flash(request, "Recovery phrase removed.", "success")
        return redirect("/settings#account-security")
    phrase = recovery_phrase.strip()
    if phrase != confirm_recovery_phrase.strip():
        flash(request, "Recovery phrases did not match.", "warning")
        return redirect("/settings#account-security")
    error = _recovery_phrase_error(phrase)
    if error:
        flash(request, error, "warning")
        return redirect("/settings#account-security")
    set_app_setting(db, RECOVERY_PHRASE_HASH_SETTING, hash_password(phrase))
    db.add(models.AuditLog(user_id=user.id, action="recovery_phrase_updated", object_type="user", object_id=user.id))
    db.commit()
    flash(request, "Recovery phrase updated. Store it somewhere safe outside Opsbook.", "success")
    return redirect("/settings#account-security")


@app.post("/settings/tokens")
def settings_token_create(
    request: Request,
    csrf: str = Form(...),
    token_name: str = Form(...),
    token_value: str = Form(...),
    token_expiry: str = Form(""),
    token_notes: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    label = token_name.strip()
    value = token_value.strip()
    if not label or not value:
        flash(request, "Token name and token are required.", "warning")
        return redirect("/settings")
    duplicate = (
        db.query(models.Credential)
        .filter(models.Credential.secret_type == "API token", models.Credential.label.ilike(label))
        .first()
    )
    if duplicate:
        flash(request, "A token with that name already exists. Edit the existing token if needed.", "warning")
        return redirect("/settings")
    credential = models.Credential(
        label=label,
        username="",
        secret_encrypted=encrypt_text(value),
        secret_type="API token",
        security_level="high",
        expires_at=_parse_optional_datetime(token_expiry),
        notes=token_notes,
        last_changed_at=now_utc(),
        active=True,
    )
    db.add(credential)
    db.flush()
    set_tags(db, "credential", credential.id, "token, api, temporary")
    if "github" in f"{label} {token_notes}".lower():
        merge_tags(db, "credential", credential.id, "github")
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="token_created",
            object_type="credential",
            object_id=credential.id,
            details_json={"expires_at": credential.expires_at.isoformat() if credential.expires_at else ""},
        )
    )
    db.commit()
    flash(request, "Token stored as a high-security encrypted credential.", "success")
    return redirect("/settings")


@app.post("/settings/2fa/start")
def settings_2fa_start(
    request: Request,
    csrf: str = Form(...),
    password: str = Form(...),
    totp_login: str = Form(""),
    totp_high_security: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    if not _account_password_ok_and_upgrade(db, user, password):
        flash(request, "Incorrect password. 2FA setup was not started.", "danger")
        return redirect("/settings#two-factor")
    scope = _set_totp_scope(db, _totp_scope_from_flags(totp_login, totp_high_security))
    user.totp_enabled = False
    user.totp_secret_encrypted = encrypt_text(pyotp.random_base32())
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="totp_setup_started",
            object_type="user",
            object_id=user.id,
            details_json={"scope": scope},
        )
    )
    db.commit()
    flash(request, "2FA setup started. Add the manual key to your authenticator app, then verify a code.", "success")
    return redirect("/settings#two-factor")


@app.post("/settings/2fa/verify")
def settings_2fa_verify(
    request: Request,
    csrf: str = Form(...),
    code: str = Form(...),
    totp_login: str = Form(""),
    totp_high_security: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    if not user.totp_secret_encrypted:
        flash(request, "Start 2FA setup first.", "warning")
        return redirect("/settings#two-factor")
    if not _verify_totp_code(user, code):
        flash(request, "Incorrect 2FA code.", "danger")
        return redirect("/settings#two-factor")
    scope = _set_totp_scope(db, _totp_scope_from_flags(totp_login, totp_high_security))
    user.totp_enabled = True
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="totp_enabled",
            object_type="user",
            object_id=user.id,
            details_json={"scope": scope},
        )
    )
    db.commit()
    flash(
        request,
        f"2FA is now enabled for {_totp_scope_label(scope)}.",
        "success",
    )
    return redirect("/settings#two-factor")


@app.post("/settings/2fa/scope")
def settings_2fa_scope(
    request: Request,
    csrf: str = Form(...),
    password: str = Form(...),
    code: str = Form(...),
    totp_login: str = Form(""),
    totp_high_security: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    if not user.totp_enabled:
        flash(request, "Enable 2FA before changing where it is used.", "warning")
        return redirect("/settings#two-factor")
    if not _account_password_ok_and_upgrade(db, user, password):
        flash(request, "Incorrect password. 2FA use was not changed.", "danger")
        return redirect("/settings#two-factor")
    if not _verify_totp_code(user, code):
        flash(request, "Incorrect 2FA code. 2FA use was not changed.", "danger")
        return redirect("/settings#two-factor")
    scope = _set_totp_scope(db, _totp_scope_from_flags(totp_login, totp_high_security))
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="totp_scope_changed",
            object_type="user",
            object_id=user.id,
            details_json={"scope": scope},
        )
    )
    db.commit()
    flash(request, "2FA use saved.", "success")
    return redirect("/settings#two-factor")


@app.post("/settings/2fa/disable")
def settings_2fa_disable(
    request: Request,
    csrf: str = Form(...),
    password: str = Form(...),
    code: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    if not _account_password_ok_and_upgrade(db, user, password):
        flash(request, "Incorrect password. 2FA was not changed.", "danger")
        return redirect("/settings#two-factor")
    if user.totp_enabled and not _verify_totp_code(user, code):
        flash(request, "Incorrect 2FA code. 2FA was not disabled.", "danger")
        return redirect("/settings#two-factor")
    user.totp_enabled = False
    user.totp_secret_encrypted = None
    db.add(models.AuditLog(user_id=user.id, action="totp_disabled", object_type="user", object_id=user.id))
    db.commit()
    flash(request, "2FA disabled.", "success")
    return redirect("/settings#two-factor")


@app.post("/maintenance/cleanup-smart-paste")
def maintenance_cleanup_smart_paste(
    request: Request,
    csrf: str = Form(...),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    cleaned = _cleanup_obvious_import_misses(db)
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="smart_paste_cleanup",
            object_type="maintenance",
            details_json=cleaned,
        )
    )
    db.commit()
    flash(
        request,
        f"Cleaned {cleaned['services']} service miss(es), {cleaned['credentials']} duplicate credential(s), {cleaned['hardware']} hardware summary field(s), and {cleaned['tag_links']} duplicate tag link(s).",
        "success",
    )
    return redirect("/settings")


def _search_results(db: Session, q: str, limit: int = 20) -> dict[str, list[Any]]:
    clean = q.strip()
    like = f"%{clean}%"
    results: dict[str, list[Any]] = {
        "devices": [],
        "services": [],
        "credentials": [],
        "commands": [],
        "urls": [],
        "ports": [],
        "notes": [],
        "images": [],
        "suggestions": [],
    }
    if clean:
        results["devices"] = (
            db.query(models.Device)
            .filter(
                or_(
                    models.Device.name.ilike(like),
                    models.Device.primary_ip.ilike(like),
                    models.Device.hostname.ilike(like),
                    models.Device.purpose.ilike(like),
                    models.Device.notes.ilike(like),
                )
            )
            .limit(limit)
            .all()
        )
        results["services"] = (
            db.query(models.Service)
            .filter(
                or_(
                    models.Service.name.ilike(like),
                    models.Service.purpose.ilike(like),
                    models.Service.local_url.ilike(like),
                    models.Service.public_url.ilike(like),
                    models.Service.repo_url.ilike(like),
                    models.Service.compose_path.ilike(like),
                    models.Service.notes.ilike(like),
                )
            )
            .limit(limit)
            .all()
        )
        results["credentials"] = (
            db.query(models.Credential)
            .filter(
                or_(
                    models.Credential.label.ilike(like),
                    models.Credential.username.ilike(like),
                    models.Credential.login_url.ilike(like),
                    models.Credential.notes.ilike(like),
                )
            )
            .limit(limit)
            .all()
        )
        results["commands"] = (
            db.query(models.Command)
            .filter(
                or_(
                    models.Command.name.ilike(like),
                    models.Command.category.ilike(like),
                    models.Command.command_template.ilike(like),
                    models.Command.short_description.ilike(like),
                    models.Command.help_low.ilike(like),
                    models.Command.help_high.ilike(like),
                )
            )
            .limit(limit)
            .all()
        )
        results["urls"] = (
            db.query(models.Url)
            .filter(
                or_(
                    models.Url.label.ilike(like),
                    models.Url.url.ilike(like),
                    models.Url.url_type.ilike(like),
                    models.Url.notes.ilike(like),
                )
            )
            .limit(limit)
            .all()
        )
        port_filters = [
            models.Port.protocol.ilike(like),
            models.Port.purpose.ilike(like),
            models.Port.notes.ilike(like),
        ]
        if clean.isdigit():
            port_number = int(clean)
            port_filters.extend([models.Port.host_port == port_number, models.Port.internal_port == port_number])
        results["ports"] = db.query(models.Port).filter(or_(*port_filters)).limit(limit).all()
        results["notes"] = (
            db.query(models.Note)
            .filter(or_(models.Note.title.ilike(like), models.Note.body.ilike(like)))
            .limit(limit)
            .all()
        )
        results["images"] = (
            db.query(models.DeviceImage)
            .filter(
                or_(
                    models.DeviceImage.name.ilike(like),
                    models.DeviceImage.original_filename.ilike(like),
                    models.DeviceImage.notes.ilike(like),
                    models.DeviceImage.ocr_text.ilike(like),
                )
            )
            .limit(limit)
            .all()
        )
        results["suggestions"] = (
            db.query(models.UserSuggestion)
            .filter(
                or_(
                    models.UserSuggestion.title.ilike(like),
                    models.UserSuggestion.subtitle.ilike(like),
                    models.UserSuggestion.notes.ilike(like),
                )
            )
            .limit(limit)
            .all()
        )
    return results


def _search_result_subtitle(*parts: Any) -> str:
    return " · ".join(str(part).strip() for part in parts if str(part or "").strip())


def _search_live_items(db: Session, results: dict[str, list[Any]], q: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    def add(
        kind: str,
        title: str,
        subtitle: str,
        url: str,
        *,
        device: models.Device | None = None,
    ) -> None:
        item = {
            "type": kind,
            "title": (title or "").strip() or kind,
            "subtitle": subtitle,
            "url": url,
        }
        if device:
            ping = _device_ping_status(db, device)
            item.update(
                {
                    "device_name": device.name,
                    "device_ping_state": ping.get("state", "unknown"),
                    "device_ping_label": ping.get("label", "unknown"),
                }
            )
        items.append(item)

    for device in results["devices"]:
        add(
            "Device",
            device.name,
            _search_result_subtitle(device.primary_ip or device.hostname, device.purpose or device.type),
            f"/devices/{device.id}",
            device=device,
        )
    for service in results["services"]:
        add(
            "Service",
            service.name,
            _search_result_subtitle(service.device.name if service.device else "Unlinked", service.local_url or service.public_url or service.compose_path),
            f"/services/{service.id}",
        )
    for credential in results["credentials"]:
        context_device = _credential_context_device(credential)
        add(
            "Token" if credential.secret_type == "API token" else "Credential",
            credential.label,
            _search_result_subtitle(credential.service.name if credential.service else context_device.name if context_device else "Unlinked", credential.username, credential.secret_type),
            f"/credentials/{credential.id}",
        )
    for command in results["commands"]:
        add("Command", command.name, _search_result_subtitle(command.category, command.short_description), f"/commands/{command.id}/edit")
    for url in results["urls"]:
        context_device = url.service.device if url.service and url.service.device else url.device
        add(
            "URL",
            url.label or url.url,
            _search_result_subtitle(context_device.name if context_device else "", url.url_type, url.url),
            f"/urls/{url.id}/edit?return_to=/search%3Fq={quote(q, safe='')}",
        )
    for port in results["ports"]:
        add(
            "Port",
            f"{port.host_port}/{port.protocol}",
            _search_result_subtitle(port.device.name if port.device else "", port.service.name if port.service else "", port.purpose),
            f"/ports/{port.id}/edit?return_to=/search%3Fq={quote(q, safe='')}",
        )
    for note in results["notes"]:
        target, _ = _note_target_label(db, note)
        add("Note", note.title or "Note", _search_result_subtitle(target, note.source), f"/notes/{note.id}")
    for image in results["images"]:
        add(
            "Image",
            image.name or image.original_filename,
            _search_result_subtitle(image.device.name if image.device else "", image.notes),
            f"/devices/{image.device_id}?tab=images",
        )
    for suggestion in results["suggestions"]:
        add("Suggestion", suggestion.title, _search_result_subtitle(suggestion.subtitle, suggestion.notes), "/suggestions#custom-suggestions")
    return items


@app.get("/search/live")
def search_live(
    q: str = "",
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    clean = q.strip()
    if len(clean) < 2:
        return JSONResponse({"items": []})
    return JSONResponse({"items": _search_live_items(db, _search_results(db, clean, limit=6), clean)[:12]})


@app.get("/search", response_class=HTMLResponse)
def search_page(
    request: Request,
    q: str = "",
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    results = _search_results(db, q)
    related_devices: list[models.Device | None] = list(results["devices"])
    related_devices.extend(item.device for item in results["services"] if item.device)
    related_devices.extend(item.device for item in results["ports"] if item.device)
    related_devices.extend(item.device for item in results["images"] if item.device)
    related_devices.extend(
        item.service.device if item.service and item.service.device else item.device
        for item in results["credentials"]
    )
    return render(
        request,
        "search.html",
        {"q": q, "results": results, "device_ping_statuses": _device_ping_status_map(db, related_devices)},
        user=user,
    )



def _export_job_snapshot() -> dict[str, Any]:
    with EXPORT_JOB_STATE_LOCK:
        return copy.deepcopy(EXPORT_JOB_STATE)


def _set_export_job_state(**values: Any) -> None:
    with EXPORT_JOB_STATE_LOCK:
        EXPORT_JOB_STATE.update(values)


def _run_emergency_export_job(user_id: int, include_secrets: bool) -> None:
    try:
        with SessionLocal() as db:
            created = create_emergency_export(db, include_credentials=include_secrets)
            db.add(
                models.AuditLog(
                    user_id=user_id,
                    action="emergency_export_created",
                    object_type="backup_export",
                    details_json={"files": [item.filename for item in created], "included_credentials": include_secrets},
                )
            )
            db.commit()
            _set_export_job_state(
                status="completed",
                finished_at=now_utc().isoformat(),
                files=[item.filename for item in created],
                error="",
            )
    except Exception:
        logger.exception("Emergency export job failed")
        _set_export_job_state(
            status="failed",
            finished_at=now_utc().isoformat(),
            files=[],
            error="The emergency export failed. Check the Opsbook logs before retrying.",
        )
    finally:
        EXPORT_JOB_RUN_LOCK.release()


@app.get("/exports/status")
def exports_status(user: models.User = Depends(require_user)) -> JSONResponse:
    return JSONResponse(_export_job_snapshot())


@app.get("/exports", response_class=HTMLResponse)
def exports_page(
    request: Request,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    exports = db.query(models.BackupExport).order_by(models.BackupExport.created_at.desc()).all()
    return render(request, "exports.html", {"exports": exports, "export_job": _export_job_snapshot()}, user=user)


@app.post("/exports")
def exports_create(
    request: Request,
    csrf: str = Form(...),
    include_credentials: str = Form(""),
    challenge: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    include_secrets = include_credentials == "on"
    if include_secrets and not _challenge_ok_and_upgrade(db, user, challenge):
        flash(request, "Credential export requires your account password or reveal password.", "danger")
        return redirect("/exports")
    if include_secrets:
        db.commit()
    if not EXPORT_JOB_RUN_LOCK.acquire(blocking=False):
        flash(request, "An emergency export is already running. You can keep using Opsbook while it finishes.", "warning")
        return redirect("/exports")
    _set_export_job_state(
        status="running",
        started_at=now_utc().isoformat(),
        finished_at="",
        files=[],
        error="",
    )
    worker = threading.Thread(
        target=_run_emergency_export_job,
        args=(user.id, include_secrets),
        name="kairix-emergency-export",
        daemon=True,
    )
    try:
        worker.start()
    except RuntimeError:
        EXPORT_JOB_RUN_LOCK.release()
        _set_export_job_state(status="failed", finished_at=now_utc().isoformat(), error="The export worker could not start.")
        flash(request, "Emergency export could not start. Check the Opsbook logs.", "danger")
        return redirect("/exports")
    flash(request, "Emergency export started. You can navigate elsewhere while it runs.", "success")
    return redirect("/exports")


@app.post("/exports/import")
async def exports_import(
    request: Request,
    csrf: str = Form(...),
    backup_file: UploadFile = File(...),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    data = await backup_file.read()
    try:
        payload = json.loads(decrypt_text(data.decode("utf-8"), export=True))
    except Exception:
        flash(request, "Import failed. Check that this is a Kairix encrypted backup and the export key matches.", "danger")
        return redirect("/exports")
    tables = payload.get("tables", {})
    imported = 0
    for table_name, model in IMPORT_MODELS.items():
        for row in tables.get(table_name, []):
            db.merge(model(**_coerce_import_row(model, row)))
            imported += 1
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="emergency_export_imported",
            object_type="backup_export",
            details_json={
                "filename": backup_file.filename,
                "rows": imported,
                "source": payload.get("metadata", {}).get("source_instance"),
            },
        )
    )
    db.commit()
    flash(request, f"Imported {imported} rows from encrypted backup.", "success")
    return redirect("/exports")


@app.get("/exports/download/{filename}")
def export_download(
    filename: str,
    user: models.User = Depends(require_user),
) -> FileResponse:
    path = safe_export_path(filename)
    if not path.exists() or not path.is_file():
        raise HTTPException(404, "Export file not found.")
    return FileResponse(path, filename=Path(filename).name)


@app.post("/exports/delete/{export_id}")
def export_delete(
    request: Request,
    export_id: int,
    csrf: str = Form(...),
    password: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    if not _challenge_ok_and_upgrade(db, user, password):
        flash(request, "Deleting emergency exports requires your account password or reveal PIN.", "danger")
        return redirect("/exports")
    export = db.get(models.BackupExport, export_id)
    if not export:
        raise HTTPException(404, "Export not found.")
    filename = export.filename
    path = safe_export_path(filename)
    try:
        path.unlink(missing_ok=True)
    except OSError:
        flash(request, "Export file could not be removed from disk.", "warning")
        return redirect("/exports")
    db.delete(export)
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="export_deleted",
            object_type="backup_export",
            object_id=export_id,
            details_json={"filename": filename},
        )
    )
    db.commit()
    flash(request, f"Deleted export {filename}.", "success")
    return redirect("/exports")


@app.post("/exports/delete-old")
def exports_delete_old(
    request: Request,
    csrf: str = Form(...),
    older_than_days: int = Form(90),
    password: str = Form(""),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    if not _challenge_ok_and_upgrade(db, user, password):
        flash(request, "Deleting old emergency exports requires your account password or reveal PIN.", "danger")
        return redirect("/exports")
    days = max(1, min(99999, int(older_than_days or 90)))
    cutoff = now_utc() - timedelta(days=days)
    exports = db.query(models.BackupExport).filter(models.BackupExport.created_at < cutoff).all()
    deleted = 0
    for export in exports:
        path = safe_export_path(export.filename)
        try:
            path.unlink(missing_ok=True)
        except OSError:
            continue
        db.delete(export)
        deleted += 1
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="old_exports_deleted",
            object_type="backup_export",
            details_json={"older_than_days": days, "deleted": deleted},
        )
    )
    db.commit()
    flash(request, f"Deleted {deleted} export file(s) older than {days} day(s).", "success")
    return redirect("/exports")


@app.get("/history", response_class=HTMLResponse)
def history_page(
    request: Request,
    kind: str = "",
    q: str = "",
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    query = db.query(models.AuditLog).filter(models.AuditLog.action != "agent_stats_received")
    if kind == "ping":
        query = query.filter(
            models.AuditLog.action.in_(
                [
                    "device_ping",
                    "service_validate",
                    "services_validated",
                    "ping_warning_scheduled",
                    "ping_warning_expected",
                    "ping_warning_known_down",
                    "webhook_sent",
                    "webhook_failed",
                    "webhook_test",
                ]
            )
        )
    elif kind == "credentials":
        query = query.filter(models.AuditLog.action.ilike("credential_%"))
    elif kind == "smart-paste":
        query = query.filter(models.AuditLog.action.ilike("smart_paste_%"))
    logs = query.order_by(models.AuditLog.created_at.desc()).limit(500 if q else 200).all()
    human_logs = [_human_audit_log(db, item) for item in logs]
    if q:
        needle = q.strip().lower()
        human_logs = [
            item
            for item in human_logs
            if needle in " ".join(
                [
                    item.get("title", ""),
                    item.get("target", ""),
                    item.get("details", ""),
                    item.get("raw", ""),
                    item.get("action", ""),
                    item.get("object_type", ""),
                    item.get("object_id", ""),
                ]
            ).lower()
        ]
    return render(request, "history.html", {"logs": human_logs, "kind": kind, "q": q}, user=user)


@app.get("/raw/{object_type}/{object_id}", response_class=HTMLResponse)
def raw_object_page(
    request: Request,
    object_type: str,
    object_id: int,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    model_map = {
        "device": models.Device,
        "service": models.Service,
        "credential": models.Credential,
        "command": models.Command,
    }
    model = model_map.get(object_type)
    if not model:
        raise HTTPException(404, "Unsupported raw object type.")
    obj = db.get(model, object_id)
    if not obj:
        raise HTTPException(404, "Object not found.")
    data = {}
    for column in model.__table__.columns:
        value = getattr(obj, column.name)
        if object_type == "credential" and column.name == "secret_encrypted":
            value = "[encrypted]"
        elif isinstance(value, datetime):
            value = value.isoformat()
        data[column.name] = value
    return render(
        request,
        "raw.html",
        {"object_type": object_type, "object_id": object_id, "raw_json": json.dumps(data, indent=2, default=str)},
        user=user,
    )
