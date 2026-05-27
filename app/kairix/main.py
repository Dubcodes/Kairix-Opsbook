from __future__ import annotations

import copy
import io
import json
import re
import socket
import subprocess
import threading
import time
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

from . import models
from .config import settings
from .database import SessionLocal, get_db, init_db
from .exporter import create_emergency_export, safe_export_path
from .parser import INVENTORY_COMMAND, parse_smart_paste
from .security import (
    challenge_ok,
    decrypt_text,
    encrypt_text,
    hash_password,
    new_csrf_token,
    now_utc,
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
GITHUB_TOKEN_RE = re.compile(r"\b(?:github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9_]+)\b")


def service_no_credentials_needed(service: models.Service) -> bool:
    return NO_CREDENTIALS_MARKER in (service.notes or "")


def public_notes(value: str) -> str:
    return (value or "").replace(NO_CREDENTIALS_MARKER, "").strip()


templates.env.globals["service_no_credentials_needed"] = service_no_credentials_needed
templates.env.globals["public_notes"] = public_notes

THEME_DEFAULTS = {
    "theme_mode": "auto",
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
}

PING_THREAD_STARTED = False
WEBHOOK_URL_SETTING = "ping_webhook_url_encrypted"
WEBHOOK_SCOPE_SETTING = "ping_webhook_scope"
WEBHOOK_RECOVERY_SETTING = "ping_webhook_send_recovery"


@app.on_event("startup")
def startup() -> None:
    global PING_THREAD_STARTED
    init_db()
    with SessionLocal() as db:
        seed_initial_data(db)
        _normalize_unknown_states(db)
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


def bool_setting(db: Session, key: str, default: bool = False) -> bool:
    raw = get_app_settings(db).get(key)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


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


def _service_tokens(service: models.Service) -> list[models.Credential]:
    return [credential for credential in service.credentials if credential.secret_type == "API token"]


def _service_login_credentials(service: models.Service) -> list[models.Credential]:
    return [credential for credential in service.credentials if credential.secret_type != "API token"]


templates.env.globals["service_tokens"] = _service_tokens
templates.env.globals["service_login_credentials"] = _service_login_credentials


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


def _service_validation_targets(service: models.Service) -> list[tuple[str, str, int]]:
    targets: list[tuple[str, str, int]] = []
    for raw_url in [service.local_url, service.public_url]:
        if not raw_url:
            continue
        parsed = urlparse(raw_url)
        if not parsed.hostname:
            continue
        default_port = 443 if parsed.scheme == "https" else 80
        try:
            port = parsed.port or default_port
        except ValueError:
            continue
        targets.append((raw_url, parsed.hostname, port))
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
    devices_failed = 0
    services_failed = 0
    for device in _device_order_query(db).all():
        latest = _latest_audit(db, "device", device.id, "device_ping")
        if latest and not (latest.details_json or {}).get("ok"):
            devices_failed += 1
    for service in _service_order_query(db).all():
        latest = _latest_audit(db, "service", service.id, "service_validate")
        if not latest:
            continue
        details = latest.details_json or {}
        if int(details.get("checked") or 0) and not details.get("ok") and not details.get("partial"):
            services_failed += 1
    return {"devices": devices_failed, "services": services_failed, "total": devices_failed + services_failed}


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
    redacted = GITHUB_TOKEN_RE.sub("[redacted github token]", redacted)
    if redacted != raw_text:
        changed = True
    return redacted, changed


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
    query = db.query(models.Credential)
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


def _match_service_for_import(db: Session, device_id: int, service_hint: dict[str, Any]) -> models.Service | None:
    name = str(service_hint.get("name", "")).strip()
    aliases = {_service_alias(name), slugify(name)}
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
        for service in db.query(models.Service).filter(models.Service.device_id == device_id).all():
            service_aliases = {_service_alias(service.name), slugify(service.name)}
            if alias in service_aliases:
                return service
            if alias and any(alias in existing or existing in alias for existing in service_aliases if len(existing) > 4):
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
        service["duplicate_id"] = duplicate.id if duplicate else None
        service["selected"] = has_context
        for url in service.get("urls", []):
            duplicate_url = db.query(models.Url).filter(models.Url.url == str(url.get("url", ""))).first()
            url["duplicate_id"] = duplicate_url.id if duplicate_url else None
            url["selected"] = duplicate_url is None
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
    for port in parsed.get("ports", []):
        port["selected"] = False
        if existing_device_id and port.get("host_port"):
            duplicate = (
                db.query(models.Port)
                .filter(models.Port.device_id == existing_device_id, models.Port.host_port == int(port["host_port"]))
                .first()
            )
            port["duplicate_id"] = duplicate.id if duplicate else None
    for url in parsed.get("urls", []):
        duplicate = db.query(models.Url).filter(models.Url.url == str(url.get("url", ""))).first()
        url["duplicate_id"] = duplicate.id if duplicate else None
        url["selected"] = duplicate is None
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


def _quick_credentials_for_device(db: Session, device: models.Device) -> list[models.Credential]:
    order = _id_list(get_app_settings(db).get(f"quick_credential_order:{device.id}", ""))
    hidden = set(_id_list(get_app_settings(db).get(f"quick_credential_hidden:{device.id}", "")))
    if not order:
        return []
    credentials = [credential for credential in device.credentials if credential.id in order and credential.id not in hidden]
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
    for credential in list(service.credentials):
        db.query(models.TagLink).filter_by(object_type="credential", object_id=credential.id).delete()
        db.delete(credential)
    for port in list(service.ports):
        db.query(models.TagLink).filter_by(object_type="port", object_id=port.id).delete()
        db.delete(port)
    for url in list(service.urls):
        db.query(models.TagLink).filter_by(object_type="url", object_id=url.id).delete()
        db.delete(url)
    db.query(models.Note).filter_by(object_type="service", object_id=service.id).delete()
    for command in db.query(models.Command).filter_by(applies_to_type="service", applies_to_id=service.id).all():
        db.query(models.TagLink).filter_by(object_type="command", object_id=command.id).delete()
        db.delete(command)
    db.query(models.TagLink).filter_by(object_type="service", object_id=service.id).delete()
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
    "note_deleted": "Note deleted",
    "note_tags_updated": "Note tags updated",
    "quick_credentials_updated": "Favorite credentials updated",
    "ping_warning_scheduled": "Ping warning marked scheduled",
    "smart_paste_parsed": "Smart Paste reviewed",
    "smart_paste_applied": "Smart Paste applied",
    "quick_note_saved": "Quick note saved",
    "emergency_export_created": "Emergency export created",
    "emergency_export_imported": "Emergency backup imported",
    "settings_updated": "Settings changed",
    "device_order_updated": "Device order changed",
    "webhook_settings_updated": "Webhook settings changed",
    "webhook_sent": "Webhook sent",
    "webhook_failed": "Webhook failed",
    "webhook_test": "Webhook tested",
    "totp_setup_started": "2FA setup started",
    "totp_enabled": "2FA enabled",
    "totp_disabled": "2FA disabled",
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


def _delete_redirect_target(request: Request, object_type: str, object_id: int) -> str:
    referer = request.headers.get("referer") or ""
    if object_type == "service" and f"/services/{object_id}" in referer:
        return "/services"
    if object_type == "credential" and f"/credentials/{object_id}" in referer:
        return "/credentials"
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
    if note_ids:
        filters.append(and_(models.AuditLog.object_type.in_(["note", "quick_note"]), models.AuditLog.object_id.in_(note_ids)))
    if command_ids:
        filters.append(and_(models.AuditLog.object_type == "command", models.AuditLog.object_id.in_(command_ids)))
    logs = (
        db.query(models.AuditLog)
        .filter(or_(*filters))
        .order_by(models.AuditLog.created_at.desc())
        .limit(limit)
        .all()
    )
    return [_human_audit_log(db, log) for log in logs]


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
    }
    payload.update(context or {})
    return templates.TemplateResponse(request, template_name, payload)


@app.get("/theme.css")
def theme_css(db: Session = Depends(get_db)) -> PlainTextResponse:
    values = get_app_settings(db)
    css = f"""
:root:not([data-theme]) {{
  --bg: {css_color(values.get("light_bg", ""), THEME_DEFAULTS["light_bg"])};
  --surface: {css_color(values.get("light_surface", ""), THEME_DEFAULTS["light_surface"])};
  --surface-soft: color-mix(in srgb, var(--surface) 92%, var(--bg));
  --ink: {css_color(values.get("light_text", ""), THEME_DEFAULTS["light_text"])};
  --muted: {css_color(values.get("light_muted", ""), THEME_DEFAULTS["light_muted"])};
  --line: {css_color(values.get("light_line", ""), THEME_DEFAULTS["light_line"])};
  --accent: {css_color(values.get("light_accent", ""), THEME_DEFAULTS["light_accent"])};
  --accent-ink: {css_color(values.get("light_accent_text", ""), THEME_DEFAULTS["light_accent_text"])};
}}
@media (prefers-color-scheme: dark) {{
  :root:not([data-theme]) {{
    --bg: {css_color(values.get("dark_bg", ""), THEME_DEFAULTS["dark_bg"])};
    --surface: {css_color(values.get("dark_surface", ""), THEME_DEFAULTS["dark_surface"])};
    --surface-soft: color-mix(in srgb, var(--surface) 78%, #000000);
    --ink: {css_color(values.get("dark_text", ""), THEME_DEFAULTS["dark_text"])};
    --muted: {css_color(values.get("dark_muted", ""), THEME_DEFAULTS["dark_muted"])};
    --line: {css_color(values.get("dark_line", ""), THEME_DEFAULTS["dark_line"])};
    --accent: {css_color(values.get("dark_accent", ""), THEME_DEFAULTS["dark_accent"])};
    --accent-ink: {css_color(values.get("dark_accent_text", ""), THEME_DEFAULTS["dark_accent_text"])};
  }}
}}
:root[data-theme="light"] {{
  --bg: {css_color(values.get("light_bg", ""), THEME_DEFAULTS["light_bg"])};
  --surface: {css_color(values.get("light_surface", ""), THEME_DEFAULTS["light_surface"])};
  --surface-soft: color-mix(in srgb, var(--surface) 92%, var(--bg));
  --ink: {css_color(values.get("light_text", ""), THEME_DEFAULTS["light_text"])};
  --muted: {css_color(values.get("light_muted", ""), THEME_DEFAULTS["light_muted"])};
  --line: {css_color(values.get("light_line", ""), THEME_DEFAULTS["light_line"])};
  --accent: {css_color(values.get("light_accent", ""), THEME_DEFAULTS["light_accent"])};
  --accent-ink: {css_color(values.get("light_accent_text", ""), THEME_DEFAULTS["light_accent_text"])};
}}
:root[data-theme="dark"] {{
  --bg: {css_color(values.get("dark_bg", ""), THEME_DEFAULTS["dark_bg"])};
  --surface: {css_color(values.get("dark_surface", ""), THEME_DEFAULTS["dark_surface"])};
  --surface-soft: color-mix(in srgb, var(--surface) 78%, #000000);
  --ink: {css_color(values.get("dark_text", ""), THEME_DEFAULTS["dark_text"])};
  --muted: {css_color(values.get("dark_muted", ""), THEME_DEFAULTS["dark_muted"])};
  --line: {css_color(values.get("dark_line", ""), THEME_DEFAULTS["dark_line"])};
  --accent: {css_color(values.get("dark_accent", ""), THEME_DEFAULTS["dark_accent"])};
  --accent-ink: {css_color(values.get("dark_accent_text", ""), THEME_DEFAULTS["dark_accent_text"])};
}}
"""
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
    return {"status": "ok", "app": settings.app_name, "version": settings.app_version}


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
    return render(request, "login.html", {"failed_ping_summary": _failed_ping_summary(db)})


@app.post("/login")
def login(
    request: Request,
    csrf: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
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
        flash(request, "Login failed. Check the username and password.", "danger")
        return redirect("/login")
    request.session.clear()
    if user.totp_enabled:
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
    secret = decrypt_text(user.totp_secret_encrypted)
    if not pyotp.TOTP(secret).verify(code.strip().replace(" ", ""), valid_window=1):
        flash(request, "Incorrect 2FA code.", "danger")
        return redirect("/login/2fa")
    request.session.clear()
    request.session["user_id"] = user.id
    request.session["last_seen"] = now_utc().isoformat()
    request.session["session_timeout_minutes"] = int_setting(db, "session_timeout_minutes", 20, minimum=1, maximum=999)
    csrf_token(request)
    _start_login_checks(user.id)
    flash(request, f"Welcome back, {user.display_name or user.username}.", "success")
    return redirect("/")


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
    suggestions = visible_suggestions(db)[:6]
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
    commands = (
        db.query(models.Command)
        .filter(
            or_(
                (models.Command.applies_to_type == "device")
                & (models.Command.applies_to_id == device.id),
                models.Command.applies_to_type == "generic",
            )
        )
        .order_by(models.Command.category, models.Command.name)
        .all()
    )
    notes = (
        db.query(models.Note)
        .filter(models.Note.object_type == "device", models.Note.object_id == device.id)
        .order_by(models.Note.updated_at.desc())
        .all()
    )
    grouped_services: dict[str, list[models.Service]] = {}
    for service in sorted(device.services, key=lambda item: (item.docker_project or "Ungrouped", item.name.lower())):
        grouped_services.setdefault(service.docker_project or "Ungrouped", []).append(service)
    service_groups = [
        {"name": name, "services": services}
        for name, services in grouped_services.items()
    ]
    auto_purpose = _device_auto_purpose(device)
    validation_status = {service.id: _service_validation_status(db, service) for service in device.services}
    return render(
        request,
        "device_detail.html",
        {
            "device": device,
            "tab": tab,
            "commands": commands,
            "history": _device_history(db, device),
            "notes": notes,
            "tag_list": tags_for(db, "device", device.id),
            "service_groups": service_groups,
            "quick_credentials": _quick_credentials_for_device(db, device),
            "favorite_edit": favorites == "edit",
            "ping_status": _device_ping_status(db, device),
            "status_log": _latest_audit(db, "device", device.id, "device_status_changed"),
            "validation_status": validation_status,
            "validation_log": _latest_audit(db, "device", device.id, "services_validated"),
            "auto_purpose": auto_purpose,
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
    action: str = Form(...),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    device = db.get(models.Device, device_id)
    credential = db.get(models.Credential, credential_id)
    if not device or not credential or credential.device_id != device.id:
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
    merge_tags(db, "device", device.id, _infer_tags_for_device(device))
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
    query = db.query(models.Credential)
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
    db.add(models.AuditLog(user_id=user.id, action="credential_created", object_type="credential", object_id=credential.id))
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
    credential.login_url = login_url
    credential.expires_at = _parse_optional_datetime(expires_at)
    credential.notes = notes
    credential.active = active == "on"
    set_tags(db, "credential", credential.id, tags)
    db.add(models.AuditLog(user_id=user.id, action="credential_edited", object_type="credential", object_id=credential.id))
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
        if service_ids and not remove_services:
            flash(
                request,
                "This device still has linked services. Check Delete linked services, or move those services before deleting the device.",
                "warning",
            )
            return redirect(f"/devices/{obj.id}/edit")
        credential_filter = models.Credential.device_id == obj.id
        if service_ids:
            credential_filter = or_(credential_filter, models.Credential.service_id.in_(service_ids))
        related_credentials = db.query(models.Credential).filter(credential_filter).all()
        if remove_credentials:
            for credential in related_credentials:
                db.query(models.TagLink).filter_by(object_type="credential", object_id=credential.id).delete()
                db.delete(credential)
        else:
            for credential in related_credentials:
                credential.device_id = None
                if credential.service_id in service_ids:
                    credential.service_id = None
                note = public_notes(credential.notes)
                credential.notes = f"{note}\nUnlinked when device {obj.name} was deleted.".strip()
        if remove_services:
            for service_id in service_ids:
                db.query(models.TagLink).filter_by(object_type="service", object_id=service_id).delete()
                db.query(models.Note).filter_by(object_type="service", object_id=service_id).delete()
                for command in db.query(models.Command).filter_by(applies_to_type="service", applies_to_id=service_id).all():
                    db.query(models.TagLink).filter_by(object_type="command", object_id=command.id).delete()
                    db.delete(command)
        for port in list(obj.ports):
            db.query(models.TagLink).filter_by(object_type="port", object_id=port.id).delete()
            db.delete(port)
        for url in list(obj.urls):
            db.query(models.TagLink).filter_by(object_type="url", object_id=url.id).delete()
            db.delete(url)
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


def _reveal_failure_response(request: Request, *, json_response: bool = False) -> JSONResponse | RedirectResponse:
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
    message = f"Incorrect password or reveal PIN. {5 - failures} attempt(s) left."
    if json_response:
        return JSONResponse(
            {
                "detail": message,
                "requires_challenge": True,
                "message": "Password or reveal PIN",
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
        },
        user=user,
    )


@app.post("/credentials/{credential_id}/reveal", response_class=HTMLResponse)
def credential_reveal_post(
    request: Request,
    credential_id: int,
    csrf: str = Form(...),
    challenge: str = Form(""),
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
    if needs_challenge and not challenge.strip():
        flash(request, "Enter your account password or reveal PIN.", "warning")
        return redirect(f"/credentials/{credential.id}/reveal")
    if needs_challenge and not challenge_ok(
        challenge, user.password_hash, user.secondary_password_hash
    ):
        return _reveal_failure_response(request)
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
    challenge_value = str(payload.get("challenge", ""))
    if needs_challenge and not challenge_value:
        return JSONResponse(
            {
                "detail": "Password or reveal PIN required.",
                "requires_challenge": True,
                "requires_reason": False,
                "message": "Password or reveal PIN",
            },
            status_code=403,
        )
    if needs_challenge and not challenge_ok(
        challenge_value, user.password_hash, user.secondary_password_hash
    ):
        response = _reveal_failure_response(request, json_response=True)
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
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    return render(
        request,
        "ports.html",
        {
            "ports": db.query(models.Port).order_by(models.Port.host_port).all(),
            "urls": db.query(models.Url).order_by(models.Url.url).all(),
            "devices": _device_order_query(db).all(),
            "services": _service_order_query(db).all(),
            "device_ping_statuses": _device_ping_status_map(db, _device_order_query(db).all()),
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
    kind_order = ["Device", "Service", "Credential", "Command", "Port", "Url", "Note", "Quick Note"]
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
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
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
        return redirect("/ports")
    port = models.Port(
        device_id=device_id,
        service_id=int(service_id) if service_id else None,
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
    return redirect("/ports")


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
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    resolved_service_id = int(service_id) if service_id else None
    resolved_device_id = int(device_id) if device_id else None
    if resolved_service_id and not resolved_device_id:
        service = db.get(models.Service, resolved_service_id)
        if service:
            resolved_device_id = service.device_id
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
    return redirect("/ports")


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
    port.device_id = device_id
    port.service_id = int(service_id) if service_id else None
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
    if resolved_service_id and not resolved_device_id:
        service = db.get(models.Service, resolved_service_id)
        if service:
            resolved_device_id = service.device_id
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
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    db.add(models.Note(object_type=object_type, object_id=object_id, title=title, body=body, source=source))
    db.add(models.AuditLog(user_id=user.id, action="note_added", object_type=object_type, object_id=object_id))
    db.commit()
    flash(request, "Note added.", "success")
    return redirect(f"/{object_type}s/{object_id}")


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
    parsed = _annotate_import_suggestions(db, parse_smart_paste(raw_text))
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
    parsed = _annotate_import_suggestions(db, parse_smart_paste(raw_text))
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
    device_bound_selected = any(
        form.getlist(name)
        for name in ["services", "ports", "urls", "credentials", "service_credentials", "service_urls", "delete_missing_services"]
    ) or bool(form.get("apply_hardware"))
    if target_raw == "new" and device_bound_selected and not apply_device:
        flash(
            request,
            "Nothing was applied. Choose an existing device, or check Create/update this device before importing services, ports, URLs, credentials, or hardware.",
            "warning",
        )
        return redirect(f"/smart-paste/{record.id}")
    requires_device = device_bound_selected or target_raw != "new" or apply_device
    if not requires_device and (form.getlist("tokens") or form.getlist("commands")):
        created_tokens = 0
        for index_raw in form.getlist("tokens"):
            if _create_token_credential_from_import(db, user, form, parsed, str(index_raw), record, None):
                created_tokens += 1
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
        db.add(models.AuditLog(user_id=user.id, action="smart_paste_applied", object_type="import", object_id=record.id, details_json={"tokens": created_tokens, "commands": created_commands}))
        db.commit()
        flash(request, f"Stored {created_tokens} token/API item(s) and {created_commands} command(s).", "success")
        return redirect("/commands" if created_commands else "/tokens")
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
        if apply_device and form.get("device_name"):
            device.name = str(form.get("device_name")).strip()
            device.slug = unique_slug(db, models.Device, device.name, existing_id=device.id)
        if apply_device and form.get("device_ip"):
            device.primary_ip = str(form.get("device_ip")).strip()
        if apply_device and form.get("device_os"):
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
        hardware.model = extras.get("model_summary") or hardware.model
        hardware.cpu = extras.get("cpu_summary") or hardware.cpu
        hardware.ram = extras.get("memory_summary") or hardware.ram
        hardware.storage_summary = extras.get("disk_summary") or hardware.storage_summary
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
            exists.docker_project = group_value or exists.docker_project
            exists.compose_path = compose_value or exists.compose_path
            exists.container_name = item.get("container_name", "") or exists.container_name
            exists.image = item.get("image", "") or exists.image
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
            if str(url_item.get("url_type", "local")) == "public":
                exists.public_url = url_value or exists.public_url
            else:
                exists.local_url = url_value or exists.local_url
            duplicate_url = db.query(models.Url).filter(models.Url.url == url_value).first()
            if not duplicate_url:
                db.add(
                    models.Url(
                        device_id=device.id,
                        service_id=exists.id,
                        label=service_name,
                        url=url_value,
                        url_type=str(url_item.get("url_type", "local")),
                        notes=f"Imported from Smart Paste {record.id}.",
                    )
                )
        for port_value in form.getlist(f"service_port_{index_raw}"):
            try:
                _, host_port, protocol = str(port_value).split(":", 2)
            except ValueError:
                continue
            if not host_port.isdigit():
                continue
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
            db.add(
                models.AuditLog(
                    user_id=user.id,
                    action="credential_created",
                    object_type="credential",
                    object_id=credential.id,
                    details_json={"source": f"smart_paste:{record.id}"},
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
    for index_raw in form.getlist("urls"):
        item = parsed.get("urls", [])[int(index_raw)]
        url_value = str(form.get(f"url_value_{index_raw}") or item["url"]).strip()
        if not url_value:
            continue
        duplicate = db.query(models.Url).filter(models.Url.url == url_value).first()
        if not duplicate:
            db.add(
                models.Url(
                    device_id=device.id,
                    url=url_value,
                    url_type=str(form.get(f"url_type_{index_raw}") or item.get("url_type", "local")),
                    notes=f"Imported from Smart Paste {record.id}.",
                )
            )
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
        db.add(
            models.AuditLog(
                user_id=user.id,
                action="credential_created",
                object_type="credential",
                object_id=credential.id,
                details_json={"source": f"smart_paste:{record.id}"},
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
        },
        user=user,
    )


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
    if action == "mute-ping":
        if not mute_event_id:
            flash(request, "That ping warning could not be marked scheduled.", "warning")
            return redirect((request.headers.get("referer") or "/suggestions") + "#active-suggestions")
        mute_ping_failure(db, suggestion_id, mute_event_id)
        db.add(
            models.AuditLog(
                user_id=user.id,
                action="ping_warning_scheduled",
                object_type=object_type,
                object_id=object_id,
                details_json={"id": suggestion_id, "event_id": mute_event_id},
            )
        )
        db.commit()
        flash(request, "Ping warning marked as scheduled for this failed check.", "success")
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
    return render(
        request,
        "settings.html",
        {
            "app_settings": get_app_settings(db),
            "pending_totp_secret": pending_totp_secret,
            "pending_totp_uri": pending_totp_uri,
            "pending_totp_qr_svg": pending_totp_qr_svg,
            "tokens": _token_credentials(db),
            "devices": _device_order_query(db).all(),
            "webhook_url_saved": bool(_webhook_url(db)),
            "webhook_scope": _webhook_scope(db),
            "webhook_send_recovery": _webhook_recovery_enabled(db),
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
        value = str(form.get(key, THEME_DEFAULTS[key])).strip()
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
        set_app_setting(db, key, value)
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="settings_updated",
            object_type="app_settings",
            details_json={"section": "theme"},
        )
    )
    db.commit()
    flash(request, "Settings saved.", "success")
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
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    if not verify_password(password, user.password_hash):
        flash(request, "Incorrect password. 2FA setup was not started.", "danger")
        return redirect("/settings#two-factor")
    user.totp_enabled = False
    user.totp_secret_encrypted = encrypt_text(pyotp.random_base32())
    db.add(models.AuditLog(user_id=user.id, action="totp_setup_started", object_type="user", object_id=user.id))
    db.commit()
    flash(request, "2FA setup started. Add the manual key to your authenticator app, then verify a code.", "success")
    return redirect("/settings#two-factor")


@app.post("/settings/2fa/verify")
def settings_2fa_verify(
    request: Request,
    csrf: str = Form(...),
    code: str = Form(...),
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    check_csrf(request, csrf)
    ensure_writable()
    if not user.totp_secret_encrypted:
        flash(request, "Start 2FA setup first.", "warning")
        return redirect("/settings#two-factor")
    secret = decrypt_text(user.totp_secret_encrypted)
    if not pyotp.TOTP(secret).verify(code.strip().replace(" ", ""), valid_window=1):
        flash(request, "Incorrect 2FA code.", "danger")
        return redirect("/settings#two-factor")
    user.totp_enabled = True
    db.add(models.AuditLog(user_id=user.id, action="totp_enabled", object_type="user", object_id=user.id))
    db.commit()
    flash(request, "2FA is now enabled for login.", "success")
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
    if not verify_password(password, user.password_hash):
        flash(request, "Incorrect password. 2FA was not changed.", "danger")
        return redirect("/settings#two-factor")
    if user.totp_enabled and user.totp_secret_encrypted:
        secret = decrypt_text(user.totp_secret_encrypted)
        if not pyotp.TOTP(secret).verify(code.strip().replace(" ", ""), valid_window=1):
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


@app.get("/search", response_class=HTMLResponse)
def search_page(
    request: Request,
    q: str = "",
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    like = f"%{q}%"
    results: dict[str, list[Any]] = {"devices": [], "services": [], "credentials": [], "commands": [], "urls": [], "ports": [], "notes": []}
    if q:
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
            .limit(20)
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
            .limit(20)
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
            .limit(20)
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
            .limit(20)
            .all()
        )
        results["urls"] = db.query(models.Url).filter(models.Url.url.ilike(like)).limit(20).all()
        if q.isdigit():
            results["ports"] = db.query(models.Port).filter(models.Port.host_port == int(q)).limit(20).all()
        results["notes"] = (
            db.query(models.Note)
            .filter(or_(models.Note.title.ilike(like), models.Note.body.ilike(like)))
            .limit(20)
            .all()
        )
    related_devices: list[models.Device | None] = list(results["devices"])
    related_devices.extend(item.device for item in results["services"] if item.device)
    related_devices.extend(item.device for item in results["ports"] if item.device)
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


@app.get("/exports", response_class=HTMLResponse)
def exports_page(
    request: Request,
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    exports = db.query(models.BackupExport).order_by(models.BackupExport.created_at.desc()).all()
    return render(request, "exports.html", {"exports": exports}, user=user)


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
    if include_secrets and not challenge_ok(challenge, user.password_hash, user.secondary_password_hash):
        flash(request, "Credential export requires your account password or reveal password.", "danger")
        return redirect("/exports")
    created = create_emergency_export(db, include_credentials=include_secrets)
    db.add(
        models.AuditLog(
            user_id=user.id,
            action="emergency_export_created",
            object_type="backup_export",
            details_json={"files": [item.filename for item in created], "included_credentials": include_secrets},
        )
    )
    db.commit()
    flash(request, f"Emergency export created with {len(created)} file(s).", "success")
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


@app.get("/history", response_class=HTMLResponse)
def history_page(
    request: Request,
    kind: str = "",
    user: models.User = Depends(require_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    query = db.query(models.AuditLog)
    if kind == "ping":
        query = query.filter(models.AuditLog.action.in_(["device_ping", "service_validate", "services_validated", "ping_warning_scheduled", "webhook_sent", "webhook_failed", "webhook_test"]))
    elif kind == "credentials":
        query = query.filter(models.AuditLog.action.ilike("credential_%"))
    elif kind == "smart-paste":
        query = query.filter(models.AuditLog.action.ilike("smart_paste_%"))
    logs = query.order_by(models.AuditLog.created_at.desc()).limit(200).all()
    human_logs = [_human_audit_log(db, item) for item in logs]
    return render(request, "history.html", {"logs": human_logs, "kind": kind}, user=user)


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
