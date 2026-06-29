from __future__ import annotations

import hashlib
import html
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from . import models
from .config import settings
from .security import decrypt_text, encrypt_text


def _iso(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return value


def table_dump(db: Session, model: type[Any], *, include_secret_plaintext: bool = False) -> list[dict[str, Any]]:
    rows = []
    for obj in db.query(model).all():
        data = {column.name: _iso(getattr(obj, column.name)) for column in model.__table__.columns}
        if isinstance(obj, models.Credential) and include_secret_plaintext:
            data["secret_plaintext"] = decrypt_text(obj.secret_encrypted)
        rows.append(data)
    return rows


def build_backup_payload(db: Session) -> dict[str, Any]:
    return {
        "metadata": {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "source_instance": settings.instance_name,
            "app_version": settings.app_version,
            "database_version": "schema-create-all-v1",
            "encrypted": True,
            "excluded_tables": ["device_stat_snapshots"],
            "exclusion_notes": "High-frequency agent telemetry is excluded from emergency recovery backups.",
        },
        "tables": {
            "users": table_dump(db, models.User),
            "devices": table_dump(db, models.Device),
            "device_hardware": table_dump(db, models.DeviceHardware),
            "services": table_dump(db, models.Service),
            "credentials": table_dump(db, models.Credential),
            "commands": table_dump(db, models.Command),
            "recipes": table_dump(db, models.Recipe),
            "recipe_steps": table_dump(db, models.RecipeStep),
            "urls": table_dump(db, models.Url),
            "ports": table_dump(db, models.Port),
            "tags": table_dump(db, models.Tag),
            "tag_links": table_dump(db, models.TagLink),
            "notes": table_dump(db, models.Note),
            "device_images": table_dump(db, models.DeviceImage),
            "user_suggestions": table_dump(db, models.UserSuggestion),
            "imports": table_dump(db, models.ImportRecord),
            "audit_log": table_dump(db, models.AuditLog),
            "backup_exports": table_dump(db, models.BackupExport),
        },
    }


def build_secrets_payload(db: Session) -> dict[str, Any]:
    return {
        "metadata": {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "source_instance": settings.instance_name,
            "app_version": settings.app_version,
            "encrypted": True,
            "warning": "Contains decrypted credential values. Store with care.",
        },
        "credentials": table_dump(db, models.Credential, include_secret_plaintext=True),
    }


def build_runbook_html(db: Session) -> str:
    devices = db.query(models.Device).order_by(models.Device.name).all()
    body = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<title>Kairix Opsbook Emergency Runbook</title>",
        "<style>body{font-family:Arial,sans-serif;line-height:1.5;color:#17212b;padding:28px;max-width:1100px;margin:auto}",
        "h1,h2,h3{color:#0d3b45}code,pre{background:#f2f5f7;padding:3px 5px;border-radius:4px}",
        "section{border-top:1px solid #ccd6dd;padding-top:18px;margin-top:22px}.muted{color:#62717d}</style>",
        "</head><body>",
        "<h1>Kairix Opsbook Emergency Runbook</h1>",
        f"<p class='muted'>Exported {html.escape(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))} from {html.escape(settings.instance_name)}. Credentials are not included in this human-readable runbook.</p>",
    ]
    for device in devices:
        body.append(f"<section><h2>{html.escape(device.name)}</h2>")
        body.append(
            f"<p><strong>{html.escape(device.primary_ip or 'No IP')}</strong> · {html.escape(device.os_name or 'OS unknown')} · {html.escape(device.type or 'device')}</p>"
        )
        if device.purpose:
            body.append(f"<p>{html.escape(device.purpose)}</p>")
        if device.notes:
            body.append(f"<h3>Notes</h3><pre>{html.escape(device.notes)}</pre>")
        if device.hardware:
            hw = device.hardware
            body.append("<h3>Hardware</h3><ul>")
            for label, value in [
                ("Model", hw.model),
                ("CPU", hw.cpu),
                ("RAM", hw.ram),
                ("GPU", hw.gpu),
                ("Storage", hw.storage_summary),
            ]:
                if value:
                    body.append(f"<li><strong>{label}:</strong> {html.escape(value)}</li>")
            body.append("</ul>")
        if device.services:
            body.append("<h3>Services</h3>")
            for service in sorted(device.services, key=lambda item: item.name.lower()):
                body.append(f"<h4>{html.escape(service.name)}</h4>")
                body.append("<ul>")
                for label, value in [
                    ("Purpose", service.purpose),
                    ("Local URL", service.local_url),
                    ("Public URL", service.public_url),
                    ("Repo", service.repo_url),
                    ("Compose path", service.compose_path),
                    ("Data path", service.data_path),
                    ("Backup path", service.backup_path),
                ]:
                    if value:
                        body.append(f"<li><strong>{label}:</strong> {html.escape(value)}</li>")
                body.append("</ul>")
                if service.notes:
                    body.append(f"<pre>{html.escape(service.notes)}</pre>")
        commands = (
            db.query(models.Command)
            .filter(
                (models.Command.applies_to_type == "device")
                & (models.Command.applies_to_id == device.id)
            )
            .all()
        )
        if commands:
            body.append("<h3>Device Commands</h3>")
            for command in commands:
                body.append(
                    f"<h4>{html.escape(command.name)}</h4><pre>{html.escape(command.command_template)}</pre>"
                )
        body.append("</section>")
    body.append("</body></html>")
    return "\n".join(body)


def _write(path: Path, content: str | bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = content if isinstance(content, bytes) else content.encode("utf-8")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return hashlib.sha256(data).hexdigest()


def create_emergency_export(db: Session, *, include_credentials: bool = False) -> list[models.BackupExport]:
    export_dir = Path(settings.export_dir)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    created: list[models.BackupExport] = []

    payload = json.dumps(build_backup_payload(db), default=str, separators=(",", ":"))
    encrypted_backup = encrypt_text(payload, export=True)
    backup_name = f"kairix-opsbook-backup-{stamp}.enc"
    checksum = _write(export_dir / backup_name, encrypted_backup)
    created.append(
        models.BackupExport(
            filename=backup_name,
            export_type="database",
            encrypted=True,
            checksum=checksum,
            notes="Full encrypted recovery backup. High-frequency stats telemetry excluded.",
        )
    )

    runbook_name = f"kairix-opsbook-runbook-{stamp}.html"
    checksum = _write(export_dir / runbook_name, build_runbook_html(db))
    created.append(
        models.BackupExport(
            filename=runbook_name,
            export_type="runbook_html",
            encrypted=False,
            checksum=checksum,
            notes="Human-readable emergency runbook. Secrets excluded.",
        )
    )

    if include_credentials:
        secret_payload = json.dumps(build_secrets_payload(db), default=str, separators=(",", ":"))
        encrypted_secrets = encrypt_text(secret_payload, export=True)
        secret_name = f"kairix-opsbook-secrets-{stamp}.enc"
        checksum = _write(export_dir / secret_name, encrypted_secrets)
        created.append(
            models.BackupExport(
                filename=secret_name,
                export_type="credentials",
                encrypted=True,
                checksum=checksum,
                notes="Encrypted credential export containing decrypted secret values.",
            )
        )

    for record in created:
        db.add(record)
    db.commit()
    return created


def safe_export_path(filename: str) -> Path:
    clean = os.path.basename(filename)
    return Path(settings.export_dir) / clean
