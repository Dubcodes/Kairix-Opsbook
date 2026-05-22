from __future__ import annotations

from collections import defaultdict

import json

from sqlalchemy.orm import Session

from . import models


TAG_IDEAS = [
    {
        "title": "Use status tags",
        "body": "Good starter tags: production, testing, critical, broken, migrate-later, needs-backup.",
    },
    {
        "title": "Separate exposure from importance",
        "body": "Use public-url or private-only for access, then critical or low-risk for importance.",
    },
    {
        "title": "Tag Docker stacks by project",
        "body": "For grouped stacks, tags like people-system, immich, cloudflare-tunnels, graphics, and infrastructure make search faster.",
    },
    {
        "title": "Tag cleanup work",
        "body": "Use needs-purpose, needs-backup, needs-restore-notes, or needs-security-note when importing rough notes.",
    },
    {
        "title": "Keep tags short and boring",
        "body": "Lowercase tags with hyphens are easiest to scan: docker-host, portainer, cloudflare, media, backup.",
    },
]


def dismissed_suggestion_ids(db: Session) -> set[str]:
    row = db.query(models.AppSetting).filter_by(key="dismissed_suggestions").first()
    if not row or not row.value:
        return set()
    try:
        value = json.loads(row.value)
    except json.JSONDecodeError:
        return set()
    if not isinstance(value, list):
        return set()
    return {str(item) for item in value}


def dismiss_suggestion(db: Session, suggestion_id: str) -> None:
    dismissed = dismissed_suggestion_ids(db)
    dismissed.add(suggestion_id)
    row = db.query(models.AppSetting).filter_by(key="dismissed_suggestions").first()
    value = json.dumps(sorted(dismissed))
    if row:
        row.value = value
    else:
        db.add(models.AppSetting(key="dismissed_suggestions", value=value))


def visible_suggestions(db: Session) -> list[dict[str, str]]:
    dismissed = dismissed_suggestion_ids(db)
    return [item for item in build_suggestions(db) if item["id"] not in dismissed]


def build_suggestions(db: Session) -> list[dict[str, str]]:
    suggestions: list[dict[str, str]] = []

    for device in db.query(models.Device).order_by(models.Device.name).all():
        if not device.purpose.strip():
            suggestions.append(
                {
                    "id": f"device:{device.id}:missing-purpose",
                    "severity": "info",
                    "title": f"{device.name} is missing a purpose",
                    "body": "Add a short purpose so future-you can remember why this machine exists.",
                    "target": f"/devices/{device.id}",
                }
            )
    devices_by_ip: dict[str, list[models.Device]] = defaultdict(list)
    for device in db.query(models.Device).filter(models.Device.primary_ip != "").all():
        devices_by_ip[device.primary_ip].append(device)
    for ip, matches in devices_by_ip.items():
        if len(matches) > 1:
            names = ", ".join(device.name for device in matches)
            suggestions.append(
                {
                    "id": f"device-ip:{ip}:possible-duplicate",
                    "severity": "warning",
                    "title": f"Possible duplicate devices for {ip}",
                    "body": f"These devices share the same IP: {names}. Keep the better record and delete or merge the other.",
                    "target": "/devices",
                }
            )

    for service in db.query(models.Service).order_by(models.Service.name).all():
        if not service.backup_path and "backup" not in service.notes.lower():
            suggestions.append(
                {
                    "id": f"service:{service.id}:missing-backup",
                    "severity": "warning",
                    "title": f"{service.name} has no backup notes",
                    "body": "Document what data matters, where it is stored, and the restore command.",
                    "target": f"/services/{service.id}",
                }
            )
        if not service.purpose.strip():
            suggestions.append(
                {
                    "id": f"service:{service.id}:missing-purpose",
                    "severity": "info",
                    "title": f"{service.name} is missing a purpose",
                    "body": "A one-line purpose makes search and emergency runbooks much easier.",
                    "target": f"/services/{service.id}",
                }
            )
        if service.public_url and not any(
            word in service.notes.lower()
            for word in ["access", "auth", "cloudflare", "security", "login"]
        ):
            suggestions.append(
                {
                    "id": f"service:{service.id}:public-url-security-note",
                    "severity": "warning",
                    "title": f"{service.name} has a public URL without a security note",
                    "body": "Add how access is protected, such as Cloudflare Access, app login, VPN, or private-only notes.",
                    "target": f"/services/{service.id}",
                }
            )

    ports: dict[tuple[int, str], list[models.Port]] = defaultdict(list)
    for port in db.query(models.Port).all():
        ports[(port.host_port, port.protocol)].append(port)
    for (host_port, protocol), matches in ports.items():
        if len(matches) > 1:
            names = ", ".join(
                port.service.name if port.service else port.device.name for port in matches
            )
            suggestions.append(
                {
                    "id": f"port:{host_port}:{protocol}:duplicate",
                    "severity": "warning",
                    "title": f"Duplicate {protocol.upper()} port {host_port}",
                    "body": f"Multiple entries mention this port: {names}. Confirm this is intentional.",
                    "target": "/ports",
                }
            )

    for cred in db.query(models.Credential).filter(models.Credential.active.is_(True)).all():
        label = f"{cred.label} {cred.username}".lower()
        if cred.security_level == "low" and any(word in label for word in ["root", "sudo", "admin"]):
            suggestions.append(
                {
                    "id": f"credential:{cred.id}:low-security-admin",
                    "severity": "danger",
                    "title": f"{cred.label} may be too low-security",
                    "body": "Root, sudo, and admin credentials should usually be Medium or higher.",
                    "target": f"/credentials/{cred.id}/edit",
                }
            )

    suggestions.extend(
        [
            {
                "id": "advice:docker-folder-layout",
                "severity": "info",
                "title": "Suggested Docker folder layout",
                "body": "/home/mainuser/docker/service-name with docker-compose.yml, data, and backups folders is easy to scan.",
                "target": "/commands",
            },
            {
                "id": "advice:port-bands",
                "severity": "info",
                "title": "Suggested port bands",
                "body": "Consider 3000-3099 for web tools, 5000-5099 for APIs, 8000-8999 for admin tools, and 9000-9099 for infrastructure dashboards.",
                "target": "/ports",
            },
        ]
    )

    return suggestions
