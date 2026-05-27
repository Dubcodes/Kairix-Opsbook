from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

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


def muted_ping_failures(db: Session) -> dict[str, str]:
    row = db.query(models.AppSetting).filter_by(key="muted_ping_failures").first()
    if not row or not row.value:
        return {}
    try:
        value = json.loads(row.value)
    except json.JSONDecodeError:
        return {}
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def mute_ping_failure(db: Session, suggestion_id: str, event_id: str) -> None:
    muted = muted_ping_failures(db)
    muted[suggestion_id] = str(event_id)
    value = json.dumps(muted, sort_keys=True)
    row = db.query(models.AppSetting).filter_by(key="muted_ping_failures").first()
    if row:
        row.value = value
    else:
        db.add(models.AppSetting(key="muted_ping_failures", value=value))


def visible_suggestions(db: Session) -> list[dict[str, str]]:
    dismissed = dismissed_suggestion_ids(db)
    muted = muted_ping_failures(db)
    return _group_repeated_suggestions(
        [
            item
            for item in build_suggestions(db)
            if item["id"] not in dismissed
            and not (item.get("mute_event_id") and muted.get(item["id"]) == str(item["mute_event_id"]))
        ],
        dismissed,
    )


def _group_repeated_suggestions(items: list[dict[str, str]], dismissed: set[str]) -> list[dict[str, str]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    passthrough: list[dict[str, str]] = []
    for item in items:
        group_id = item.get("group_id", "")
        if group_id:
            grouped[group_id].append(item)
        else:
            passthrough.append(item)
    result = list(passthrough)
    severity_rank = {"info": 0, "warning": 1, "danger": 2}
    for group_id, members in grouped.items():
        if group_id in dismissed:
            continue
        if len(members) < 4:
            result.extend(members)
            continue
        names = [member.get("subject", member["title"]) for member in members]
        sample = ", ".join(names[:8])
        if len(names) > 8:
            sample += f", and {len(names) - 8} more"
        result.append(
            {
                "id": group_id,
                "severity": max((member["severity"] for member in members), key=lambda item: severity_rank.get(item, 0)),
                "title": members[0].get("group_title", f"{len(members)} related suggestions"),
                "body": f"{sample}.",
                "target": members[0].get("group_target", members[0]["target"]),
                "count": str(len(members)),
            }
        )
    return sorted(result, key=lambda item: (severity_rank.get(item["severity"], 0) * -1, item["title"].lower()))


def build_suggestions(db: Session) -> list[dict[str, str]]:
    suggestions: list[dict[str, str]] = []

    for device in db.query(models.Device).order_by(models.Device.display_order, models.Device.name).all():
        device_tags = {
            row[0]
            for row in db.query(models.Tag.name)
            .join(models.TagLink, models.TagLink.tag_id == models.Tag.id)
            .filter(models.TagLink.object_type == "device", models.TagLink.object_id == device.id)
            .all()
        }
        if not device.purpose.strip():
            suggestions.append(
                {
                    "id": f"device:{device.id}:missing-purpose",
                    "severity": "info",
                    "title": f"{device.name} is missing a purpose",
                    "body": "Add a short purpose so future-you can remember why this machine exists.",
                    "target": f"/devices/{device.id}/edit?focus=purpose",
                    "action": "device-purpose",
                    "object_type": "device",
                    "object_id": str(device.id),
                    "placeholder": "Example: Docker host for media, backups, and Portainer.",
                }
            )
        if any(word in (device.status_manual or "").lower() for word in ["needs", "attention", "broken", "offline"]):
            suggestions.append(
                {
                    "id": f"device:{device.id}:manual-state-attention",
                    "severity": "warning",
                    "title": f"{device.name} is marked {device.status_manual}",
                    "body": "This manual state means the device needs a follow-up. Update the state once it is resolved.",
                    "target": f"/devices/{device.id}",
                }
            )
        if {"needs-attention", "broken"} & device_tags:
            suggestions.append(
                {
                    "id": f"device:{device.id}:attention-tag",
                    "severity": "warning",
                    "title": f"{device.name} is tagged for attention",
                    "body": "This device has an attention tag. Remove the tag once the follow-up is handled.",
                    "target": f"/devices/{device.id}",
                }
            )
        latest_ping = (
            db.query(models.AuditLog)
            .filter(
                models.AuditLog.object_type == "device",
                models.AuditLog.object_id == device.id,
                models.AuditLog.action == "device_ping",
            )
            .order_by(models.AuditLog.created_at.desc())
            .first()
        )
        failure_limit_row = db.query(models.AppSetting).filter_by(key="ping_failures_before_warning").first()
        try:
            failure_limit = max(1, int(failure_limit_row.value)) if failure_limit_row else 3
        except ValueError:
            failure_limit = 3
        if latest_ping and int((latest_ping.details_json or {}).get("failures") or 0) >= failure_limit:
            suggestions.append(
                {
                    "id": f"device:{device.id}:ping-failing",
                    "severity": "danger",
                    "title": f"Device ping failing: {device.name}",
                    "body": "Repeated ping checks are not getting a reply. If this is expected, dismiss it or mark the current failed check expected.",
                    "target": f"/devices/{device.id}",
                    "action": "mute-ping",
                    "object_type": "device",
                    "object_id": str(device.id),
                    "mute_event_id": str(latest_ping.id),
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

    for service in (
        db.query(models.Service)
        .join(models.Device, models.Service.device_id == models.Device.id)
        .order_by(models.Device.display_order, models.Device.name, models.Service.name)
        .all()
    ):
        service_tags = {
            row[0]
            for row in db.query(models.Tag.name)
            .join(models.TagLink, models.TagLink.tag_id == models.Tag.id)
            .filter(models.TagLink.object_type == "service", models.TagLink.object_id == service.id)
            .all()
        }
        if not service.backup_path and "backup" not in service.notes.lower():
            suggestions.append(
                {
                    "id": f"service:{service.id}:missing-backup",
                    "severity": "warning",
                    "title": f"{service.name} has no backup notes",
                    "body": "Document what data matters, where it is stored, and the restore command.",
                    "target": f"/services/{service.id}/edit?focus=backup_path",
                    "subject": service.name,
                    "group_id": f"group:device:{service.device_id}:missing-backup",
                    "group_title": f"{service.device.name}: services missing backup notes",
                    "group_target": f"/devices/{service.device_id}?tab=services&highlight=missing-backup",
                    "action": "service-backup",
                    "object_type": "service",
                    "object_id": str(service.id),
                    "placeholder": "Backup path or note, e.g. /srv/backups/service-name",
                }
            )
        if not service.purpose.strip():
            suggestions.append(
                {
                    "id": f"service:{service.id}:missing-purpose",
                    "severity": "info",
                    "title": f"{service.name} is missing a purpose",
                    "body": "A one-line purpose makes search and emergency runbooks much easier.",
                    "target": f"/services/{service.id}/edit?focus=purpose",
                    "subject": service.name,
                    "group_id": f"group:device:{service.device_id}:missing-purpose",
                    "group_title": f"{service.device.name}: services missing a purpose",
                    "group_target": f"/devices/{service.device_id}?tab=services&highlight=missing-purpose",
                    "action": "service-purpose",
                    "object_type": "service",
                    "object_id": str(service.id),
                    "placeholder": "Example: Web UI for managing Docker containers.",
                }
            )
        if any(word in (service.status_manual or "").lower() for word in ["needs", "attention", "broken", "offline"]):
            suggestions.append(
                {
                    "id": f"service:{service.id}:manual-state-attention",
                    "severity": "warning",
                    "title": f"{service.name} is marked {service.status_manual}",
                    "body": "This manual state means the service needs a follow-up. Update the state once it is resolved.",
                    "target": f"/services/{service.id}",
                }
            )
        if {"needs-attention", "broken"} & service_tags:
            suggestions.append(
                {
                    "id": f"service:{service.id}:attention-tag",
                    "severity": "warning",
                    "title": f"{service.name} is tagged for attention",
                    "body": "This service has an attention tag. Remove the tag once the follow-up is handled.",
                    "target": f"/services/{service.id}",
                }
            )
        latest_validation = (
            db.query(models.AuditLog)
            .filter(
                models.AuditLog.object_type == "service",
                models.AuditLog.object_id == service.id,
                models.AuditLog.action == "service_validate",
            )
            .order_by(models.AuditLog.created_at.desc())
            .first()
        )
        if latest_validation:
            details = latest_validation.details_json or {}
            if int(details.get("checked") or 0) and not details.get("ok") and not details.get("partial"):
                targets = details.get("targets") or []
                target_label = ""
                if targets and isinstance(targets, list):
                    failed = [target for target in targets if isinstance(target, dict) and not target.get("ok")]
                    target_label = str(((failed[0] if failed else targets[0]) or {}).get("label") or "")
                suggestions.append(
                    {
                        "id": f"service:{service.id}:validation-failing",
                        "severity": "danger",
                        "title": f"Service check failing: {service.name}",
                        "body": f"Last service reachability check failed{f' for {target_label}' if target_label else ''}. Confirm the URL, port, service state, or dismiss it if this service is intentionally offline.",
                        "target": f"/services/{service.id}",
                        "action": "mute-ping",
                        "object_type": "service",
                        "object_id": str(service.id),
                        "mute_event_id": str(latest_validation.id),
                    }
                )
    ports: dict[tuple[int, int, str], list[models.Port]] = defaultdict(list)
    for port in db.query(models.Port).all():
        ports[(port.device_id, port.host_port, port.protocol)].append(port)
    for (device_id, host_port, protocol), matches in ports.items():
        if len(matches) > 1:
            names = ", ".join(
                port.service.name if port.service else port.device.name for port in matches
            )
            loose_count = sum(1 for port in matches if not port.service_id)
            suggestions.append(
                {
                    "id": f"device:{device_id}:port:{host_port}:{protocol}:duplicate",
                    "severity": "warning",
                    "title": f"Duplicate {protocol.upper()} port {host_port}",
                    "body": f"Multiple entries on the same device mention this port: {names}."
                    + (" Quick cleanup can remove loose duplicates." if loose_count else " Open Ports & URLs and keep the correct service link."),
                    "target": "/ports",
                    "action": "duplicate-port-cleanup" if loose_count else "",
                    "object_type": "port",
                    "object_id": str(device_id),
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
        if cred.secret_type == "API token" and cred.expires_at:
            now = datetime.now(timezone.utc)
            expiry = cred.expires_at if cred.expires_at.tzinfo else cred.expires_at.replace(tzinfo=timezone.utc)
            if expiry < now:
                suggestions.append(
                    {
                        "id": f"credential:{cred.id}:token-expired",
                        "severity": "warning",
                        "title": f"{cred.label} has expired",
                        "body": "Rotate or delete this token so you do not trust a dead credential later.",
                        "target": f"/credentials/{cred.id}",
                    }
                )
            elif expiry <= now + timedelta(days=7):
                suggestions.append(
                    {
                        "id": f"credential:{cred.id}:token-expiring",
                        "severity": "info",
                        "title": f"{cred.label} expires soon",
                        "body": "This temporary token expires within the next week.",
                        "target": f"/credentials/{cred.id}",
                    }
                )

    suggestions.extend(
        [
            {
                "id": "advice:docker-folder-layout",
                "severity": "info",
                "title": "Suggested Docker folder layout",
                "body": "/home/example/docker/service-name with docker-compose.yml, data, and backups folders is easy to scan.",
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
