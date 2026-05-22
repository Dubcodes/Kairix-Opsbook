from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "item"


def unique_slug(db: Session, model: type[Any], value: str, existing_id: int | None = None) -> str:
    base = slugify(value)
    slug = base
    counter = 2
    while True:
        stmt = select(model).where(model.slug == slug)
        existing = db.execute(stmt).scalar_one_or_none()
        if existing is None or (existing_id and existing.id == existing_id):
            return slug
        slug = f"{base}-{counter}"
        counter += 1


def split_tags(tags_text: str) -> list[str]:
    seen: set[str] = set()
    tags: list[str] = []
    for raw in re.split(r"[,#\n]", tags_text or ""):
        tag = slugify(raw)
        if tag and tag not in seen:
            seen.add(tag)
            tags.append(tag)
    return tags


def set_tags(db: Session, object_type: str, object_id: int, tags_text: str) -> None:
    db.query(models.TagLink).filter_by(
        object_type=object_type, object_id=object_id
    ).delete()
    for name in split_tags(tags_text):
        tag = db.execute(select(models.Tag).where(models.Tag.name == name)).scalar_one_or_none()
        if tag is None:
            tag = models.Tag(name=name)
            db.add(tag)
            db.flush()
        db.add(models.TagLink(tag_id=tag.id, object_type=object_type, object_id=object_id))


def tags_for(db: Session, object_type: str, object_id: int) -> list[str]:
    rows = (
        db.query(models.Tag.name)
        .join(models.TagLink, models.TagLink.tag_id == models.Tag.id)
        .filter(models.TagLink.object_type == object_type, models.TagLink.object_id == object_id)
        .order_by(models.Tag.name)
        .all()
    )
    return [row[0] for row in rows]


def tag_map(db: Session, object_type: str) -> dict[int, list[str]]:
    rows = (
        db.query(models.TagLink.object_id, models.Tag.name)
        .join(models.Tag, models.Tag.id == models.TagLink.tag_id)
        .filter(models.TagLink.object_type == object_type)
        .order_by(models.Tag.name)
        .all()
    )
    mapped: dict[int, list[str]] = defaultdict(list)
    for object_id, name in rows:
        mapped[object_id].append(name)
    return mapped


def format_dt(value: datetime | None) -> str:
    if not value:
        return "Never"
    return value.strftime("%Y-%m-%d %H:%M")


def render_template_vars(template: str, *, device: models.Device | None = None, service: models.Service | None = None) -> str:
    values = {
        "host": device.primary_ip if device else "",
        "hostname": device.hostname if device else "",
        "device_name": device.name if device else "",
        "username": "mainuser",
        "service_name": service.name if service else "",
        "service_path": service.compose_path or service.data_path if service else "",
        "repo_url": service.repo_url if service else "",
        "repo_folder": service.compose_path if service else "",
        "parent_folder": "/home/mainuser/docker",
        "folder": service.compose_path if service else "/srv",
        "container_name": service.container_name if service else "",
        "port": "",
    }
    if service and service.ports:
        values["port"] = str(service.ports[0].host_port)

    def replace(match: re.Match[str]) -> str:
        key = match.group(1).strip()
        return values.get(key, match.group(0))

    return re.sub(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}", replace, template)


def command_with_comments(command: models.Command) -> str:
    lines = [line.rstrip() for line in command.command_template.strip().splitlines()]
    if len(lines) <= 1:
        return command.command_template.strip()
    return "\n".join(lines)


def risk_label(risk: str) -> str:
    return {
        "safe": "Safe",
        "caution": "Caution",
        "dangerous": "Dangerous",
        "destructive": "Destructive",
    }.get(risk, risk.title())
