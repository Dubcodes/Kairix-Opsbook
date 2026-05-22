from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(160), default="")
    password_hash: Mapped[str] = mapped_column(Text)
    secondary_password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    role: Mapped[str] = mapped_column(String(40), default="owner")
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)


class Device(Base, TimestampMixin):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(180), index=True)
    slug: Mapped[str] = mapped_column(String(220), unique=True, index=True)
    type: Mapped[str] = mapped_column(String(100), default="server")
    purpose: Mapped[str] = mapped_column(Text, default="")
    hostname: Mapped[str] = mapped_column(String(180), default="")
    primary_ip: Mapped[str] = mapped_column(String(80), default="", index=True)
    os_name: Mapped[str] = mapped_column(String(160), default="")
    os_version: Mapped[str] = mapped_column(String(120), default="")
    location: Mapped[str] = mapped_column(String(160), default="")
    status_manual: Mapped[str] = mapped_column(String(80), default="")
    update_check_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    update_status: Mapped[str] = mapped_column(String(160), default="")
    display_order: Mapped[int] = mapped_column(Integer, default=1000)
    notes: Mapped[str] = mapped_column(Text, default="")

    hardware: Mapped["DeviceHardware"] = relationship(
        back_populates="device", cascade="all, delete-orphan", uselist=False
    )
    services: Mapped[list["Service"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
    credentials: Mapped[list["Credential"]] = relationship(back_populates="device")
    ports: Mapped[list["Port"]] = relationship(back_populates="device")
    urls: Mapped[list["Url"]] = relationship(back_populates="device")


class DeviceHardware(Base):
    __tablename__ = "device_hardware"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), unique=True)
    device: Mapped[Device] = relationship(back_populates="hardware")
    device_type: Mapped[str] = mapped_column(String(100), default="")
    model: Mapped[str] = mapped_column(String(180), default="")
    cpu: Mapped[str] = mapped_column(Text, default="")
    ram: Mapped[str] = mapped_column(Text, default="")
    gpu: Mapped[str] = mapped_column(Text, default="")
    storage_summary: Mapped[str] = mapped_column(Text, default="")
    serial_optional: Mapped[str] = mapped_column(String(180), default="")
    usb_devices: Mapped[str] = mapped_column(Text, default="")
    network_adapters: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="")


class Service(Base, TimestampMixin):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    device: Mapped[Device] = relationship(back_populates="services")
    name: Mapped[str] = mapped_column(String(180), index=True)
    slug: Mapped[str] = mapped_column(String(220), index=True)
    type: Mapped[str] = mapped_column(String(100), default="")
    purpose: Mapped[str] = mapped_column(Text, default="")
    status_manual: Mapped[str] = mapped_column(String(80), default="")
    local_url: Mapped[str] = mapped_column(String(500), default="")
    public_url: Mapped[str] = mapped_column(String(500), default="")
    repo_url: Mapped[str] = mapped_column(String(500), default="")
    compose_path: Mapped[str] = mapped_column(String(500), default="")
    data_path: Mapped[str] = mapped_column(String(500), default="")
    config_path: Mapped[str] = mapped_column(String(500), default="")
    log_path: Mapped[str] = mapped_column(String(500), default="")
    backup_path: Mapped[str] = mapped_column(String(500), default="")
    docker_project: Mapped[str] = mapped_column(String(180), default="")
    container_name: Mapped[str] = mapped_column(String(180), default="")
    image: Mapped[str] = mapped_column(String(260), default="")
    notes: Mapped[str] = mapped_column(Text, default="")

    credentials: Mapped[list["Credential"]] = relationship(back_populates="service")
    ports: Mapped[list["Port"]] = relationship(back_populates="service")
    urls: Mapped[list["Url"]] = relationship(back_populates="service")


class Credential(Base, TimestampMixin):
    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id"), nullable=True)
    device: Mapped[Device | None] = relationship(back_populates="credentials")
    service: Mapped[Service | None] = relationship(back_populates="credentials")
    label: Mapped[str] = mapped_column(String(180), index=True)
    username: Mapped[str] = mapped_column(String(180), default="", index=True)
    secret_encrypted: Mapped[str] = mapped_column(Text)
    secret_type: Mapped[str] = mapped_column(String(80), default="password")
    security_level: Mapped[str] = mapped_column(String(40), default="low")
    login_url: Mapped[str] = mapped_column(String(500), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_revealed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Command(Base, TimestampMixin):
    __tablename__ = "commands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(180), index=True)
    category: Mapped[str] = mapped_column(String(100), index=True)
    applies_to_type: Mapped[str] = mapped_column(String(60), default="generic")
    applies_to_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    command_template: Mapped[str] = mapped_column(Text)
    short_description: Mapped[str] = mapped_column(Text, default="")
    long_description: Mapped[str] = mapped_column(Text, default="")
    where_to_run: Mapped[str] = mapped_column(String(260), default="Remote SSH host")
    risk_level: Mapped[str] = mapped_column(String(40), default="safe")
    help_low: Mapped[str] = mapped_column(Text, default="")
    help_high: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="")


class Recipe(Base, TimestampMixin):
    __tablename__ = "recipes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(180), index=True)
    category: Mapped[str] = mapped_column(String(100), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    risk_level: Mapped[str] = mapped_column(String(40), default="safe")
    steps: Mapped[list["RecipeStep"]] = relationship(
        back_populates="recipe", cascade="all, delete-orphan", order_by="RecipeStep.position"
    )


class RecipeStep(Base):
    __tablename__ = "recipe_steps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    recipe_id: Mapped[int] = mapped_column(ForeignKey("recipes.id"), index=True)
    recipe: Mapped[Recipe] = relationship(back_populates="steps")
    position: Mapped[int] = mapped_column(Integer, default=1)
    title: Mapped[str] = mapped_column(String(180), default="")
    explanation: Mapped[str] = mapped_column(Text, default="")
    command_id: Mapped[int | None] = mapped_column(ForeignKey("commands.id"), nullable=True)
    command_text: Mapped[str] = mapped_column(Text, default="")


class Url(Base):
    __tablename__ = "urls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id"), nullable=True)
    device: Mapped[Device | None] = relationship(back_populates="urls")
    service: Mapped[Service | None] = relationship(back_populates="urls")
    label: Mapped[str] = mapped_column(String(180), default="")
    url: Mapped[str] = mapped_column(String(500), index=True)
    url_type: Mapped[str] = mapped_column(String(80), default="local")
    notes: Mapped[str] = mapped_column(Text, default="")


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id"), nullable=True)
    device: Mapped[Device] = relationship(back_populates="ports")
    service: Mapped[Service | None] = relationship(back_populates="ports")
    internal_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    host_port: Mapped[int] = mapped_column(Integer, index=True)
    protocol: Mapped[str] = mapped_column(String(20), default="tcp")
    purpose: Mapped[str] = mapped_column(String(180), default="")
    notes: Mapped[str] = mapped_column(Text, default="")


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    color_optional: Mapped[str] = mapped_column(String(40), default="")


class TagLink(Base):
    __tablename__ = "tag_links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tag_id: Mapped[int] = mapped_column(ForeignKey("tags.id"), index=True)
    object_type: Mapped[str] = mapped_column(String(40), index=True)
    object_id: Mapped[int] = mapped_column(Integer, index=True)


class Note(Base, TimestampMixin):
    __tablename__ = "notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    object_type: Mapped[str] = mapped_column(String(40), index=True)
    object_id: Mapped[int] = mapped_column(Integer, index=True)
    title: Mapped[str] = mapped_column(String(180), default="")
    body: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(120), default="manual")


class ImportRecord(Base, TimestampMixin):
    __tablename__ = "imports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_type: Mapped[str] = mapped_column(String(80), default="raw_text")
    raw_text: Mapped[str] = mapped_column(Text)
    parsed_json: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(40), default="review")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(120), index=True)
    object_type: Mapped[str] = mapped_column(String(60), default="")
    object_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    details_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class BackupExport(Base):
    __tablename__ = "backup_exports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    filename: Mapped[str] = mapped_column(String(260), index=True)
    export_type: Mapped[str] = mapped_column(String(80), default="backup")
    encrypted: Mapped[bool] = mapped_column(Boolean, default=True)
    checksum: Mapped[str] = mapped_column(String(128), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AppSetting(Base):
    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    value: Mapped[str] = mapped_column(Text, default="")
