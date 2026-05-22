# Kairix Opsbook

Kairix Opsbook is a self-hosted operations notebook for servers, Docker stacks, credentials, commands, URLs, ports, backups, setup notes, and recovery notes.

It is designed to be fast like notes, structured like inventory, and safe like a vault. The app focuses on documenting what exists, where it runs, how to log in, what commands to copy, and how to recover it later.

## Features

- FastAPI web app with a simple server-rendered UI.
- PostgreSQL via Docker Compose.
- Owner setup, login sessions, CSRF-protected forms, and session timeout.
- Devices, services, credentials, commands, ports, URLs, notes, tags, search, and history.
- Read-only-first device and service pages.
- Encrypted credential storage with Low, Medium, High, and Extreme security levels.
- Credential reveal audit log.
- Copy-friendly command library with starter Linux, Docker, Docker Compose, Git, networking, and recovery commands.
- Smart Paste import with review-before-apply for notes, SSH output, Docker output, URLs, ports, paths, commands, and service login blocks.
- Suggestions for missing backup notes, duplicate ports, low-security admin credentials, and missing purpose fields.
- Emergency encrypted backup export, human-readable runbook HTML export, and encrypted import.
- Standby/read-only instance mode for backup servers.

## Quick Start

```bash
git clone https://github.com/Dubcodes/Kairix-Opsbook.git
cd Kairix-Opsbook
cp .env.example .env
nano .env
docker compose up -d --build
```

Open:

```text
http://SERVER-IP:8095
```

On first run, create the owner account. Change the database password and all secret keys in `.env` before storing real credentials.

## Configuration

Important `.env` values:

```text
APP_PORT=8095
INSTANCE_NAME=Opsbook
INSTANCE_MODE=primary
POSTGRES_PASSWORD=change-this-database-password
OPSBOOK_SECRET_KEY=change-this-secret-encryption-key
EXPORT_SECRET_KEY=change-this-export-encryption-key
SESSION_SECRET_KEY=change-this-session-signing-key
SESSION_COOKIE_SECURE=false
```

Set `SESSION_COOKIE_SECURE=true` when serving Kairix Opsbook behind HTTPS.

## Standby Mode

Set this in `.env` to make the UI read-only:

```text
INSTANCE_MODE=standby
```

The app will show a standby banner and block writes. To promote a standby manually, change `INSTANCE_MODE=primary` and restart the app.

## Smart Paste

Smart Paste can turn messy notes into structured suggestions. For example, a block like this:

```text
portainer
https://192.168.1.10:9443/
admin
example-password
```

is reviewed as one service/login suggestion with the URL, port, username, password, and service relationship kept together. Nothing is applied until you review and select it.

## Emergency Export And Import

The Emergency Export page can create:

- An encrypted database backup.
- A human-readable emergency runbook HTML file.
- An optional encrypted credentials export after a password/reveal challenge.

The same page can import an encrypted Kairix backup into a clean or standby instance.

## Important Security Notes

- Do not expose this app publicly without HTTPS and strong authentication.
- Change `OPSBOOK_SECRET_KEY`, `EXPORT_SECRET_KEY`, and `SESSION_SECRET_KEY` before entering real secrets.
- Keep `.env`, `data/`, `backups/`, and `exports/` out of Git.
- Passwords are hidden from normal list views and reveal events are logged.
- Docker API control is intentionally not part of this MVP.

## Development

Useful checks:

```bash
python -m py_compile app/kairix/*.py
docker compose --env-file .env.example config --quiet
```

This project does not include remote command execution. Commands are documented and copyable by design.
