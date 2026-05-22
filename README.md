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

To generate strong first-run values for Portainer or `.env`:

```bash
python generate-portainer-env.py
```

For an HTTPS install:

```bash
python generate-portainer-env.py --secure-cookie
```

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
- Smart Paste encrypts detected secrets in pending import data and redacts them from preserved raw notes.
- Optional TOTP 2FA can be enabled from Settings after confirming your password.
- Docker API control is intentionally not part of this MVP.

## Development

Useful checks:

```bash
python -m py_compile app/kairix/*.py
docker compose --env-file .env.example config --quiet
```

This project does not include remote command execution. Commands are documented and copyable by design.

## Portainer Install

Kairix Opsbook can be deployed from Git in Portainer with `portainer-stack.yml`.

1. In Portainer, open **Stacks** and choose **Add stack**.
2. Use **Git Repository**.
3. Repository URL: `https://github.com/Dubcodes/Kairix-Opsbook.git`
4. Branch/reference: `main`
5. Compose path: `portainer-stack.yml`
6. Add environment variables before deploying:

```text
APP_PORT=8095
POSTGRES_DB=opsbook
POSTGRES_USER=opsbook
POSTGRES_PASSWORD=make-a-long-random-password
OPSBOOK_SECRET_KEY=make-a-long-random-secret
EXPORT_SECRET_KEY=make-another-long-random-secret
SESSION_SECRET_KEY=make-one-more-long-random-secret
SESSION_COOKIE_SECURE=false
```

You can generate those values locally instead of typing long random strings:

```bash
python generate-portainer-env.py
```

Copy the output into Portainer's environment variable editor. Use the same `OPSBOOK_SECRET_KEY` and `EXPORT_SECRET_KEY` on a standby instance if it needs to import/decrypt backups from the primary.

The Portainer stack stores data in named Docker volumes:

```text
kairix-opsbook-postgres
kairix-opsbook-exports
kairix-opsbook-backups
```

Do not delete `kairix-opsbook-postgres` unless you intentionally want to wipe the app.

## Updating A Portainer Install

The GitHub Actions workflow publishes `ghcr.io/dubcodes/kairix-opsbook:latest` on pushes to `main`.

To update:

1. Push or merge changes to `main`.
2. Wait for the **Build and publish Docker image** action to pass.
3. In Portainer, pull/redeploy the stack so it downloads the newest `latest` image.

If Portainer cannot pull the image, check that the GitHub Container Registry package is public or configure registry authentication in Portainer.

## Primary And Standby

Use `INSTANCE_MODE=primary` for the normal writable instance.

Use `INSTANCE_MODE=standby` for a secondary read-only instance. The standby instance should use the same `OPSBOOK_SECRET_KEY` and `EXPORT_SECRET_KEY` as the primary so encrypted credentials and encrypted exports can be decrypted after import.

A simple standby flow is:

1. Create an Emergency Export on the primary.
2. Copy the encrypted backup file to the standby.
3. Import it from the standby Emergency Export page.
4. Keep the standby read-only until the primary is unavailable.
5. To promote standby, set `INSTANCE_MODE=primary` and restart the stack.

Avoid writing to both instances at once. Multi-master sync is intentionally not part of the MVP.
