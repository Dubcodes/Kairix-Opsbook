# Opsbook Next Features

These items need schema and security design before implementation.

## Device Images

Purpose: store receipts, serial-label photos, warranty screenshots, rack photos, and other device evidence.

Suggested model:
- Image belongs to a device, optionally to a service.
- Fields: name, image date, tags, notes, original filename, stored filename, MIME type, size, optional OCR text.
- Keep uploads outside the database, with database metadata and an emergency-export include path.
- OCR should be optional and best-effort. If added, store extracted text as searchable metadata and never overwrite the user notes.

## Custom Suggestions

Purpose: user-created reminders that appear in Warnings & Suggestions at a chosen date/time.

Suggested model:
- Title, subtitle/body, due date, optional due time, severity, tags, optional image, optional device or service link.
- Hidden until due, then appears as a normal dismissible suggestion tile.
- Useful examples: cancel subscription, renew certificate, check warranty, follow up with vendor.

## Password Recovery

Purpose: recover access without weakening normal login.

Suggested flow:
- User creates a long recovery phrase in Settings.
- Phrase must be sentence-length and include uppercase, lowercase, number, and special character.
- Login accepts the recovery phrase and then requires a recognition challenge.
- Recognition challenge should show six services, with three real recent services and three decoys. The user must pick the three real services.
- On success, route only to Settings account security so the user can change the password.

Risk notes:
- This must be rate-limited and audited.
- Decoy generation must not reveal too much inventory detail to an attacker.
- It should recommend setup when enabling 2FA.

## SSH Health Checks

Purpose: optional deeper checks for CPU, RAM, disk, Docker status, and service health.

Recommendation:
- Do not put raw SSH into the web app first.
- Prefer a small read-only agent on each host that reports safe stats to Opsbook, or use SSH only with a dedicated least-privilege key.
- Treat this as optional telemetry, not required for the core runbook.
