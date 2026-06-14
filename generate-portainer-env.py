from __future__ import annotations

import argparse
import secrets


def secret_value() -> str:
    return secrets.token_urlsafe(48)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate first-run environment variables for a Kairix Opsbook Portainer stack."
    )
    parser.add_argument("--port", default="8095", help="Host port to publish the web app on.")
    parser.add_argument("--image-tag", default="0.1.24", help="Versioned Opsbook image tag to deploy.")
    parser.add_argument("--instance", default="Opsbook", help="Instance name shown in the app header.")
    parser.add_argument("--mode", default="primary", choices=["primary", "standby"], help="Instance mode.")
    parser.add_argument(
        "--secure-cookie",
        action="store_true",
        help="Set SESSION_COOKIE_SECURE=true. Use this only when serving Opsbook over HTTPS.",
    )
    args = parser.parse_args()

    values = {
        "OPSBOOK_IMAGE_TAG": args.image_tag,
        "APP_PORT": args.port,
        "INSTANCE_NAME": args.instance,
        "INSTANCE_MODE": args.mode,
        "POSTGRES_DB": "opsbook",
        "POSTGRES_USER": "opsbook",
        "POSTGRES_PASSWORD": secret_value(),
        "OPSBOOK_SECRET_KEY": secret_value(),
        "EXPORT_SECRET_KEY": secret_value(),
        "SESSION_SECRET_KEY": secret_value(),
        "OPSBOOK_AGENT_TOKEN": secret_value(),
        "SESSION_COOKIE_SECURE": "true" if args.secure_cookie else "false",
        "SESSION_TIMEOUT_MINUTES": "20",
        "MEDIUM_UNLOCK_MINUTES": "5",
    }

    print("# Paste these into Portainer stack environment variables.")
    print("# Keep them private. Do not commit real values to GitHub.")
    for key, value in values.items():
        print(f"{key}={value}")


if __name__ == "__main__":
    main()
