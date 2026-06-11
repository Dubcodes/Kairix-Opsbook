from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse


INVENTORY_COMMAND = r"""printf '=== HOST ===\n'; hostnamectl 2>/dev/null || hostname; \
printf '\n=== OS ===\n'; cat /etc/os-release 2>/dev/null; \
printf '\n=== CPU ===\n'; lscpu 2>/dev/null | sed -n '1,20p'; \
printf '\n=== MEMORY ===\n'; free -h 2>/dev/null; \
printf '\n=== DISKS ===\n'; lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE 2>/dev/null; \
printf '\n=== IP ADDRESSES ===\n'; ip -br addr 2>/dev/null; \
printf '\n=== ROUTES ===\n'; ip route 2>/dev/null; \
printf '\n=== DOCKER VERSION ===\n'; docker version --format '{{.Server.Version}}' 2>/dev/null || true; \
printf '\n=== DOCKER CONTAINERS ===\n'; docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || true; \
printf '\n=== DOCKER COMPOSE PROJECTS ===\n'; docker compose ls 2>/dev/null || true; \
printf '\n=== CLOUDFLARE TUNNELS ===\n'; docker ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null | awk '$2 ~ /cloudflare\/cloudflared/ {print $1}' | while read -r container; do printf '\n--- %s ---\n' "$container"; docker logs --tail 200 "$container" 2>&1 | grep -Eo 'https://[-A-Za-z0-9.]+\.trycloudflare\.com' | tail -n 5; done 2>/dev/null || true; \
printf '\n=== LISTENING PORTS ===\n'; ss -tulpn 2>/dev/null | sed -n '1,80p'"""

CLOUDFLARED_URL_COMMAND = r"""printf '=== CLOUDFLARE TUNNELS ===\n'
docker ps --format '{{.Names}}\t{{.Image}}' | awk '$2 ~ /cloudflare\/cloudflared/ {print $1}' | while read -r container; do
  printf '\n--- %s ---\n' "$container"
  docker logs --tail 300 "$container" 2>&1 | grep -Eo 'https://[-A-Za-z0-9.]+\.trycloudflare\.com' | tail -n 3
done"""

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"https?://[^\s)\]'\"<>]+", re.IGNORECASE)
PATH_RE = re.compile(r"(?<![\w.-])/(?:[\w .@+-]+/)*[\w .@+-]+")
PORT_RE = re.compile(r"\bport\s*(?:is|:)?\s*(\d{2,5})\b", re.IGNORECASE)
COMMAND_RE = re.compile(
    r"^\s*(sudo |docker |git |ssh |cd |cloudflared |systemctl |ss |df |free |uptime|apt |tail |ls |nano |vim |cat |mkdir |cp |mv )",
    re.IGNORECASE,
)
USERNAME_RE = re.compile(r"\b(?:user(?:name)?|login|account)\s*(?:is|:)?\s*([a-z_][a-z0-9_-]{1,31})\b", re.IGNORECASE)
PASSWORD_STYLE_USER_RE = re.compile(r"\b([a-z_][a-z0-9_-]{1,31})\s+password\b", re.IGNORECASE)
GITHUB_TOKEN_RE = re.compile(r"\b(?:github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9_]+)\b")
USERNAME_NOISE_WORDS = {
    "as",
    "last",
    "local",
    "only",
    "root",
    "mon",
    "monday",
    "tue",
    "tues",
    "tuesday",
    "wed",
    "wednesday",
    "thu",
    "thurs",
    "thursday",
    "fri",
    "friday",
    "sat",
    "saturday",
    "sun",
    "sunday",
    "jan",
    "feb",
    "mar",
    "apr",
    "may",
    "jun",
    "jul",
    "aug",
    "sep",
    "sept",
    "oct",
    "nov",
    "dec",
}


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        clean = item.strip().strip(",.;")
        if clean and clean not in seen:
            seen.add(clean)
            result.append(clean)
    return result


def _line_for_span(text: str, start: int, end: int) -> str:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()


def _is_session_noise_line(line: str) -> bool:
    clean = line.strip()
    lowered = clean.lower()
    if not clean:
        return False
    if lowered.startswith(
        (
            "login as:",
            "last login:",
            "linux ",
            "the programs included",
            "debian gnu/linux comes",
            "the exact distribution terms",
            "warning:",
            "host key verification",
        )
    ):
        return True
    return bool(re.match(r"^[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+:.*[$#]\s*", clean))


def _safe_username_candidate(candidate: str) -> bool:
    clean = candidate.strip().lower()
    return bool(clean) and clean not in USERNAME_NOISE_WORDS


def _field_value_from_line(line: str, labels: set[str]) -> str:
    clean = line.strip()
    if not clean:
        return ""
    for label in sorted(labels, key=len, reverse=True):
        label_pattern = re.escape(label).replace(r"\ ", r"\s+")
        match = re.match(rf"^\s*{label_pattern}(?:\s|\.)*(?::|=)\s*(.+?)\s*$", clean, re.IGNORECASE)
        if match:
            return _clean_field_value(match.group(1))
    return ""


def _clean_field_value(value: str) -> str:
    clean = value.strip().strip('"').strip("'").strip()
    if clean.lower() in {"", "<none>", "none", "n/a", "not available", "unknown"}:
        return ""
    return clean


def _extract_labeled_value(text: str, labels: set[str]) -> str:
    for line in text.splitlines():
        value = _field_value_from_line(line, labels)
        if value:
            return value
    return ""


def _looks_like_device_name(value: str) -> bool:
    clean = value.strip()
    if (
        not clean
        or len(clean) > 80
        or clean.startswith("===")
        or IP_RE.search(clean)
        or URL_RE.search(clean)
        or COMMAND_RE.search(clean)
        or _is_session_noise_line(clean)
    ):
        return False
    return bool(re.search(r"[A-Za-z0-9]", clean))


def _inventory_text(text: str) -> str:
    marker = re.search(r"^=== HOST ===\s*$", text, re.MULTILINE)
    if marker:
        return text[marker.start() :]
    return text


def _section(text: str, name: str) -> str:
    marker = f"=== {name.upper()} ==="
    if marker not in text:
        return ""
    tail = text.rsplit(marker, 1)[1]
    next_marker = re.search(r"\n=== [A-Z0-9 _-]+ ===", tail)
    if next_marker:
        tail = tail[: next_marker.start()]
    return tail.strip()


def parse_smart_paste(raw_text: str) -> dict[str, Any]:
    effective_text = _inventory_text(raw_text)
    lines = [line.rstrip() for line in effective_text.splitlines()]
    is_inventory = "=== HOST ===" in effective_text and "=== IP ADDRESSES ===" in effective_text

    host_section = _section(effective_text, "HOST")
    os_section = _section(effective_text, "OS")
    cpu = _section(effective_text, "CPU")
    memory = _section(effective_text, "MEMORY")
    disks = _section(effective_text, "DISKS")
    ip_section = _section(effective_text, "IP ADDRESSES")
    docker_containers = _section(effective_text, "DOCKER CONTAINERS")
    docker_compose = _section(effective_text, "DOCKER COMPOSE PROJECTS")
    cloudflare_tunnels = _section(effective_text, "CLOUDFLARE TUNNELS")
    listening_ports = _section(effective_text, "LISTENING PORTS")
    is_cloudflare_output_only = bool(cloudflare_tunnels) and not docker_containers and not is_inventory
    has_runtime_inventory = bool(docker_containers or docker_compose or cloudflare_tunnels or listening_ports)

    ips = _unique(IP_RE.findall(ip_section or effective_text))
    urls = _normalized_urls_from_text(effective_text if not is_inventory else "")
    paths = _unique(_clean_paths(PATH_RE.findall(effective_text)))
    ports = _unique([match.group(1) for match in PORT_RE.finditer(effective_text)])
    if not is_inventory:
        ports.extend(
            line.strip()
            for line in effective_text.splitlines()
            if re.fullmatch(r"\d{2,5}", line.strip()) and 0 < int(line.strip()) <= 65535
        )

    for url in urls:
        try:
            parsed = urlparse(url)
        except ValueError:
            continue
        if parsed.port:
            ports.append(str(parsed.port))
    docker_port_map = _docker_port_map(docker_containers)
    ports.extend(_listening_tcp_ports(listening_ports))
    ports = _unique(ports)

    command_lines = [] if is_inventory or is_cloudflare_output_only else lines
    commands: list[dict[str, str]] = []
    previous_label = ""
    for line in command_lines:
        stripped = line.strip()
        if COMMAND_RE.search(stripped) and not stripped.endswith(":"):
            commands.append({"command": stripped, "name": _command_name(stripped, previous_label)})
        if "command:" in stripped.lower():
            maybe = stripped.split(":", 1)[1].strip()
            if maybe:
                commands.append({"command": maybe, "name": _command_name(maybe, previous_label)})
        if stripped and not COMMAND_RE.search(stripped) and not URL_RE.search(stripped) and len(stripped) < 80:
            previous_label = stripped.strip(":")
    commands = _unique_commands(commands)
    cloudflared_containers = _cloudflared_container_names(docker_containers)
    cloudflare_tunnel_entries = _cloudflare_tunnel_entries(cloudflare_tunnels)
    if (
        not is_cloudflare_output_only
        and not cloudflare_tunnel_entries
        and (_looks_like_temporary_cloudflared(effective_text) or cloudflared_containers)
    ):
        command_template = _cloudflared_url_command(cloudflared_containers)
        container_note = ", ".join(cloudflared_containers) if cloudflared_containers else "running cloudflared containers"
        commands = _unique_commands(
            commands
            + [
                {
                    "command": command_template,
                    "name": "Find temporary Cloudflare tunnel URLs",
                    "category": "Network lookup",
                    "where_to_run": "Docker host SSH shell",
                    "risk_level": "safe",
                    "help_low": "Lists quick TryCloudflare URLs from running cloudflared containers. Paste the output back into Smart Paste so Opsbook can attach the URL to the matching service.",
                    "notes": f"Generated because Smart Paste saw temporary cloudflared / trycloudflare activity. Targets: {container_note}.",
                }
            ]
        )

    usernames = _unique(_safe_usernames(raw_text))
    primary_ip = _primary_ip(ips)

    compose_projects = _compose_projects(docker_compose)
    service_items: list[dict[str, Any]] = []
    for line in lines:
        clean = line.strip()
        service_match = re.search(r"^([A-Z][\w .-]{2,60})\s+(?:is on|runs on|runs at|is in)\b", clean)
        if service_match:
            service_items.append({"name": service_match.group(1).strip(), "confidence": "medium"})
        docker_row = _container_row_from_line(clean)
        if docker_row:
            container_name = docker_row["container_name"]
            stack_group = _guess_stack_group(container_name, compose_projects)
            service_items.append(
                {
                    "name": container_name.replace("-", " ").replace("_", " ").title(),
                    "container_name": container_name,
                    "image": docker_row["image"],
                    "stack_group": stack_group,
                    "compose_path": compose_projects.get(stack_group, ""),
                    "ports": docker_port_map.get(container_name, []),
                    "urls": _local_urls_for_docker_ports(primary_ip, container_name, docker_port_map.get(container_name, [])),
                    "confidence": "medium",
                }
            )
    _attach_cloudflare_urls(service_items, cloudflare_tunnel_entries)
    service_items = [item for item in service_items if not _is_detached_cloudflared_placeholder(item)]
    if not is_inventory:
        service_items.extend(_note_services(raw_text))
        service_items.extend(_inline_service_entries(raw_text))
    service_items = _unique_services(service_items)
    token_items = _github_tokens(raw_text)
    grouped_urls = {
        url["url"]
        for service in service_items
        for url in service.get("urls", [])
        if url.get("url")
    }
    grouped_credential_keys = {
        (
            str(credential.get("label", "")).lower(),
            str(credential.get("username", "")).lower(),
            str(credential.get("service_name", "")).lower(),
        )
        for service in service_items
        for credential in service.get("credentials", [])
    }
    service_port_values = {
        str(port["host_port"])
        for mapped_ports in docker_port_map.values()
        for port in mapped_ports
    } | {
        str(port["host_port"])
        for service in service_items
        for port in service.get("ports", [])
        if port.get("host_port")
    }

    device_name = _device_name_from_text(
        host_section,
        lines,
        has_runtime_inventory=has_runtime_inventory,
        is_inventory=is_inventory,
        primary_ip=primary_ip,
    )
    os_name = _os_name_from_text(os_section, lines)

    final_device_name = "" if device_name == os_name else device_name
    if (
        final_device_name
        and not primary_ip
        and not os_name
        and not service_items
        and (urls or cloudflare_tunnels)
        and (
            re.search(r"[@:].*[$#]\s*", final_device_name)
            or final_device_name.lower().startswith(("printf ", "for container", "docker logs"))
        )
    ):
        final_device_name = ""
    if token_items and not primary_ip and not service_items and not urls and not ports:
        final_device_name = ""
    likely_device = {
        "name": final_device_name,
        "primary_ip": primary_ip,
        "os_name": os_name,
        "confidence": "medium" if final_device_name or ips else "low",
    }

    suggested_ports = []
    for port in ports:
        if port.isdigit() and port not in service_port_values:
            numeric_port = int(port)
            hint = _port_hint(numeric_port)
            suggested_ports.append(
                {
                    "host_port": numeric_port,
                    "protocol": "tcp",
                    "purpose": hint["purpose"],
                    "tags": hint["tags"],
                    "confidence": "medium",
                }
            )
    grouped_cloudflare_urls = {
        url
        for entry in cloudflare_tunnel_entries
        for url in (entry.get("history_urls") or [entry["url"]])
    }
    suggested_urls = [
        {"url": url, "url_type": "public" if not _is_private_url(url) else "local", "confidence": "high"}
        for url in urls
        if url not in grouped_urls and url not in grouped_cloudflare_urls
    ]
    suggested_urls.extend(
        entry
        for entry in cloudflare_tunnel_entries
        if entry["url"] not in grouped_urls
    )
    suggested_services = service_items
    suggested_commands = [
        {
            "name": command["name"],
            "command_template": command["command"],
            "category": command.get("category", ""),
            "where_to_run": command.get("where_to_run", ""),
            "risk_level": command.get("risk_level", ""),
            "help_low": command.get("help_low", ""),
            "notes": command.get("notes", ""),
            "confidence": "medium",
        }
        for command in commands
    ]
    suggested_credentials = [
        credential
        for credential in _note_credentials(raw_text)
        if (
            str(credential.get("label", "")).lower(),
            str(credential.get("username", "")).lower(),
            str(credential.get("service_name", "")).lower(),
        )
        not in grouped_credential_keys
    ]
    existing_users = {item["username"] for item in suggested_credentials}
    existing_users.update(
        str(credential.get("username", ""))
        for service in service_items
        for credential in service.get("credentials", [])
    )
    suggested_credentials.extend(
        [
        {
            "label": f"{username} login",
            "username": username,
            "security_level": "medium" if username in {"root", "admin", "serveruser"} else "low",
            "secret_detected": False,
            "confidence": "low",
        }
        for username in usernames
        if username not in existing_users
        ]
    )

    extras: dict[str, Any] = {
        "paths": paths,
        "model_summary": _model_summary(host_section),
        "cpu_summary": _cpu_summary(cpu),
        "memory_summary": _memory_summary(memory or effective_text),
        "disk_summary": _disk_summary(disks),
        "docker_containers": docker_containers,
        "docker_compose": docker_compose,
        "cloudflare_tunnels": cloudflare_tunnels,
        "listening_ports": listening_ports,
    }

    return {
        "device": likely_device,
        "services": suggested_services,
        "urls": suggested_urls,
        "ports": suggested_ports,
        "commands": suggested_commands,
        "credentials": suggested_credentials,
        "tokens": token_items,
        "paths": [{"path": path, "confidence": "medium"} for path in paths],
        "extras": extras,
        "counts": dict(
            Counter(
                {
                    "ips": len(ips),
                    "urls": len(urls),
                    "ports": len(ports),
                    "paths": len(paths),
                    "commands": len(commands),
                    "services": len(service_items),
                    "usernames": len(usernames),
                    "tokens": len(token_items),
                }
            )
        ),
    }


def _is_private_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    host = parsed.hostname or ""
    return host.startswith("192.168.") or host.startswith("10.") or host in {"localhost", "127.0.0.1"}


def _normalize_discovered_url(url: str) -> str:
    clean = url.strip().rstrip(".,;")
    if not clean or any(marker in clean for marker in ["[", "]", "{", "}", "\\"]):
        return ""
    try:
        parsed = urlparse(clean)
    except ValueError:
        return ""
    host = parsed.hostname or ""
    if not host:
        return ""
    if host.endswith("trycloudflare.com"):
        return parsed._replace(path="", params="", query="", fragment="").geturl()
    return clean


def _normalized_urls_from_text(text: str) -> list[str]:
    return _unique([_normalize_discovered_url(url) for url in URL_RE.findall(text or "")])


def _primary_ip(ips: list[str]) -> str:
    for ip in ips:
        if ip.startswith("192.168.") or ip.startswith("10."):
            return ip
    for ip in ips:
        if not ip.startswith("127.") and not ip.startswith("172."):
            return ip
    return ips[0] if ips else ""


def _device_name_from_text(
    host_section: str,
    lines: list[str],
    *,
    has_runtime_inventory: bool,
    is_inventory: bool,
    primary_ip: str,
) -> str:
    host_labels = {
        "static hostname",
        "hostname",
        "host name",
        "computer name",
        "computername",
        "device name",
        "machine name",
        "local hostname",
        "localhostname",
        "node name",
        "system name",
    }
    if host_section:
        value = _extract_labeled_value(host_section, host_labels)
        if value:
            return value
        for line in host_section.splitlines():
            clean = line.strip()
            if _looks_like_device_name(clean) and not re.search(r"\b(operating system|kernel|architecture|hardware|firmware)\b", clean, re.IGNORECASE):
                return clean
    value = _extract_labeled_value("\n".join(lines[:80]), host_labels)
    if value:
        return value
    if not has_runtime_inventory:
        for line in lines[:8]:
            clean = line.strip()
            if _looks_like_device_name(clean):
                return clean
    if not is_inventory and primary_ip:
        last_octet = primary_ip.rsplit(".", 1)[-1]
        for line in lines[:20]:
            match = re.match(rf"^([A-Za-z][\w .-]{{1,50}})\s+{re.escape(last_octet)}$", line.strip())
            if match:
                return match.group(1).strip()
    return ""


def _os_name_from_text(os_section: str, lines: list[str]) -> str:
    source = os_section or "\n".join(lines[:100])
    if not source:
        return ""
    pretty = re.search(r'^\s*PRETTY_NAME="?([^"\n]+)"?', source, re.IGNORECASE | re.MULTILINE)
    if pretty:
        return _clean_field_value(pretty.group(1))
    os_name = _extract_labeled_value(
        source,
        {
            "os name",
            "operating system",
            "os",
            "productname",
            "product name",
            "system version",
            "platform",
        },
    )
    product_version = _extract_labeled_value(source, {"productversion", "product version", "os version", "version"})
    if os_name and product_version and product_version.lower() not in os_name.lower():
        return f"{os_name} {product_version}"
    if os_name:
        return os_name
    name = _extract_labeled_value(source, {"name"})
    version = _extract_labeled_value(source, {"version", "version_id"})
    if name and version and name.lower() not in {"name", "os"}:
        return f"{name} {version}"
    for line in source.splitlines():
        clean = line.strip()
        if _is_session_noise_line(clean) or COMMAND_RE.search(clean):
            continue
        if re.search(
            r"\b(windows|debian|ubuntu|fedora|centos|red hat|rocky|almalinux|arch|opensuse|suse|macos|darwin|freebsd|openbsd|netbsd|raspbian|raspberry pi os|proxmox|synology|truenas|unraid)\b",
            clean,
            re.IGNORECASE,
        ):
            return clean
    return ""


def _local_urls_for_docker_ports(primary_ip: str, container_name: str, ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not primary_ip or _is_cloudflare_container({"container_name": container_name}):
        return []
    urls: list[dict[str, Any]] = []
    for port in ports:
        host_port = int(port.get("host_port") or 0)
        if not _port_looks_web_accessible(host_port, container_name):
            continue
        scheme = "https" if host_port in {443, 8443, 9443} else "http"
        urls.append(
            {
                "url": f"{scheme}://{primary_ip}:{host_port}/",
                "url_type": "local",
                "confidence": "medium",
            }
        )
    return urls


def _port_looks_web_accessible(port: int, container_name: str) -> bool:
    if port <= 0:
        return False
    lowered = container_name.lower()
    if "portainer" in lowered and port == 8000:
        return False
    if any(marker in lowered for marker in ["postgres", "mariadb", "mysql", "redis", "-db", "_db"]):
        return False
    non_web_ports = {
        22,
        25,
        53,
        110,
        137,
        138,
        139,
        143,
        389,
        445,
        465,
        587,
        993,
        995,
        1883,
        1935,
        21027,
        22000,
        22067,
        22070,
        3306,
        5432,
        5433,
        5900,
        6379,
        8554,
    }
    return port not in non_web_ports


def _cloudflare_tunnel_entries(text: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    current = ""
    current_urls: list[str] = []

    def flush_current() -> None:
        if not current_urls:
            return
        source_label = current or "cloudflare tunnel output"
        latest_url = current_urls[-1]
        recent_urls = current_urls[-5:]
        excerpt_lines = [f"--- {source_label} ---", *recent_urls]
        unique_urls = _unique(current_urls)
        if len(unique_urls) > 1:
            excerpt_lines.append(f"Selected latest URL: {latest_url}")
        entries.append(
            {
                "url": latest_url,
                "url_type": "public",
                "confidence": "high",
                "source_label": source_label,
                "source_excerpt": "\n".join(excerpt_lines),
                "service_hint": _cloudflare_target_hint(source_label),
                "history_urls": unique_urls,
            }
        )

    for line in text.splitlines():
        clean = line.strip()
        if not clean:
            continue
        header = re.match(r"^-{3,}\s*(.+?)\s*-{3,}$", clean)
        if header:
            flush_current()
            current = header.group(1).strip()
            current_urls = []
            continue
        urls = [url for url in _normalized_urls_from_text(clean) if "trycloudflare.com" in url.lower()]
        if not urls:
            continue
        current_urls.extend(urls)
    flush_current()
    return entries


def _looks_like_temporary_cloudflared(text: str) -> bool:
    lowered = text.lower()
    return (
        "trycloudflare.com" in lowered
        or "quick tunnel" in lowered
        or "cloudflare/cloudflared" in lowered
        or ("cloudflared" in lowered and "requesting new quick tunnel" in lowered)
    )


def _cloudflared_container_names(text: str) -> list[str]:
    names: list[str] = []
    for line in text.splitlines():
        clean = line.strip()
        if "cloudflare/cloudflared" not in clean.lower():
            continue
        row = _container_row_from_line(clean)
        name = row["container_name"] if row else clean.split(None, 1)[0]
        if name.lower() in {"names", "name"}:
            continue
        if re.fullmatch(r"[A-Za-z0-9_.-]+", name) and name not in names:
            names.append(name)
    return names


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _cloudflared_url_command(container_names: list[str]) -> str:
    if not container_names:
        return CLOUDFLARED_URL_COMMAND
    quoted = " ".join(_shell_quote(name) for name in container_names)
    return (
        "printf '=== CLOUDFLARE TUNNELS ===\\n'\n"
        f"for container in {quoted}; do\n"
        "  printf '\\n--- %s ---\\n' \"$container\"\n"
        "  docker logs --tail 300 \"$container\" 2>&1 | grep -Eo 'https://[-A-Za-z0-9.]+\\.trycloudflare\\.com' | tail -n 3\n"
        "done"
    )


def _attach_cloudflare_urls(services: list[dict[str, Any]], tunnel_entries: list[dict[str, Any]]) -> None:
    for entry in tunnel_entries:
        container_name = str(entry.get("source_label") or "")
        url = str(entry.get("url") or "")
        target = _cloudflare_target_service(services, container_name)
        if not target:
            continue
        _append_service_url(
            target,
            url,
            "public",
            "high",
            source_label=container_name,
            source_excerpt=str(entry.get("source_excerpt") or ""),
            service_hint=str(entry.get("service_hint") or ""),
            history_urls=list(entry.get("history_urls") or []),
        )


def _cloudflare_target_service(services: list[dict[str, Any]], container_name: str) -> dict[str, Any] | None:
    source = next((item for item in services if item.get("container_name") == container_name), None)
    source_group = str((source or {}).get("stack_group") or "").strip()
    candidates = [
        item
        for item in services
        if item.get("container_name") != container_name
        and not _is_cloudflare_container(item)
        and (not source_group or item.get("stack_group") == source_group)
    ]
    if not candidates:
        candidates = [
            item
            for item in services
            if item.get("container_name") != container_name and not _is_cloudflare_container(item)
        ]
    if not candidates:
        return source

    descriptor = _norm_name(container_name)
    db_markers = {"db", "postgres", "redis", "mysql", "mariadb"}
    non_db_candidates = [
        item
        for item in candidates
        if not any(marker in _norm_name(str(item.get("name", "") + " " + item.get("container_name", ""))) for marker in db_markers)
    ]
    candidates = non_db_candidates or candidates
    distinctive_terms = _cloudflare_distinctive_terms(container_name)
    if distinctive_terms:
        matching_distinctive = [
            item
            for item in candidates
            if distinctive_terms & set(_service_tokens(str(item.get("name", "") + " " + item.get("container_name", ""))))
        ]
        if matching_distinctive:
            candidates = matching_distinctive
        elif source:
            return source
    preferred_terms: list[str] = []
    if "public" in descriptor:
        preferred_terms = ["public"]
    elif any(term in descriptor for term in ["control", "admin", "web"]):
        preferred_terms = ["web", "app", "control", "admin"]
    for term in preferred_terms:
        match = next(
            (
                item
                for item in candidates
                if term in _norm_name(str(item.get("name", "") + " " + item.get("container_name", "")))
            ),
            None,
        )
        if match:
            return match
    target_hint = _cloudflare_target_hint(container_name)
    if target_hint:
        scored: list[tuple[int, dict[str, Any]]] = []
        for item in candidates:
            candidate_text = _norm_name(str(item.get("name", "") + " " + item.get("container_name", "")))
            if target_hint in candidate_text or candidate_text in target_hint:
                scored.append((max(len(target_hint), len(candidate_text)), item))
        if scored:
            return sorted(scored, key=lambda item: item[0], reverse=True)[0][1]
    with_ports = [item for item in candidates if item.get("ports")]
    return (with_ports or candidates)[0]


def _cloudflare_target_hint(container_name: str) -> str:
    hint = _norm_name(container_name)
    for marker in ["trycloudflare", "cloudflared", "cloudflare", "temporary", "temp", "tunnel", "public", "control", "url"]:
        hint = hint.replace(marker, "")
    return hint.strip()


def _service_tokens(value: str) -> list[str]:
    return [token for token in re.split(r"[^a-z0-9]+", value.lower()) if token]


def _cloudflare_distinctive_terms(container_name: str) -> set[str]:
    broad_terms = {
        "cloudflare",
        "cloudflared",
        "trycloudflare",
        "temporary",
        "temp",
        "tunnel",
        "url",
        "urls",
        "quick",
        "container",
        "people",
        "kairix",
    }
    role_terms = {"public", "control", "admin", "web", "app"}
    return {token for token in _service_tokens(container_name) if token not in broad_terms and token not in role_terms}


def _is_cloudflare_container(item: dict[str, Any]) -> bool:
    text = " ".join(str(item.get(key, "")) for key in ["name", "container_name", "image"]).lower()
    return "cloudflared" in text or "cloudflare/cloudflared" in text


def _is_detached_cloudflared_placeholder(item: dict[str, Any]) -> bool:
    return _is_cloudflare_container(item) and not item.get("ports") and not item.get("urls") and not item.get("credentials")


def _append_service_url(
    service: dict[str, Any],
    url: str,
    url_type: str,
    confidence: str,
    *,
    source_label: str = "",
    source_excerpt: str = "",
    service_hint: str = "",
    history_urls: list[str] | None = None,
) -> None:
    clean = url.strip().strip(",.;")
    if not clean:
        return
    existing = {str(item.get("url", "")).strip() for item in service.setdefault("urls", [])}
    if clean not in existing:
        item = {"url": clean, "url_type": url_type, "confidence": confidence}
        if source_label:
            item["source_label"] = source_label
        if source_excerpt:
            item["source_excerpt"] = source_excerpt
        if service_hint:
            item["service_hint"] = service_hint
        if history_urls:
            item["history_urls"] = history_urls
        service["urls"].append(item)


def _port_hint(port: int) -> dict[str, str]:
    hints = {
        22: {"purpose": "SSH", "tags": "ssh, remote-access"},
        80: {"purpose": "HTTP web", "tags": "http, web"},
        139: {"purpose": "SMB / Samba", "tags": "smb, file-sharing"},
        443: {"purpose": "HTTPS web", "tags": "https, web"},
        445: {"purpose": "SMB / Samba", "tags": "smb, file-sharing"},
        5432: {"purpose": "PostgreSQL", "tags": "postgres, database"},
        5433: {"purpose": "PostgreSQL alternate", "tags": "postgres, database"},
        8000: {"purpose": "Web/admin service", "tags": "web, admin"},
        8080: {"purpose": "Web/admin service", "tags": "web, admin"},
        8095: {"purpose": "Kairix Opsbook", "tags": "kairix-opsbook, web"},
        9443: {"purpose": "HTTPS admin service", "tags": "https, admin"},
    }
    return hints.get(port, {"purpose": "", "tags": ""})


def _container_row_from_line(line: str) -> dict[str, str] | None:
    clean = line.strip()
    if not clean or clean.startswith("===") or _is_session_noise_line(clean):
        return None
    lower = clean.lower()
    if lower.startswith(("names ", "name ", "container id ", "container_id ")) or lower in {"names", "name"}:
        return None
    status_pattern = r"(?:Up|Exited|Created|Restarting|Paused|Running|running|healthy|unhealthy)"
    if not re.search(rf"\b{status_pattern}\b", clean, re.IGNORECASE):
        return None
    id_first = re.match(r"^(?P<id>[0-9a-f]{12,64})\s+(?P<image>\S+)\s+.+?\s(?P<name>[A-Za-z0-9_.-]+)$", clean, re.IGNORECASE)
    if id_first:
        return {"container_name": id_first.group("name"), "image": id_first.group("image")}
    name_first = re.match(rf"^(?P<name>[A-Za-z0-9_.-]+)\s+(?P<image>\S+)\s+{status_pattern}\b", clean, re.IGNORECASE)
    if name_first:
        return {"container_name": name_first.group("name"), "image": name_first.group("image")}
    compose_ps = re.match(rf"^(?P<name>[A-Za-z0-9_.-]+)\s+(?P<image>\S+)\s+.+?\b{status_pattern}\b", clean, re.IGNORECASE)
    if compose_ps:
        return {"container_name": compose_ps.group("name"), "image": compose_ps.group("image")}
    return None


def _docker_port_map(text: str) -> dict[str, list[dict[str, Any]]]:
    mapped: dict[str, list[dict[str, Any]]] = {}
    for line in text.splitlines():
        if "->" not in line:
            continue
        row = _container_row_from_line(line)
        container = row["container_name"] if row else line.split(None, 1)[0]
        if container.lower() in {"names", "name"} or re.fullmatch(r"[0-9a-f]{12,64}", container, re.IGNORECASE):
            continue
        mapped[container] = _extract_mapped_ports(line)
    return mapped


def _extract_mapped_ports(line: str) -> list[dict[str, Any]]:
    ports: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    pattern = re.compile(
        r"(?:(?:0\.0\.0\.0|127\.0\.0\.1|\[::\]|::|localhost|\*):)?"
        r"(\d{2,5})(?:-(\d{2,5}))?->(\d{1,5})(?:-\d{1,5})?/(\w+)"
    )
    for match in pattern.finditer(line):
        start = int(match.group(1))
        end = int(match.group(2) or start)
        internal_port = int(match.group(3))
        protocol = match.group(4).lower()
        for port in range(start, min(end, start + 10) + 1):
            key = (port, protocol)
            if key not in seen:
                seen.add(key)
                ports.append(
                    {
                        "host_port": port,
                        "internal_port": internal_port,
                        "protocol": protocol,
                        "confidence": "high",
                    }
                )
    return ports


def _clean_note_value(value: str) -> str:
    return value.split("|", 1)[0].strip()


def _note_header_parts(value: str) -> tuple[str, list[str], list[dict[str, Any]]]:
    clean = re.sub(r"^\s*-{2,}\s*", "", value.strip()).strip(" :-")
    inline_urls = _normalized_urls_from_text(clean)
    clean = URL_RE.sub("", clean).strip(" :-")
    ports: list[dict[str, Any]] = []
    seen: set[int] = set()
    for match in re.finditer(r"\b(\d{2,5})\s*:\s*\d{1,5}(?:/(tcp|udp))?\b", clean, re.IGNORECASE):
        host_port = int(match.group(1))
        if 0 < host_port <= 65535 and host_port not in seen:
            seen.add(host_port)
            ports.append({"host_port": host_port, "protocol": (match.group(2) or "tcp").lower(), "confidence": "medium"})
    name = re.sub(r"\b\d{2,5}\s*:\s*\d{1,5}(?:/(?:tcp|udp))?\b", " ", clean, flags=re.IGNORECASE)
    trailing_ports = re.search(r"^(.*?)(?:\s+-\s+|\s+)((?:\d{2,5}(?:/(?:tcp|udp))?\s*)+)$", name, re.IGNORECASE)
    if trailing_ports:
        name = trailing_ports.group(1)
        for token in re.finditer(r"\b(\d{2,5})(?:/(tcp|udp))?\b", trailing_ports.group(2), re.IGNORECASE):
            host_port = int(token.group(1))
            if 0 < host_port <= 65535 and host_port not in seen:
                seen.add(host_port)
                ports.append({"host_port": host_port, "protocol": (token.group(2) or "tcp").lower(), "confidence": "medium"})
    name = re.sub(r"\s+", " ", name).strip(" :-")
    return name, inline_urls, ports


def _listening_tcp_ports(text: str) -> list[str]:
    ports: list[str] = []
    for line in text.splitlines():
        if not line.strip().startswith("tcp") or "LISTEN" not in line:
            continue
        match = re.search(r":(\d{2,5})\s+", line)
        if match:
            ports.append(match.group(1))
    return ports


def _clean_paths(paths: list[str]) -> list[str]:
    cleaned: list[str] = []
    for path in paths:
        value = path.strip()
        if (
            value == "/"
            or value.startswith(("/dev/null", "/www.", "/bugs."))
            or re.fullmatch(r"/\d{1,3}(?:\.\d{1,3}){3}", value)
            or re.fullmatch(r"/[-A-Za-z0-9.]+\.trycloudflare\.com", value)
        ):
            continue
        if re.search(r"\s(?:ext4|vfat|swap|xfs|btrfs|zfs)$", value):
            value = value.split(" ", 1)[0]
        elif " " in value and not value.startswith(("/srv/", "/home/", "/opt/", "/var/", "/etc/", "/boot/")):
            value = value.split(" ", 1)[0]
        cleaned.append(value)
    return cleaned


def _cpu_summary(text: str) -> str:
    model = re.search(r"^Model name:\s*(.+)$", text, re.MULTILINE)
    if model:
        return model.group(1).strip()
    for line in text.splitlines():
        clean = line.strip()
        if clean and any(word in clean.lower() for word in ["intel", "amd", "arm", "model"]):
            return clean.split(":", 1)[-1].strip()
    return ""


def _model_summary(text: str) -> str:
    model = re.search(r"^\s*Hardware Model:\s*(.+)$", text, re.MULTILINE)
    if model:
        return model.group(1).strip()
    return ""


def _memory_summary(text: str) -> str:
    explicit = re.search(
        r"^\s*(?:total\s+ram|ram|memory)\s*:?\s*([0-9.]+\s*(?:[KMGTPE]i?B|[KMGTPE]B))\b",
        text,
        re.IGNORECASE | re.MULTILINE,
    )
    if explicit:
        return re.sub(r"\s+", " ", explicit.group(1)).strip()
    quick = re.search(
        r"^\s*([0-9.]+\s*(?:[KMGTPE]i?B|[KMGTPE]B))\s+ram\b",
        text,
        re.IGNORECASE | re.MULTILINE,
    )
    if quick:
        return re.sub(r"\s+", " ", quick.group(1)).strip()
    for line in text.splitlines():
        parts = line.split()
        if parts and parts[0].rstrip(":").lower() == "mem" and len(parts) > 1:
            return parts[1]
    return ""


def _disk_summary(text: str) -> str:
    for line in text.splitlines():
        clean = line.strip()
        if not clean or clean.lower().startswith("name "):
            continue
        clean = re.sub(r"^[├└─\s]+", "", clean)
        parts = clean.split()
        if len(parts) >= 3 and parts[2] == "disk":
            return " ".join(parts[:3])
    return ""


def _unique_commands(items: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[str] = set()
    result: list[dict[str, str]] = []
    for item in items:
        key = item["command"].strip().lower()
        if key and key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _command_name(command: str, label: str = "") -> str:
    clean_label = label.strip().strip(":")
    if clean_label and not COMMAND_RE.search(clean_label) and not URL_RE.search(clean_label):
        return clean_label[:60]
    lowered = command.lower()
    if "docker compose logs" in lowered:
        return "Docker Compose logs"
    if "docker compose up" in lowered:
        return "Docker Compose start/update"
    if "git pull" in lowered:
        return "Git pull"
    if lowered.startswith("cd "):
        return "Go to folder"
    return command[:60]


def _safe_usernames(text: str) -> list[str]:
    usernames: list[str] = []
    for match in USERNAME_RE.finditer(text):
        candidate = match.group(1)
        if _safe_username_candidate(candidate) and not _is_session_noise_line(_line_for_span(text, match.start(), match.end())):
            usernames.append(candidate)
    for match in PASSWORD_STYLE_USER_RE.finditer(text):
        candidate = match.group(1)
        if _safe_username_candidate(candidate) and not _is_session_noise_line(_line_for_span(text, match.start(), match.end())):
            usernames.append(candidate)
    for match in re.finditer(r"^User:\s*([a-z_][a-z0-9_-]{1,31})\s*$", text, re.IGNORECASE | re.MULTILINE):
        if _safe_username_candidate(match.group(1)):
            usernames.append(match.group(1))
    return usernames


def _note_credentials(text: str) -> list[dict[str, Any]]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    credentials: list[dict[str, Any]] = []
    for block in re.split(r"\n\s*\n+", text):
        block_lines = [line.strip() for line in block.splitlines() if line.strip()]
        if len(block_lines) < 2:
            continue
        first = block_lines[0].strip(":")
        if (
            len(block_lines) == 2
            and _looks_like_username(first)
            and _looks_like_secret(block_lines[1])
        ):
            credentials.append(
                {
                    "label": f"{first} login",
                    "username": first,
                    "secret": _clean_note_value(block_lines[1]),
                    "service_name": "",
                    "security_level": "medium" if first.lower() in {"root", "admin"} else "low",
                    "secret_detected": True,
                    "confidence": "medium",
                }
            )
            continue
        if len(block_lines) < 3:
            continue
        if (
            not first.startswith("-")
            and not URL_RE.search(first)
            and not IP_RE.search(first)
            and not COMMAND_RE.search(first)
            and len(first) <= 60
            and _looks_like_username(block_lines[1])
            and _looks_like_secret(block_lines[2])
        ):
            username = _clean_note_value(block_lines[1])
            secret = _clean_note_value(block_lines[2])
            credentials.append(
                {
                    "label": f"{first} login",
                    "username": username,
                    "secret": secret,
                    "service_name": "",
                    "security_level": "medium" if username.lower() in {"root", "admin"} else "low",
                    "secret_detected": True,
                    "confidence": "medium",
                }
            )
            continue
        marker = re.match(r"^([A-Za-z][\w .-]{1,50})\s+(\d{1,3})$", first)
        if marker and int(marker.group(2)) <= 255:
            username = block_lines[1]
            secret = _clean_note_value(block_lines[2])
            if _looks_like_username(username) and _looks_like_secret(secret):
                credentials.append(
                    {
                        "label": f"{first} login",
                        "username": username,
                        "secret": secret,
                        "service_name": "",
                        "security_level": "medium",
                        "secret_detected": True,
                        "confidence": "medium",
                    }
                )
    for index, line in enumerate(lines):
        lower = line.lower().strip(":")
        if lower in {"root", "admin", "serveruser"} or "password" in lower:
            next_one = _clean_note_value(lines[index + 1]) if index + 1 < len(lines) else ""
            next_two = lines[index + 2].strip() if index + 2 < len(lines) else ""
            if (
                lower in {"root", "admin", "serveruser"}
                and next_one
                and not (_looks_like_username(next_one) and _looks_like_secret(next_two))
                and not URL_RE.search(next_one)
                and not (index > 0 and URL_RE.search(lines[index - 1]))
                and not (index > 0 and lines[index - 1].lstrip().startswith("---"))
                and not (index > 0 and lines[index - 1].lower().strip(":") in {"portainer", "docker"})
            ):
                credentials.append(
                    {
                        "label": f"{line} login",
                        "username": lower,
                        "secret": next_one,
                        "service_name": "",
                        "security_level": "medium" if lower in {"root", "admin", "serveruser"} else "low",
                        "secret_detected": True,
                        "confidence": "medium",
                    }
                )
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in credentials:
        key = (item["label"].lower(), item["username"].lower())
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


def _github_tokens(text: str) -> list[dict[str, Any]]:
    tokens: list[dict[str, Any]] = []
    for match in GITHUB_TOKEN_RE.finditer(text):
        token = match.group(0)
        prefix_lines = [line.strip() for line in text[: match.start()].splitlines() if line.strip()]
        owner = ""
        name = "GitHub token"
        expiry = ""
        for index in range(len(prefix_lines) - 1, -1, -1):
            line = prefix_lines[index]
            if line.lower().startswith("expires on "):
                expiry = _parse_github_expiry(line.removeprefix("Expires on ").strip())
                continue
            if line.startswith("@"):
                owner = line
                if index + 1 < len(prefix_lines):
                    candidate = prefix_lines[index + 1]
                    if not candidate.lower().startswith(("never used", "expires on", "make sure")):
                        name = candidate
                break
        if name == "GitHub token":
            for line in reversed(prefix_lines):
                lower = line.lower()
                if (
                    line.startswith("@")
                    or GITHUB_TOKEN_RE.search(line)
                    or lower.startswith(("never used", "expires on", "make sure", "copied", "skip to content", "settings"))
                ):
                    continue
                if len(line) <= 80:
                    name = line
                    break
        tokens.append(
            {
                "label": name,
                "username": owner,
                "token": token,
                "service_name": _token_service_name(name),
                "expires_at": expiry,
                "notes": "Imported GitHub personal access token.",
                "security_level": "high",
                "confidence": "high",
            }
        )
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in tokens:
        if item["token"] not in seen:
            seen.add(item["token"])
            deduped.append(item)
    return deduped


def _token_service_name(label: str) -> str:
    clean = re.sub(r"\b(github|personal|access|api|pat|token|key)\b", "", label, flags=re.IGNORECASE)
    clean = re.sub(r"[-_]+", " ", clean)
    clean = re.sub(r"\s+", " ", clean).strip(" -:")
    return clean


def _parse_github_expiry(value: str) -> str:
    clean = value.strip().rstrip(".")
    try:
        parsed = parsedate_to_datetime(clean)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.isoformat()
    except (TypeError, ValueError, IndexError):
        pass
    for fmt in ("%a, %b %d %Y", "%b %d %Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(clean, fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return clean


def _compose_projects(text: str) -> dict[str, str]:
    projects: dict[str, str] = {}
    for line in text.splitlines():
        clean = line.strip()
        if not clean or clean.lower().startswith("name "):
            continue
        match = re.match(r"^([a-zA-Z0-9_.-]+)\s+\S+\s+(.+\.ya?ml)\s*$", clean)
        if match:
            projects[match.group(1)] = match.group(2).strip()
    return projects


def _norm_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _stack_match_tokens(value: str) -> set[str]:
    generic = {
        "app",
        "container",
        "containers",
        "db",
        "database",
        "latest",
        "project",
        "running",
        "server",
        "service",
        "services",
        "stats",
        "web",
    }
    return {token for token in _service_tokens(value) if token not in generic and not token.isdigit()}


def _guess_stack_group(container_name: str, projects: dict[str, str]) -> str:
    normalized = _norm_name(container_name)
    known_prefixes = {
        "people": "people-system",
        "immich": "immich",
        "kairixjudging": "kairix_judging",
        "syncthing": "syncthing",
        "graphicsproject": "graphics-project",
        "omnitools": "omni-tools",
        "ittools": "ittools",
        "omadacontroller": "omada-controller",
        "vaultwarden": "vaultwarden",
        "portainer": "portainer",
        "heimdall": "heimdall",
        "dockpeek": "dockpeek",
        "glances": "glances",
        "filebrowser": "filebrowser",
        "frigate": "frigatenvr",
        "mqtt": "frigatenvr",
        "opsbookstatsagent": "opsbook-agent",
    }
    for prefix, project in known_prefixes.items():
        if normalized.startswith(prefix) and project in projects:
            return project
    best = ""
    for project in projects:
        project_norm = _norm_name(project)
        if project_norm and (normalized.startswith(project_norm) or project_norm in normalized):
            if len(project) > len(best):
                best = project
    if best:
        return best
    container_tokens = _stack_match_tokens(container_name)
    scored_projects: list[tuple[int, int, str]] = []
    for project in projects:
        project_tokens = _stack_match_tokens(project)
        overlap = container_tokens & project_tokens
        if overlap:
            score = (len(overlap) * 10) + sum(len(token) for token in overlap)
            scored_projects.append((score, len(project), project))
    if scored_projects:
        return sorted(scored_projects, reverse=True)[0][2]
    if "cloudflared" in normalized or "tunnel" in normalized:
        return "cloudflare-tunnels"
    return ""


def _note_services(text: str) -> list[dict[str, Any]]:
    services: list[dict[str, Any]] = []
    for block in re.split(r"\n\s*\n+", text):
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        if not lines:
            continue
        first_line = lines[0].strip(":")
        name, inline_urls, header_ports = _note_header_parts(first_line)
        if not _looks_like_note_service_name(name):
            continue
        urls = _unique(inline_urls + _normalized_urls_from_text(block))
        if (
            first_line.lstrip().startswith("---")
            and urls
            and all("trycloudflare.com" in url.lower() for url in urls)
            and not header_ports
            and all(line.startswith("---") or URL_RE.fullmatch(line) or re.search(r"[@:].*[$#]\s*$", line) for line in lines)
        ):
            continue
        device_login_marker = re.match(r"^.+\s+(\d{1,3})$", first_line)
        if device_login_marker and int(device_login_marker.group(1)) <= 255 and not urls and not header_ports:
            continue
        standalone_ports = [
            int(line)
            for line in lines
            if re.fullmatch(r"\d{2,5}", line) and 0 < int(line) <= 65535
        ]
        service_urls = [
            {"url": url, "url_type": "public" if not _is_private_url(url) else "local", "confidence": "high"}
            for url in urls
        ]
        service_ports: list[dict[str, Any]] = []
        for url in urls:
            try:
                parsed = urlparse(url)
            except ValueError:
                continue
            if parsed.port:
                service_ports.append({"host_port": parsed.port, "protocol": "tcp", "confidence": "high"})
        for port in standalone_ports:
            if all(existing["host_port"] != port for existing in service_ports):
                service_ports.append({"host_port": port, "protocol": "tcp", "confidence": "medium"})
        for port in header_ports:
            if all(existing["host_port"] != port["host_port"] for existing in service_ports):
                service_ports.append(port)
        credentials = _credentials_from_service_block(name, lines, service_urls[0]["url"] if service_urls else "")
        if not urls and not standalone_ports and not header_ports and credentials and not lines[0].lstrip().startswith("---"):
            continue
        if not urls and not standalone_ports and not header_ports and not credentials:
            continue
        services.append(
            {
                "name": name,
                "confidence": "medium" if urls else "low",
                "urls": service_urls,
                "ports": service_ports,
                "credentials": credentials,
            }
        )
    return services


def _inline_service_entries(text: str) -> list[dict[str, Any]]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    services: list[dict[str, Any]] = []
    for index, line in enumerate(lines):
        name_source, urls, header_ports = _note_header_parts(line)
        known_credential_service = name_source.lower() in {
            "docker",
            "portainer",
            "gluetun",
            "qbittorrent",
            "sonarr",
            "radarr",
            "plex",
            "filebrowser",
            "syncthing",
        }
        username = lines[index + 1] if index + 1 < len(lines) else ""
        secret = lines[index + 2] if index + 2 < len(lines) else ""
        has_inline_credentials = _looks_like_username(username) and _looks_like_secret(secret)
        if not urls and not header_ports and not (known_credential_service and has_inline_credentials):
            continue
        if not _looks_like_note_service_name(name_source):
            continue
        service_urls = [
            {"url": url, "url_type": "public" if not _is_private_url(url) else "local", "confidence": "high"}
            for url in urls
        ]
        ports: list[dict[str, Any]] = []
        for url in urls:
            try:
                parsed = urlparse(url)
            except ValueError:
                continue
            if parsed.port:
                ports.append({"host_port": parsed.port, "protocol": "tcp", "confidence": "high"})
        for port in header_ports:
            if all(existing["host_port"] != port["host_port"] for existing in ports):
                ports.append(port)
        credentials: list[dict[str, Any]] = []
        if has_inline_credentials:
            credentials.append(
                {
                    "label": f"{name_source} login",
                    "username": username,
                    "secret": secret,
                    "service_name": name_source,
                    "login_url": service_urls[0]["url"] if service_urls else "",
                    "security_level": "medium" if username.lower() in {"root", "admin"} else "low",
                    "secret_detected": True,
                    "confidence": "medium",
                }
            )
        services.append(
            {
                "name": name_source,
                "confidence": "high" if urls else "medium",
                "urls": service_urls,
                "ports": ports,
                "credentials": credentials,
            }
        )
    return services


def _looks_like_note_service_name(value: str) -> bool:
    clean = value.strip().strip(":")
    lower = clean.lower()
    if (
        not clean
        or len(clean) > 60
        or lower in {"root", "user", "main ip", "ssh", "hostname", "os", "admin", "serveruser"}
        or re.match(r"^\d{4}-\d{2}-\d{2}[t\s]\d{2}:", lower)
        or lower.startswith(("inf ", "err ", "wrn "))
        or any(word in lower for word in ["folder", "folders", "rules", "shares", "by ip", "check ", "restart ", "start/stop", "recommended", "update system"])
        or COMMAND_RE.search(clean)
        or IP_RE.search(clean)
        or re.search(r"[@\\\\|]", clean)
    ):
        return False
    if "." in clean and not any(word in lower for word in ["app", "tools"]):
        return False
    return bool(re.search(r"[a-zA-Z]", clean))


def _looks_like_username(value: str) -> bool:
    clean = _clean_note_value(value)
    return bool(
        re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.@-]{1,63}", clean)
        or re.fullmatch(r"\d{4,20}", clean)
    ) and not URL_RE.search(clean)


def _looks_like_secret(value: str) -> bool:
    clean = _clean_note_value(value)
    if not clean or URL_RE.search(clean) or COMMAND_RE.search(clean) or IP_RE.search(clean):
        return False
    return len(clean) >= 4 and not clean.endswith(":")


def _credentials_from_service_block(service_name: str, lines: list[str], login_url: str) -> list[dict[str, Any]]:
    credentials: list[dict[str, Any]] = []
    service_display = service_name.strip(":")
    credentials.extend(_credentials_from_key_values(service_display, lines, login_url))
    labeled_username = _labeled_line_value(lines, {"user", "username", "login", "account"})
    labeled_secret = _labeled_line_value(lines, {"password", "pass", "secret", "token", "pin"})
    if labeled_username and labeled_secret:
        credentials.append(
            {
                "label": f"{service_display} login",
                "username": labeled_username,
                "secret": labeled_secret,
                "service_name": service_display,
                "login_url": login_url,
                "security_level": "medium" if labeled_username.lower() in {"root", "admin"} else "low",
                "secret_detected": True,
                "confidence": "high",
            }
        )
    for index, line in enumerate(lines):
        if URL_RE.search(line):
            username = lines[index + 1].strip() if index + 1 < len(lines) else ""
            secret = _clean_note_value(lines[index + 2]) if index + 2 < len(lines) else ""
            if _looks_like_username(username) and _looks_like_secret(secret):
                credentials.append(
                    {
                        "label": f"{service_display} login",
                        "username": username,
                        "secret": secret,
                        "service_name": service_display,
                        "login_url": login_url,
                        "security_level": "medium" if username.lower() in {"root", "admin"} else "low",
                        "secret_detected": True,
                        "confidence": "medium",
                    }
                )
    if not credentials and len(lines) >= 3:
        username = lines[1]
        secret = _clean_note_value(lines[2])
        if _looks_like_username(username) and _looks_like_secret(secret):
            credentials.append(
                {
                    "label": f"{service_display} login",
                    "username": username,
                    "secret": secret,
                    "service_name": service_display,
                    "login_url": login_url,
                    "security_level": "medium" if username.lower() in {"root", "admin"} else "low",
                    "secret_detected": True,
                    "confidence": "low",
                }
            )
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in credentials:
        key = (item["label"].lower(), item["username"].lower(), item["service_name"].lower())
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


def _credentials_from_key_values(service_name: str, lines: list[str], login_url: str) -> list[dict[str, Any]]:
    values: list[tuple[str, str, str]] = []
    for line in lines:
        match = re.match(r"^\s*([A-Za-z][A-Za-z0-9_ .-]{1,60})\s*(?::|=)\s*(.+?)\s*$", line)
        if not match:
            continue
        label = match.group(1).strip()
        value = _clean_note_value(match.group(2))
        key = re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")
        if key and value:
            values.append((key, label, value))

    credentials: list[dict[str, Any]] = []
    username_keys = [(key, label, value) for key, label, value in values if _key_is_username(key)]
    for key, label, secret in values:
        if not _key_is_secret(key) or not _looks_like_secret(secret):
            continue
        prefix = re.sub(r"(?:password|passwd|pass|secret|token|pin).*$", "", key).strip("_")
        username = "root" if "root" in key.split("_") else ""
        for user_key, _user_label, user_value in username_keys:
            user_prefix = re.sub(r"(?:username|user|email|login|account).*$", "", user_key).strip("_")
            if prefix and user_prefix and (prefix == user_prefix or prefix.startswith(user_prefix) or user_prefix.startswith(prefix)):
                username = user_value
                break
        if not username and len(username_keys) == 1:
            username = username_keys[0][2]
        label_prefix = prefix.replace("_", " ").strip().title()
        credential_label = f"{service_name} {label_prefix} login".strip() if label_prefix else f"{service_name} login"
        credentials.append(
            {
                "label": credential_label,
                "username": username,
                "secret": secret,
                "service_name": service_name,
                "login_url": login_url,
                "security_level": "medium" if username.lower() in {"root", "admin"} else "low",
                "secret_detected": True,
                "confidence": "high",
            }
        )
    return credentials


def _key_is_username(key: str) -> bool:
    parts = set(key.split("_"))
    return bool(parts & {"user", "username", "email", "login", "account"})


def _key_is_secret(key: str) -> bool:
    parts = set(key.split("_"))
    return bool(parts & {"password", "passwd", "pass", "secret", "token", "pin"}) or any(
        marker in key for marker in ("password", "passwd", "pass", "secret", "token")
    )


def _labeled_line_value(lines: list[str], labels: set[str]) -> str:
    label_pattern = "|".join(re.escape(label) for label in sorted(labels, key=len, reverse=True))
    for index, line in enumerate(lines):
        match = re.match(rf"^\s*(?:{label_pattern})\s*(?::|=|-)\s*(.+?)\s*$", line, re.IGNORECASE)
        if match:
            value = _clean_note_value(match.group(1))
            if value:
                return value
        label_only = re.match(rf"^\s*(?:{label_pattern})\s*:?\s*$", line, re.IGNORECASE)
        if label_only and index + 1 < len(lines):
            return _clean_note_value(lines[index + 1])
    return ""


def _unique_services(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for item in items:
        name = item.get("name", "").strip()
        key = _norm_name(name)
        if not key or key in seen:
            continue
        seen.add(key)
        item.setdefault("container_name", "")
        item.setdefault("image", "")
        item.setdefault("stack_group", "")
        item.setdefault("compose_path", "")
        item.setdefault("ports", [])
        item.setdefault("urls", [])
        item.setdefault("credentials", [])
        item.setdefault("confidence", "medium")
        result.append(item)
    return result
