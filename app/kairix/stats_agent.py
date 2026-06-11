#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

AGENT_VERSION = "0.1.16"


def _host_root() -> str:
    return os.getenv("OPSBOOK_HOST_ROOT", "").strip()


def _host_path(path: str) -> Path:
    host_root = _host_root()
    if host_root and path.startswith("/") and os.name != "nt":
        return Path(host_root) / path.lstrip("/")
    return Path(path)


def _read_text(path: str) -> str:
    try:
        return _host_path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _run_text(command: list[str], timeout: float = 3.0) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip()


def _primary_ip() -> str:
    configured = os.getenv("OPSBOOK_PRIMARY_IP", "").strip()
    if configured:
        return configured
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.2)
        sock.connect(("10.255.255.255", 1))
        ip = sock.getsockname()[0]
        sock.close()
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return ""


def _linux_memory() -> dict[str, int | float] | None:
    text = _read_text("/proc/meminfo")
    if not text:
        return None
    values: dict[str, int] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        parts = raw.strip().split()
        if parts and parts[0].isdigit():
            values[key] = int(parts[0]) * 1024
    total = values.get("MemTotal")
    available = values.get("MemAvailable")
    if not total or available is None:
        return None
    used = max(0, total - available)
    return {"total_bytes": total, "used_bytes": used, "percent": round((used / total) * 100, 2)}


def _windows_memory() -> dict[str, int | float] | None:
    if platform.system().lower() != "windows":
        return None

    class MemoryStatus(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    status = MemoryStatus()
    status.dwLength = ctypes.sizeof(MemoryStatus)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):  # type: ignore[attr-defined]
        return None
    used = int(status.ullTotalPhys - status.ullAvailPhys)
    total = int(status.ullTotalPhys)
    return {"total_bytes": total, "used_bytes": used, "percent": float(status.dwMemoryLoad)}


def _mac_memory() -> dict[str, int | float] | None:
    if platform.system().lower() != "darwin":
        return None
    total_raw = _run_text(["sysctl", "-n", "hw.memsize"])
    if not total_raw.isdigit():
        return None
    total = int(total_raw)
    vm_stat = _run_text(["vm_stat"])
    page_size = 4096
    page_match = next((line for line in vm_stat.splitlines() if "page size of" in line.lower()), "")
    digits = "".join(char for char in page_match if char.isdigit())
    if digits:
        page_size = int(digits)
    free_pages = 0
    for line in vm_stat.splitlines():
        lower = line.lower()
        if lower.startswith(("pages free", "pages inactive")) and ":" in line:
            raw = line.split(":", 1)[1].strip().strip(".")
            if raw.isdigit():
                free_pages += int(raw)
    used = max(0, total - free_pages * page_size)
    return {"total_bytes": total, "used_bytes": used, "percent": round((used / total) * 100, 2)}


def memory_stats() -> dict[str, int | float] | None:
    return _linux_memory() or _windows_memory() or _mac_memory()


def _linux_cpu_times() -> tuple[int, int] | None:
    text = _read_text("/proc/stat")
    if not text:
        return None
    first = text.splitlines()[0].split()
    if not first or first[0] != "cpu":
        return None
    values = [int(value) for value in first[1:] if value.isdigit()]
    if len(values) < 4:
        return None
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    total = sum(values)
    return idle, total


def cpu_percent() -> float | None:
    first = _linux_cpu_times()
    if not first:
        return None
    time.sleep(0.25)
    second = _linux_cpu_times()
    if not second:
        return None
    idle_delta = second[0] - first[0]
    total_delta = second[1] - first[1]
    if total_delta <= 0:
        return None
    return round(max(0.0, min(100.0, (1 - idle_delta / total_delta) * 100)), 2)


def load_average() -> list[float]:
    try:
        return [round(value, 2) for value in os.getloadavg()]
    except (AttributeError, OSError):
        return []


def disk_stats() -> list[dict[str, int | float | str]]:
    mounts: list[str] = []
    configured_mounts = [part.strip() for part in os.getenv("OPSBOOK_DISK_MOUNTS", "").split(",") if part.strip()]
    if configured_mounts:
        mounts = configured_mounts
    elif _host_root():
        mounts = ["/"]
        proc_mounts = _read_text("/proc/mounts")
        for line in proc_mounts.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("/") and parts[1] not in mounts:
                mounts.append(parts[1])
    elif os.name == "nt":
        mounts = [f"{letter}:\\" for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if Path(f"{letter}:\\").exists()]
    else:
        mounts = ["/"]
        proc_mounts = _read_text("/proc/mounts")
        for line in proc_mounts.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("/") and parts[1] not in mounts:
                mounts.append(parts[1])
    results: list[dict[str, int | float | str]] = []
    seen: set[tuple[int, int]] = set()
    skipped_prefixes = ("/proc", "/sys", "/dev", "/run")
    for mount in mounts[:24]:
        if mount != "/" and mount.startswith(skipped_prefixes):
            continue
        try:
            usage = shutil.disk_usage(_host_path(mount))
        except OSError:
            continue
        if usage.total <= 0:
            continue
        key = (usage.total, usage.free)
        if key in seen:
            continue
        seen.add(key)
        used = usage.total - usage.free
        percent = round((used / usage.total) * 100, 2) if usage.total else 0.0
        results.append(
            {
                "mountpoint": mount,
                "total_bytes": int(usage.total),
                "used_bytes": int(used),
                "free_bytes": int(usage.free),
                "percent": percent,
            }
        )
    return results


def uptime_seconds() -> float | None:
    text = _read_text("/proc/uptime")
    if text:
        try:
            return float(text.split()[0])
        except (IndexError, ValueError):
            pass
    if platform.system().lower() == "windows":
        try:
            return float(ctypes.windll.kernel32.GetTickCount64() / 1000)  # type: ignore[attr-defined]
        except Exception:
            return None
    boot = _run_text(["sysctl", "-n", "kern.boottime"])
    if "sec =" in boot:
        try:
            raw = boot.split("sec =", 1)[1].split(",", 1)[0].strip()
            return max(0.0, time.time() - float(raw))
        except ValueError:
            return None
    return None


def collect_payload(device_id: str = "") -> dict[str, object]:
    host = os.getenv("OPSBOOK_DEVICE_HOSTNAME", "").strip() or socket.gethostname()
    device_name = os.getenv("OPSBOOK_DEVICE_NAME", "").strip() or host
    payload: dict[str, object] = {
        "agent_version": AGENT_VERSION,
        "source": "opsbook-stats-agent",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "device_id": int(device_id) if device_id.isdigit() else None,
        "hostname": host,
        "device_name": device_name,
        "primary_ip": _primary_ip(),
        "os_name": platform.platform(),
        "platform": platform.platform(),
        "uptime_seconds": uptime_seconds(),
        "cpu": {
            "percent": cpu_percent(),
            "count": os.cpu_count(),
            "load_average": load_average(),
        },
        "memory": memory_stats(),
        "disks": disk_stats(),
    }
    return {key: value for key, value in payload.items() if value is not None}


def post_payload(base_url: str, token: str, payload: dict[str, object], timeout: float = 10.0) -> tuple[int, str]:
    url = urljoin(base_url.rstrip("/") + "/", "api/agent/stats")
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = Request(
        url,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": f"opsbook-stats-agent/{AGENT_VERSION}",
        },
    )
    with urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", "replace")
        return int(getattr(response, "status", 200)), body


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Kairix Opsbook system stats agent.")
    parser.add_argument("--url", default=os.getenv("OPSBOOK_URL", ""), help="Opsbook base URL, for example http://192.168.0.238:8095")
    parser.add_argument("--token", default=os.getenv("OPSBOOK_AGENT_TOKEN", ""), help="Agent token matching OPSBOOK_AGENT_TOKEN on the Opsbook server")
    parser.add_argument("--device-id", default=os.getenv("OPSBOOK_DEVICE_ID", ""), help="Optional Opsbook device ID to attach snapshots to")
    parser.add_argument("--interval", type=int, default=int(os.getenv("OPSBOOK_INTERVAL_SECONDS", "0")), help="Repeat every N seconds; default is one-shot")
    parser.add_argument("--print", action="store_true", help="Print payload instead of posting it")
    args = parser.parse_args()

    if not args.print and (not args.url or not args.token):
        print("OPSBOOK_URL and OPSBOOK_AGENT_TOKEN are required unless --print is used.", file=sys.stderr)
        return 2

    while True:
        payload = collect_payload(args.device_id)
        if args.print:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            try:
                status_code, body = post_payload(args.url, args.token, payload)
            except HTTPError as exc:
                detail = exc.read().decode("utf-8", "replace")
                print(f"Opsbook rejected stats: HTTP {exc.code} {detail}", file=sys.stderr)
                return 1
            except URLError as exc:
                print(f"Could not reach Opsbook: {exc}", file=sys.stderr)
                return 1
            print(f"Posted stats: HTTP {status_code} {body}")
        if args.interval <= 0:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
