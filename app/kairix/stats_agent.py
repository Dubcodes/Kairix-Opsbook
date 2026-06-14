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

AGENT_VERSION = "0.1.22"


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


def _env_enabled(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _first_text(paths: list[str]) -> str:
    for path in paths:
        value = _read_text(path).replace("\x00", "").strip()
        if value:
            return value
    return ""


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
    stats: dict[str, int | float] = {"total_bytes": total, "used_bytes": used, "percent": round((used / total) * 100, 2)}
    swap_total = values.get("SwapTotal")
    swap_free = values.get("SwapFree")
    if swap_total is not None and swap_free is not None:
        swap_used = max(0, swap_total - swap_free)
        stats.update(
            {
                "swap_total_bytes": swap_total,
                "swap_used_bytes": swap_used,
                "swap_percent": round((swap_used / swap_total) * 100, 2) if swap_total else 0.0,
            }
        )
    return stats


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
    stats: dict[str, int | float] = {"total_bytes": total, "used_bytes": used, "percent": float(status.dwMemoryLoad)}
    page_total = int(status.ullTotalPageFile)
    page_available = int(status.ullAvailPageFile)
    if page_total > 0 and page_available >= 0:
        page_used = max(0, page_total - page_available)
        stats.update(
            {
                "swap_total_bytes": page_total,
                "swap_used_bytes": page_used,
                "swap_percent": round((page_used / page_total) * 100, 2),
            }
        )
    return stats


def _size_to_bytes(value: str) -> int | None:
    clean = value.strip().replace(",", "")
    if not clean:
        return None
    number = ""
    unit = ""
    for char in clean:
        if char.isdigit() or char == ".":
            number += char
        elif not char.isspace():
            unit += char
    if not number:
        return None
    try:
        amount = float(number)
    except ValueError:
        return None
    multipliers = {
        "": 1,
        "b": 1,
        "k": 1024,
        "kb": 1024,
        "m": 1024**2,
        "mb": 1024**2,
        "g": 1024**3,
        "gb": 1024**3,
        "t": 1024**4,
        "tb": 1024**4,
    }
    return int(amount * multipliers.get(unit.lower(), 1))


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
    stats: dict[str, int | float] = {"total_bytes": total, "used_bytes": used, "percent": round((used / total) * 100, 2)}
    swap_raw = _run_text(["sysctl", "-n", "vm.swapusage"])
    if swap_raw:
        swap_values: dict[str, int] = {}
        tokens = [part.strip(":,") for part in swap_raw.replace("=", " ").split()]
        for index, part in enumerate(tokens[:-1]):
            key = part.lower()
            if key not in {"total", "used", "free"}:
                continue
            parsed = _size_to_bytes(tokens[index + 1])
            if parsed is not None:
                swap_values[key] = parsed
        swap_total = swap_values.get("total")
        swap_used = swap_values.get("used")
        if swap_total is not None and swap_used is not None:
            stats.update(
                {
                    "swap_total_bytes": swap_total,
                    "swap_used_bytes": swap_used,
                    "swap_percent": round((swap_used / swap_total) * 100, 2) if swap_total else 0.0,
                }
            )
    return stats


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


def _format_bytes(value: int | float | None) -> str:
    if value is None:
        return ""
    amount = float(value)
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    unit = units[0]
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            break
        amount /= 1024
    return f"{amount:.1f} {unit}" if unit != "B" else f"{int(amount)} B"


def _cpu_model() -> str:
    cpuinfo = _read_text("/proc/cpuinfo")
    for label in ("model name", "Hardware", "Processor"):
        for line in cpuinfo.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            if key.strip().lower() == label.lower() and value.strip():
                return value.strip()
    return platform.processor() or platform.machine()


def hardware_stats(memory: dict[str, int | float] | None, disks: list[dict[str, int | float | str]]) -> dict[str, str]:
    vendor = _first_text(["/sys/devices/virtual/dmi/id/sys_vendor"])
    product = _first_text([
        "/proc/device-tree/model",
        "/sys/devices/virtual/dmi/id/product_name",
        "/sys/firmware/devicetree/base/model",
    ])
    model = " ".join(part for part in [vendor, product] if part and part.lower() not in {"default string", "to be filled by o.e.m."})
    storage_lines: list[str] = []
    for disk in disks[:8]:
        mount = str(disk.get("mountpoint") or disk.get("mount") or "").strip()
        total = _format_bytes(disk.get("total_bytes") if isinstance(disk.get("total_bytes"), (int, float)) else None)
        used = _format_bytes(disk.get("used_bytes") if isinstance(disk.get("used_bytes"), (int, float)) else None)
        percent = disk.get("percent")
        if mount and total:
            storage_lines.append(f"{mount}: {used} / {total} ({percent:.0f}%)" if isinstance(percent, (int, float)) else f"{mount}: {used} / {total}")
    return {
        "model": model.strip(),
        "cpu": _cpu_model(),
        "ram": _format_bytes(memory.get("total_bytes")) if memory else "",
        "storage_summary": "\n".join(storage_lines),
    }


def network_stats() -> dict[str, object] | None:
    configured = {part.strip() for part in os.getenv("OPSBOOK_NETWORK_INTERFACES", "").split(",") if part.strip()}
    text = _read_text("/proc/net/dev")
    if not text:
        return None
    interfaces: list[dict[str, int | str]] = []
    total_rx = 0
    total_tx = 0
    skipped_prefixes = ("lo", "docker", "br-", "veth", "virbr", "tun", "tap")
    for line in text.splitlines()[2:]:
        if ":" not in line:
            continue
        iface, raw_values = line.split(":", 1)
        iface = iface.strip()
        if configured:
            if iface not in configured:
                continue
        elif iface.startswith(skipped_prefixes):
            continue
        parts = raw_values.split()
        if len(parts) < 16:
            continue
        try:
            rx_bytes = int(parts[0])
            tx_bytes = int(parts[8])
        except ValueError:
            continue
        total_rx += rx_bytes
        total_tx += tx_bytes
        interfaces.append({"name": iface, "rx_bytes": rx_bytes, "tx_bytes": tx_bytes})
    if not interfaces:
        return None
    return {"rx_bytes": total_rx, "tx_bytes": total_tx, "interfaces": interfaces[:32]}


def _decode_chunked(body: bytes) -> bytes:
    decoded = bytearray()
    index = 0
    while index < len(body):
        line_end = body.find(b"\r\n", index)
        if line_end < 0:
            break
        raw_size = body[index:line_end].split(b";", 1)[0].strip()
        try:
            size = int(raw_size, 16)
        except ValueError:
            break
        index = line_end + 2
        if size == 0:
            break
        decoded.extend(body[index : index + size])
        index += size + 2
    return bytes(decoded)


def _docker_api_json(path: str) -> object | None:
    if os.name == "nt" or not hasattr(socket, "AF_UNIX"):
        return None
    configured = os.getenv("OPSBOOK_DOCKER_SOCKET", "").strip()
    candidates = [configured] if configured else []
    candidates.extend(["/var/run/docker.sock", str(_host_path("/var/run/docker.sock"))])
    for socket_path in dict.fromkeys(candidate for candidate in candidates if candidate):
        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(2.5)
            client.connect(socket_path)
            request = f"GET {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n"
            client.sendall(request.encode("ascii"))
            chunks: list[bytes] = []
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
            client.close()
        except OSError:
            continue
        raw = b"".join(chunks)
        header, sep, body = raw.partition(b"\r\n\r\n")
        status_line = header.splitlines()[0] if header.splitlines() else b""
        if not sep or b" 200 " not in status_line:
            continue
        if b"transfer-encoding: chunked" in header.lower():
            body = _decode_chunked(body)
        try:
            return json.loads(body.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            continue
    return None


def docker_health() -> dict[str, object] | None:
    if not _env_enabled("OPSBOOK_DOCKER_HEALTH"):
        return None
    containers = _docker_api_json("/containers/json?all=1")
    if not isinstance(containers, list):
        output = _run_text(["docker", "ps", "-a", "--format", "{{json .}}"], timeout=4.0)
        parsed: list[dict[str, object]] = []
        for line in output.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                parsed.append(item)
        containers = parsed
    if not isinstance(containers, list):
        return None
    cleaned: list[dict[str, str]] = []
    running = 0
    unhealthy = 0
    for item in containers[:100]:
        if not isinstance(item, dict):
            continue
        names = item.get("Names") or item.get("names") or item.get("Name") or item.get("name")
        if isinstance(names, list):
            name = str(names[0]).lstrip("/") if names else ""
        else:
            name = str(names or item.get("Names") or "").lstrip("/")
        state = str(item.get("State") or item.get("state") or "").lower()
        status = str(item.get("Status") or item.get("status") or "")
        image = str(item.get("Image") or item.get("image") or "")
        is_running = state == "running" or status.lower().startswith("up")
        if is_running:
            running += 1
        if "unhealthy" in status.lower():
            unhealthy += 1
        cleaned.append({"name": name, "state": state or ("running" if is_running else ""), "status": status, "image": image})
    total = len(cleaned)
    return {
        "enabled": True,
        "total": total,
        "running": running,
        "stopped": max(0, total - running),
        "unhealthy": unhealthy,
        "containers": cleaned,
    }


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
    memory = memory_stats()
    disks = disk_stats()
    payload: dict[str, object] = {
        "agent_version": AGENT_VERSION,
        "source": "opsbook-stats-agent",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "device_id": int(device_id) if device_id.isdigit() else None,
        "device_key": device_id.strip() if device_id and not device_id.isdigit() else "",
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
        "memory": memory,
        "disks": disks,
        "hardware": hardware_stats(memory, disks),
        "network": network_stats(),
        "docker": docker_health(),
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
    parser.add_argument("--device-id", default=os.getenv("OPSBOOK_DEVICE_ID", ""), help="Optional numeric Opsbook device ID, or a device name/key to match before IP")
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
