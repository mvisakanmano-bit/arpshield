"""Baseline management and packet capture."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from arpshield.models import ARPEntry


def auto_detect_interface() -> str:
    """Return the first non-loopback interface with an IPv4 address."""
    try:
        import ifaddr
        for adapter in ifaddr.get_adapters():
            for ip in adapter.ips:
                if isinstance(ip.ip, str) and not ip.ip.startswith("127."):
                    return adapter.name
    except ImportError:
        pass
    return "eth0"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


DEFAULT_BASELINE_PATH = Path.home() / ".arpshield" / "baseline.json"


def load_baseline(path: Path = DEFAULT_BASELINE_PATH) -> dict[str, ARPEntry]:
    if path.exists():
        raw = json.loads(path.read_text(encoding="utf-8"))
        return {
            ip: ARPEntry(**entry)
            for ip, entry in raw.items()
        }
    return build_from_kernel_arp()


def save_baseline(entries: dict[str, ARPEntry], path: Path = DEFAULT_BASELINE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {ip: vars(entry) for ip, entry in entries.items()}
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def build_from_kernel_arp() -> dict[str, ARPEntry]:
    """Parse `ip neigh show` into ARPEntry objects. Returns {} if unavailable."""
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {}

    entries: dict[str, ARPEntry] = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        # Format: <ip> dev <iface> lladdr <mac> <state>
        if len(parts) >= 5 and parts[1] == "dev" and parts[3] == "lladdr":
            ip = parts[0]
            iface = parts[2]
            mac = parts[4]
            now = _now()
            entries[ip] = ARPEntry(
                ip=ip,
                mac=mac,
                interface=iface,
                first_seen=now,
                last_seen=now,
                status="VERIFIED",
                label="",
            )
    return entries


def start_capture(
    interface: str,
    callback: Callable[..., None],
    stop_event: threading.Event,
    started_at: datetime,
) -> None:
    """Start scapy packet capture in the current thread. Blocks until stop_event is set."""
    try:
        from scapy.all import sniff
    except ImportError:
        print("[ERROR] scapy is not installed. Run: pip install scapy", file=sys.stderr)
        sys.exit(1)

    try:
        sniff(
            iface=interface,
            filter="arp",
            prn=callback,
            store=False,
            stop_filter=lambda _: stop_event.is_set(),
        )
    except PermissionError:
        print(
            "[ERROR] Raw socket capture requires root. Run: sudo python -m arpshield",
            file=sys.stderr,
        )
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        uptime = datetime.now(timezone.utc) - started_at
        print(f"\nSession uptime: {uptime}")
