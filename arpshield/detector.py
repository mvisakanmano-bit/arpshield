"""Five ARP spoofing detection rules."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

from arpshield.models import AlertEvent, ARPEntry


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# RULE 1 — IP_MAC_CONFLICT (CRITICAL)
# ---------------------------------------------------------------------------

def check_ip_mac_conflict(
    ip: str,
    incoming_mac: str,
    arp_table: dict[str, ARPEntry],
    baseline: dict[str, ARPEntry],
) -> AlertEvent | None:
    if ip not in arp_table:
        return None
    existing = arp_table[ip]
    if existing.mac == incoming_mac:
        return None
    if ip not in baseline:
        return None
    return AlertEvent(
        severity="CRITICAL",
        message=f"ARP Poisoning — {ip} MAC changed from {existing.mac} to {incoming_mac}",
        src_ip=ip,
        src_mac=incoming_mac,
        timestamp=_now(),
        rule_triggered="IP_MAC_CONFLICT",
    )


# ---------------------------------------------------------------------------
# RULE 2 — GATEWAY_IMPERSONATION (CRITICAL)
# ---------------------------------------------------------------------------

def check_gateway_impersonation(
    incoming_ip: str,
    incoming_mac: str,
    gateway_ip: str,
    gateway_mac: str,
) -> AlertEvent | None:
    if incoming_ip != gateway_ip:
        return None
    if incoming_mac == gateway_mac:
        return None
    return AlertEvent(
        severity="CRITICAL",
        message=f"Gateway impersonation — {incoming_mac} claiming {gateway_ip}",
        src_ip=incoming_ip,
        src_mac=incoming_mac,
        timestamp=_now(),
        rule_triggered="GATEWAY_IMPERSONATION",
    )


# ---------------------------------------------------------------------------
# RULE 3 — GRATUITOUS_ARP_FLOOD (WARNING)
# ---------------------------------------------------------------------------

# Module-level state: maps src_mac → deque of timestamps
_flood_window: dict[str, deque[float]] = defaultdict(deque)
_FLOOD_WINDOW_SECONDS: float = 5.0


def check_gratuitous_arp_flood(
    src_mac: str,
    threshold: int = 10,
) -> AlertEvent | None:
    now = time.monotonic()
    window = _flood_window[src_mac]
    window.append(now)
    cutoff = now - _FLOOD_WINDOW_SECONDS
    while window and window[0] < cutoff:
        window.popleft()
    rate = len(window) / _FLOOD_WINDOW_SECONDS
    if rate > threshold:
        return AlertEvent(
            severity="WARNING",
            message=f"Gratuitous ARP flood from {src_mac} — {rate:.1f} req/s",
            src_ip="",
            src_mac=src_mac,
            timestamp=_now(),
            rule_triggered="GRATUITOUS_ARP_FLOOD",
        )
    return None


def reset_flood_state() -> None:
    """Clear rolling-window state (used in tests)."""
    _flood_window.clear()


# ---------------------------------------------------------------------------
# RULE 4 — UNKNOWN_HOST (WARNING)
# ---------------------------------------------------------------------------

def check_unknown_host(
    ip: str,
    mac: str,
    interface: str,
    baseline: dict[str, ARPEntry],
    seen_this_session: set[str],
) -> AlertEvent | None:
    if ip in baseline or ip in seen_this_session:
        return None
    return AlertEvent(
        severity="WARNING",
        message=f"New unrecognized host — {ip} / {mac} on {interface}",
        src_ip=ip,
        src_mac=mac,
        timestamp=_now(),
        rule_triggered="UNKNOWN_HOST",
    )


# ---------------------------------------------------------------------------
# RULE 5 — PAYLOAD_MAC_MISMATCH (CRITICAL)
# ---------------------------------------------------------------------------

def check_payload_mac_mismatch(
    eth_src: str,
    arp_hwsrc: str,
) -> AlertEvent | None:
    if eth_src.lower() == arp_hwsrc.lower():
        return None
    return AlertEvent(
        severity="CRITICAL",
        message=f"Definitive spoof -- Ethernet {eth_src} != ARP payload {arp_hwsrc}",
        src_ip="",
        src_mac=eth_src,
        timestamp=_now(),
        rule_triggered="PAYLOAD_MAC_MISMATCH",
    )


# ---------------------------------------------------------------------------
# Aggregate runner
# ---------------------------------------------------------------------------

def run_all_rules(
    pkt: Any,
    arp_table: dict[str, ARPEntry],
    baseline: dict[str, ARPEntry],
    gateway_ip: str,
    gateway_mac: str,
    seen_this_session: set[str],
    flood_threshold: int = 10,
) -> list[AlertEvent]:
    """Evaluate all five rules against a scapy packet and return any alerts."""
    events: list[AlertEvent] = []

    try:
        from scapy.layers.l2 import ARP, Ether
    except ImportError:
        return events

    if not pkt.haslayer(ARP):
        return events

    arp_layer = pkt[ARP]
    eth_src: str = pkt[Ether].src if pkt.haslayer(Ether) else arp_layer.hwsrc
    arp_hwsrc: str = arp_layer.hwsrc
    src_ip: str = arp_layer.psrc
    interface: str = getattr(pkt, "sniffed_on", "unknown")

    ev1 = check_ip_mac_conflict(src_ip, arp_hwsrc, arp_table, baseline)
    if ev1:
        events.append(ev1)

    ev2 = check_gateway_impersonation(src_ip, arp_hwsrc, gateway_ip, gateway_mac)
    if ev2:
        events.append(ev2)

    ev3 = check_gratuitous_arp_flood(arp_hwsrc, flood_threshold)
    if ev3:
        events.append(ev3)

    ev4 = check_unknown_host(src_ip, arp_hwsrc, interface, baseline, seen_this_session)
    if ev4:
        events.append(ev4)

    ev5 = check_payload_mac_mismatch(eth_src, arp_hwsrc)
    if ev5:
        events.append(ev5)

    return events
