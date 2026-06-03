"""Dataclass models for ARPShield."""

from dataclasses import dataclass
from typing import Literal


@dataclass
class ARPEntry:
    ip: str
    mac: str
    interface: str
    first_seen: str       # UTC ISO-8601
    last_seen: str        # UTC ISO-8601
    status: Literal["VERIFIED", "WARNING", "CRITICAL"]
    label: str            # "Gateway", "SPOOFED", "MAC-CHANGED", ""


@dataclass
class AlertEvent:
    severity: Literal["INFO", "WARNING", "CRITICAL"]
    message: str
    src_ip: str
    src_mac: str
    timestamp: str        # UTC ISO-8601
    rule_triggered: str   # e.g. "IP_MAC_CONFLICT"


@dataclass
class PacketRecord:
    index: int
    pkt_type: str         # "ARP", "ICMP", "TCP"
    src: str
    dst: str
    verdict: Literal["VERIFIED", "ANOMALY", "MAC-CHNG", "MITM"]
    timestamp: str        # UTC ISO-8601
