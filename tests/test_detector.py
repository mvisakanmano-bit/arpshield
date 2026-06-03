"""Tests for the five detection rules in arpshield/detector.py."""

from __future__ import annotations

import time

import pytest

from arpshield.detector import (
    check_gateway_impersonation,
    check_ip_mac_conflict,
    check_payload_mac_mismatch,
    check_gratuitous_arp_flood,
    reset_flood_state,
)
from arpshield.models import ARPEntry


def _make_entry(ip: str, mac: str) -> ARPEntry:
    return ARPEntry(
        ip=ip,
        mac=mac,
        interface="eth0",
        first_seen="2026-05-30T00:00:00+00:00",
        last_seen="2026-05-30T00:00:00+00:00",
        status="VERIFIED",
        label="",
    )


GATEWAY_IP = "192.168.1.1"
GATEWAY_MAC = "aa:bb:cc:dd:ee:01"


# ---------------------------------------------------------------------------
# RULE 1
# ---------------------------------------------------------------------------

def test_ip_mac_conflict_fires_critical() -> None:
    baseline = {GATEWAY_IP: _make_entry(GATEWAY_IP, GATEWAY_MAC)}
    arp_table = {GATEWAY_IP: _make_entry(GATEWAY_IP, GATEWAY_MAC)}
    attacker_mac = "ff:ff:ff:ff:ff:ff"

    event = check_ip_mac_conflict(GATEWAY_IP, attacker_mac, arp_table, baseline)

    assert event is not None
    assert event.severity == "CRITICAL"
    assert event.rule_triggered == "IP_MAC_CONFLICT"
    assert attacker_mac in event.message


def test_clean_packet_returns_none() -> None:
    baseline = {GATEWAY_IP: _make_entry(GATEWAY_IP, GATEWAY_MAC)}
    arp_table = {GATEWAY_IP: _make_entry(GATEWAY_IP, GATEWAY_MAC)}

    event = check_ip_mac_conflict(GATEWAY_IP, GATEWAY_MAC, arp_table, baseline)

    assert event is None


# ---------------------------------------------------------------------------
# RULE 2
# ---------------------------------------------------------------------------

def test_gateway_impersonation_detected() -> None:
    attacker_mac = "de:ad:be:ef:00:01"

    event = check_gateway_impersonation(GATEWAY_IP, attacker_mac, GATEWAY_IP, GATEWAY_MAC)

    assert event is not None
    assert event.severity == "CRITICAL"
    assert event.rule_triggered == "GATEWAY_IMPERSONATION"
    assert attacker_mac in event.message


# ---------------------------------------------------------------------------
# RULE 3
# ---------------------------------------------------------------------------

def test_gratuitous_flood_rate_limiting() -> None:
    reset_flood_state()
    src_mac = "11:22:33:44:55:66"
    # Inject 15 packets instantly — rate = 15/5 = 3 req/s, but threshold=2 so it fires
    event = None
    for _ in range(15):
        event = check_gratuitous_arp_flood(src_mac, threshold=2)
    reset_flood_state()

    assert event is not None
    assert event.severity == "WARNING"
    assert event.rule_triggered == "GRATUITOUS_ARP_FLOOD"


# ---------------------------------------------------------------------------
# RULE 5
# ---------------------------------------------------------------------------

def test_payload_mac_mismatch_fires_critical() -> None:
    eth_src = "aa:bb:cc:dd:ee:ff"
    arp_hwsrc = "11:22:33:44:55:66"

    event = check_payload_mac_mismatch(eth_src, arp_hwsrc)

    assert event is not None
    assert event.severity == "CRITICAL"
    assert event.rule_triggered == "PAYLOAD_MAC_MISMATCH"
    assert eth_src in event.message
    assert arp_hwsrc in event.message
