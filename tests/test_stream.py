"""Tests for PacketStream in arpshield/stream.py."""

from __future__ import annotations

from unittest.mock import MagicMock

from arpshield.stream import PacketStream


def _make_arp_pkt(eth_src: str, arp_hwsrc: str, psrc: str = "10.0.0.1", pdst: str = "10.0.0.2") -> MagicMock:
    """Build a minimal mock that mimics a scapy Ether/ARP packet."""
    arp = MagicMock()
    arp.hwsrc = arp_hwsrc
    arp.psrc = psrc
    arp.pdst = pdst

    ether = MagicMock()
    ether.src = eth_src

    def _getitem(key: str) -> MagicMock:
        return arp if key == "ARP" else ether

    pkt = MagicMock()
    pkt.haslayer.side_effect = lambda layer: layer in ("ARP", "Ether")
    pkt.__getitem__ = MagicMock(side_effect=_getitem)
    return pkt


def test_record_increments_index() -> None:
    stream = PacketStream()
    pkt = _make_arp_pkt("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:01")
    r0 = stream.record(pkt, "VERIFIED")
    r1 = stream.record(pkt, "VERIFIED")
    assert r0.index == 0
    assert r1.index == 1


def test_pps_returns_zero_on_empty() -> None:
    stream = PacketStream()
    assert stream.pps() == 0.0


def test_recent_returns_newest_first() -> None:
    stream = PacketStream()
    pkt = _make_arp_pkt("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:01")
    stream.record(pkt, "VERIFIED")
    stream.record(pkt, "VERIFIED")
    r2 = stream.record(pkt, "VERIFIED")
    recent = stream.recent(3)
    assert recent[0].index == r2.index


def test_rule5_sets_mitm_verdict_on_mac_mismatch() -> None:
    stream = PacketStream()
    pkt = _make_arp_pkt(eth_src="aa:bb:cc:dd:ee:ff", arp_hwsrc="11:22:33:44:55:66")
    rec = stream.record(pkt, "VERIFIED")
    assert rec.verdict == "MITM"


def test_rule5_does_not_trigger_on_clean_packet() -> None:
    stream = PacketStream()
    pkt = _make_arp_pkt(eth_src="aa:bb:cc:dd:ee:ff", arp_hwsrc="aa:bb:cc:dd:ee:ff")
    rec = stream.record(pkt, "VERIFIED")
    assert rec.verdict == "VERIFIED"
