"""Packet stream recorder with PPS counter and inline RULE 5 check."""

from __future__ import annotations

import time
from collections import deque
from datetime import datetime, timezone
from typing import Any

from arpshield.detector import check_payload_mac_mismatch
from arpshield.models import PacketRecord


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class PacketStream:
    def __init__(self) -> None:
        self._records: deque[PacketRecord] = deque(maxlen=1000)
        self._timestamps: deque[float] = deque()
        self._index = 0

    def record(self, pkt: Any, verdict: str) -> PacketRecord:
        """Build a PacketRecord from a scapy packet. Applies RULE 5 inline."""
        pkt_type = "ARP"
        src = ""
        dst = ""

        try:
            if pkt.haslayer("ARP"):
                pkt_type = "ARP"
                arp = pkt["ARP"]
                src = arp.psrc
                dst = arp.pdst
                # RULE 5 inline
                eth_src: str = pkt["Ether"].src if pkt.haslayer("Ether") else arp.hwsrc
                arp_hwsrc: str = arp.hwsrc
                rule5 = check_payload_mac_mismatch(eth_src, arp_hwsrc)
                if rule5 is not None:
                    verdict = "MITM"
            elif pkt.haslayer("ICMP"):
                pkt_type = "ICMP"
                ip = pkt["IP"]
                src = ip.src
                dst = ip.dst
            elif pkt.haslayer("TCP"):
                pkt_type = "TCP"
                ip = pkt["IP"]
                src = ip.src
                dst = ip.dst
            else:
                pkt_type = type(pkt).__name__
                src = getattr(pkt, "src", "")
                dst = getattr(pkt, "dst", "")
        except Exception:
            pass

        rec = PacketRecord(
            index=self._index,
            pkt_type=pkt_type,
            src=src,
            dst=dst,
            verdict=verdict,  # type: ignore[arg-type]
            timestamp=_now(),
        )
        self._index += 1
        self._records.append(rec)
        self._timestamps.append(time.monotonic())
        return rec

    def recent(self, n: int = 50) -> list[PacketRecord]:
        """Return last n records, newest first."""
        records = list(self._records)
        return list(reversed(records[-n:]))

    def pps(self) -> float:
        """Packets per second over the last 5 seconds."""
        if not self._timestamps:
            return 0.0
        cutoff = time.monotonic() - 5.0
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()
        return len(self._timestamps) / 5.0
