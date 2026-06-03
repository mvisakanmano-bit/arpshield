# ARPShield — Implementation Plan

## 1. Module Breakdown and File Layout

```
arpshield/
├── __init__.py       — package marker + version
├── __main__.py       — `python -m arpshield` entrypoint
├── cli.py            — argparse + rich live dashboard (1 s refresh)
├── models.py         — ARPEntry, AlertEvent, PacketRecord dataclasses
├── monitor.py        — scapy capture thread, baseline load/save, kernel ARP parse
├── detector.py       — 5 detection rule functions + run_all_rules()
├── alerts.py         — AlertDispatcher: ring buffer (100), JSONL persistence, thread-safe
└── stream.py         — PacketStream: indexed records, PPS counter, RULE 5 inline

tests/
├── fixtures/arp_table_baseline.json   — seed baseline for tests
├── test_detector.py   — 5 unit tests for rule logic
├── test_alerts.py     — 5 unit tests for dispatcher
└── test_stream.py     — 5 unit tests for packet stream
```

## 2. Data Flow

```
Raw NIC frames (scapy.sniff)
        │
        ▼
  monitor.py:start_capture()          ← background thread
        │  callback(pkt)
        ▼
  stream.py:PacketStream.record()     ← RULE 5 applied here
        │  returns PacketRecord
        ▼
  detector.py:run_all_rules()         ← RULES 1-4 evaluated
        │  returns list[AlertEvent]
        ▼
  alerts.py:AlertDispatcher.add()     ← ring buffer + JSONL append
        │
        ▼
  cli.py:Live dashboard               ← reads dispatcher + stream, refreshes every 1s
```

## 3. Detection Rules: WARNING vs CRITICAL

| Rule | Severity | Rationale |
|------|----------|-----------|
| RULE 1 — IP_MAC_CONFLICT | CRITICAL | Known host changed MAC → definitive poisoning |
| RULE 2 — GATEWAY_IMPERSONATION | CRITICAL | Attacker redirecting all traffic through themselves |
| RULE 3 — GRATUITOUS_ARP_FLOOD | WARNING | Suspicious but could be legitimate NIC reset/failover |
| RULE 4 — UNKNOWN_HOST | WARNING | New device — may be legitimate, needs investigation |
| RULE 5 — PAYLOAD_MAC_MISMATCH | CRITICAL | Eth src ≠ ARP hwsrc: strongest single indicator of active spoofing |

## 4. Test File Assertions

### test_detector.py
- `test_ip_mac_conflict_fires_critical` — build ARP entry in table, send packet with different MAC → expect CRITICAL AlertEvent with rule IP_MAC_CONFLICT
- `test_clean_packet_returns_none` — packet MAC matches baseline → no alert
- `test_gateway_impersonation_detected` — packet claims gateway IP with wrong MAC → CRITICAL GATEWAY_IMPERSONATION
- `test_gratuitous_flood_rate_limiting` — inject 15 packets in 1 s window → WARNING GRATUITOUS_ARP_FLOOD
- `test_payload_mac_mismatch_fires_critical` — Ether(src="AA") / ARP(hwsrc="BB") → CRITICAL PAYLOAD_MAC_MISMATCH

### test_alerts.py
- `test_add_increments_threat_count_for_critical` — add CRITICAL event → threat_count() == 1
- `test_clear_resets_threat_count` — add then clear → threat_count() == 0
- `test_ring_buffer_drops_oldest_at_cap` — add 101 events → buffer length == 100, oldest gone
- `test_get_active_filters_by_severity` — mix WARNING + CRITICAL → filter returns only matching
- `test_thread_safety_concurrent_adds` — 10 threads × 10 adds → threat_count() == 100

### test_stream.py
- `test_record_increments_index` — record two packets → indices 0 and 1
- `test_pps_returns_zero_on_empty` — fresh stream → pps() == 0.0
- `test_recent_returns_newest_first` — record 3 packets → recent(3)[0] is last recorded
- `test_rule5_sets_mitm_verdict_on_mac_mismatch` — Ether src ≠ ARP hwsrc → verdict "MITM"
- `test_rule5_does_not_trigger_on_clean_packet` — matching MACs → verdict unchanged

## 5. Non-Obvious Decisions and Tradeoffs

- **RULE 3 rolling window**: Use `collections.deque` keyed by src_mac holding timestamps; prune entries older than 5 s on each call. No background sweep needed — amortized O(n) per packet.
- **Thread safety in AlertDispatcher**: Single `threading.Lock` wrapping all mutations. The rich refresh loop reads under the same lock to avoid torn reads.
- **scapy import guard**: Wrap `from scapy.all import sniff` in a try/except ImportError so the module loads cleanly in CI without libpcap; tests mock scapy objects directly.
- **`--simulate-attack` without root**: The simulation path never calls `sniff()` — it constructs a synthetic AlertEvent directly and passes it to AlertDispatcher, so CI and demo always work.
- **Baseline fallback**: If `ip neigh show` is unavailable (Windows CI), `build_from_kernel_arp()` returns an empty dict and logs a warning rather than crashing; the tool still functions but with no pre-known hosts.
- **JSONL append vs overwrite**: Each AlertEvent is appended atomically via `file.write(json_line + "\n")` inside the lock, so partial writes from concurrent threads can't corrupt the file.
