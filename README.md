# ARPShield

A production-grade CLI tool for detecting ARP spoofing and Man-in-the-Middle (MITM) attacks on local networks.

## Quick Start

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Run with root for live capture
sudo python -m arpshield --interface eth0

# Demo mode (no root required)
python -m arpshield --simulate-attack --no-color
```

## Detection Rules

| Rule | Severity | Description |
|------|----------|-------------|
| IP_MAC_CONFLICT | CRITICAL | IP's MAC changed from known baseline |
| GATEWAY_IMPERSONATION | CRITICAL | Non-gateway MAC claiming gateway IP |
| GRATUITOUS_ARP_FLOOD | WARNING | ARP request rate exceeds threshold |
| UNKNOWN_HOST | WARNING | New host not in baseline |
| PAYLOAD_MAC_MISMATCH | CRITICAL | Ethernet src MAC ≠ ARP payload MAC |

## Options

```
--interface TEXT    Network interface to monitor [default: auto-detect]
--baseline PATH     Path to baseline JSON [default: ~/.arpshield/baseline.json]
--alert-log PATH    Alert output path    [default: ~/.arpshield/alerts.jsonl]
--threshold INT     Gratuitous ARP flood rate limit per second [default: 10]
--no-color          Disable rich formatting (plain text output)
--simulate-attack   Inject a synthetic MITM event (demo/testing mode)
```
