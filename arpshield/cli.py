"""Rich live dashboard and CLI entrypoint for ARPShield."""

from __future__ import annotations

import argparse
import threading
from datetime import datetime, timezone
from pathlib import Path

from arpshield import __version__
from arpshield.alerts import AlertDispatcher
from arpshield.models import AlertEvent, ARPEntry
from arpshield.monitor import (
    DEFAULT_BASELINE_PATH,
    auto_detect_interface,
    load_baseline,
    save_baseline,
    start_capture,
)
from arpshield.stream import PacketStream


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m arpshield",
        description="ARPShield — ARP spoof and MITM detection tool",
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="Network interface to monitor [default: auto-detect]",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=DEFAULT_BASELINE_PATH,
        help="Path to baseline JSON [default: ~/.arpshield/baseline.json]",
    )
    parser.add_argument(
        "--alert-log",
        type=Path,
        default=Path.home() / ".arpshield" / "alerts.jsonl",
        help="Alert output path [default: ~/.arpshield/alerts.jsonl]",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=10,
        help="Gratuitous ARP flood rate limit per second [default: 10]",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable rich formatting (plain text output)",
    )
    parser.add_argument(
        "--simulate-attack",
        action="store_true",
        help="Inject a synthetic MITM event (demo/testing mode)",
    )
    return parser.parse_args(argv)


def _make_sim_event() -> AlertEvent:
    return AlertEvent(
        severity="CRITICAL",
        message="[SIMULATION] Definitive spoof -- Ethernet de:ad:be:ef:00:01 != ARP payload 00:c0:ff:ee:00:01",
        src_ip="192.168.1.99",
        src_mac="de:ad:be:ef:00:01",
        timestamp=datetime.now(timezone.utc).isoformat(),
        rule_triggered="SIMULATION",
    )


def _render_plain(
    dispatcher: AlertDispatcher,
    stream: PacketStream,
    baseline: dict[str, ARPEntry],
    interface: str,
) -> None:
    """Single plain-text render pass (--no-color / --simulate-attack mode)."""
    alerts = dispatcher.get_active()
    packets = stream.recent(10)
    hosts = len(baseline)
    total_pkts = stream._index
    threats = dispatcher.threat_count()

    print(f"\n=== ARPShield v{__version__} | Interface: {interface} ===")
    print(f"Hosts: {hosts}  Packets: {total_pkts}  Threats: {threats}")

    if alerts:
        print("\n--- Alert Log ---")
        for ev in alerts[-10:]:
            ts = ev.timestamp[11:19]
            print(f"[{ev.severity[:4]}] {ts} {ev.message}")

    if packets:
        print("\n--- Packet Stream ---")
        for rec in packets:
            print(f"#{rec.index:04d}  {rec.pkt_type:<5} {rec.src} → {rec.dst}  {rec.verdict}")


def _run_live_dashboard(
    dispatcher: AlertDispatcher,
    stream: PacketStream,
    baseline: dict[str, ARPEntry],
    interface: str,
    stop_event: threading.Event,
) -> None:
    """Rich live dashboard that refreshes every 1 second."""
    from rich import box
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    console = Console()

    severity_color = {"CRITICAL": "red", "WARNING": "yellow", "INFO": "green"}
    verdict_color = {"VERIFIED": "green", "ANOMALY": "yellow", "MAC-CHNG": "orange3", "MITM": "red"}

    with Live(console=console, refresh_per_second=1, screen=False) as live:
        while not stop_event.is_set():
            threats = dispatcher.threat_count()
            total_pkts = stream._index
            hosts = len(baseline)

            threat_label = (
                "[red]■ CRITICAL[/red]" if threats > 0 else "[green]■ CLEAN[/green]"
            )

            # Header
            header = Text.from_markup(
                f"Hosts: [cyan]{hosts}[/cyan]  "
                f"Packets: [cyan]{total_pkts:,}[/cyan]  "
                f"Threats: [bold]{threats}[/bold] {threat_label}  "
                f"PPS: [cyan]{stream.pps():.1f}[/cyan]"
            )

            # ARP table
            arp_tbl = Table("IP", "MAC", "Status", "Label", box=box.SIMPLE, expand=True)
            for ip, entry in list(baseline.items())[:15]:
                color = severity_color.get(entry.status, "white")
                arp_tbl.add_row(entry.ip, entry.mac[-11:], f"[{color}]{entry.status}[/{color}]", entry.label)

            # Alert log
            alert_tbl = Table("Sev", "Time", "Message", box=box.SIMPLE, expand=True)
            for ev in reversed(dispatcher.get_active()[-10:]):
                color = severity_color.get(ev.severity, "white")
                alert_tbl.add_row(
                    f"[{color}]{ev.severity[:4]}[/{color}]",
                    ev.timestamp[11:19],
                    ev.message[:60],
                )

            # Packet stream
            pkt_tbl = Table("#", "Type", "Src", "Dst", "Verdict", box=box.SIMPLE, expand=True)
            for rec in stream.recent(10):
                color = verdict_color.get(rec.verdict, "white")
                pkt_tbl.add_row(
                    f"{rec.index:04d}", rec.pkt_type, rec.src, rec.dst,
                    f"[{color}]{rec.verdict}[/{color}]",
                )

            from rich.layout import Layout
            layout = Layout()
            layout.split_column(
                Layout(Panel(header, title=f"ARPShield v{__version__}  [green]● MONITORING[/green]"), size=3),
                Layout(name="middle", size=15),
                Layout(Panel(pkt_tbl, title="Packet Stream (live)"), size=12),
            )
            layout["middle"].split_row(
                Layout(Panel(arp_tbl, title="ARP Table")),
                Layout(Panel(alert_tbl, title="Alert Log")),
            )
            live.update(layout)

            stop_event.wait(timeout=1.0)


def run(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)

    interface = args.interface or auto_detect_interface()
    dispatcher = AlertDispatcher(log_path=args.alert_log)
    stream = PacketStream()
    baseline = load_baseline(args.baseline)

    if args.simulate_attack:
        event = _make_sim_event()
        dispatcher.add(event)
        if args.no_color:
            print(f"[CRITICAL] {event.timestamp[11:19]} {event.message}")
        else:
            from rich.console import Console
            Console().print(f"[bold red][CRITICAL][/bold red] {event.message}")

    if args.no_color or args.simulate_attack:
        _render_plain(dispatcher, stream, baseline, interface)
        return

    # Live capture mode
    stop_event = threading.Event()
    started_at = datetime.now(timezone.utc)

    from arpshield.detector import run_all_rules
    gateway_ip = next(
        (ip for ip, e in baseline.items() if e.label == "Gateway"), ""
    )
    gateway_mac = baseline[gateway_ip].mac if gateway_ip in baseline else ""
    seen_this_session: set[str] = set()

    def on_packet(pkt: object) -> None:
        verdict = "VERIFIED"
        events = run_all_rules(
            pkt, baseline, baseline, gateway_ip, gateway_mac,
            seen_this_session, args.threshold,
        )
        if events:
            for ev in events:
                dispatcher.add(ev)
            verdict = "ANOMALY"
        stream.record(pkt, verdict)
        try:
            from scapy.layers.l2 import ARP
            if hasattr(pkt, "haslayer") and pkt.haslayer(ARP):
                src_ip = pkt[ARP].psrc  # type: ignore[index]
                seen_this_session.add(src_ip)
        except Exception:
            pass

    capture_thread = threading.Thread(
        target=start_capture,
        args=(interface, on_packet, stop_event, started_at),
        daemon=True,
    )
    capture_thread.start()

    try:
        _run_live_dashboard(dispatcher, stream, baseline, interface, stop_event)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        capture_thread.join(timeout=3)
        save_baseline(baseline, args.baseline)
        uptime = datetime.now(timezone.utc) - started_at
        print(f"\nSession uptime: {uptime}")
