"""Tests for AlertDispatcher in arpshield/alerts.py."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from arpshield.alerts import AlertDispatcher
from arpshield.models import AlertEvent


def _make_event(severity: str = "CRITICAL", rule: str = "TEST") -> AlertEvent:
    return AlertEvent(
        severity=severity,  # type: ignore[arg-type]
        message="test",
        src_ip="1.2.3.4",
        src_mac="aa:bb:cc:dd:ee:ff",
        timestamp="2026-06-03T00:00:00+00:00",
        rule_triggered=rule,
    )


@pytest.fixture
def dispatcher(tmp_path: Path) -> AlertDispatcher:
    return AlertDispatcher(log_path=tmp_path / "alerts.jsonl")


def test_add_increments_threat_count_for_critical(dispatcher: AlertDispatcher) -> None:
    dispatcher.add(_make_event("CRITICAL"))
    assert dispatcher.threat_count() == 1


def test_clear_resets_threat_count(dispatcher: AlertDispatcher) -> None:
    dispatcher.add(_make_event("CRITICAL"))
    dispatcher.add(_make_event("CRITICAL"))
    dispatcher.clear()
    assert dispatcher.threat_count() == 0


def test_ring_buffer_drops_oldest_at_cap(dispatcher: AlertDispatcher) -> None:
    for i in range(101):
        dispatcher.add(_make_event("WARNING", rule=f"RULE_{i}"))
    active = dispatcher.get_active()
    assert len(active) == 100
    rules = [e.rule_triggered for e in active]
    assert "RULE_0" not in rules
    assert "RULE_100" in rules


def test_get_active_filters_by_severity(dispatcher: AlertDispatcher) -> None:
    dispatcher.add(_make_event("CRITICAL"))
    dispatcher.add(_make_event("WARNING"))
    dispatcher.add(_make_event("INFO"))
    criticals = dispatcher.get_active(severity="CRITICAL")
    assert len(criticals) == 1
    assert criticals[0].severity == "CRITICAL"


def test_thread_safety_concurrent_adds(dispatcher: AlertDispatcher) -> None:
    def add_ten() -> None:
        for _ in range(10):
            dispatcher.add(_make_event("CRITICAL"))

    threads = [threading.Thread(target=add_ten) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Ring buffer caps at 100; all 100 slots should be CRITICAL
    assert dispatcher.threat_count() == 100
