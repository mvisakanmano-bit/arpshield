"""Thread-safe alert dispatcher with ring buffer and JSONL persistence."""

from __future__ import annotations

import json
import threading
from collections import deque
from pathlib import Path

from arpshield.models import AlertEvent


DEFAULT_ALERT_LOG = Path.home() / ".arpshield" / "alerts.jsonl"
_RING_CAP = 100


class AlertDispatcher:
    def __init__(self, log_path: Path = DEFAULT_ALERT_LOG) -> None:
        self._lock = threading.Lock()
        self._buffer: deque[AlertEvent] = deque(maxlen=_RING_CAP)
        self._log_path = log_path
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

    def add(self, event: AlertEvent) -> None:
        """Append event to ring buffer and persist to JSONL."""
        with self._lock:
            self._buffer.append(event)
            with self._log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(vars(event)) + "\n")

    def get_active(self, severity: str | None = None) -> list[AlertEvent]:
        """Return buffered alerts, optionally filtered by severity."""
        with self._lock:
            events = list(self._buffer)
        if severity is None:
            return events
        return [e for e in events if e.severity == severity]

    def clear(self) -> None:
        """Flush buffer and reset threat counter."""
        with self._lock:
            self._buffer.clear()

    def threat_count(self) -> int:
        """Count of CRITICAL alerts currently in buffer."""
        with self._lock:
            return sum(1 for e in self._buffer if e.severity == "CRITICAL")
