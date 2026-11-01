"""Alert dispatcher handling console output, JSON log persistence, and notifications."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, List, Optional
from src.detector import Alert


class AlertDispatcher:
    """Dispatches alerts to multiple destinations."""

    def __init__(self, log_file: Optional[Path] = None, quiet: bool = False):
        self.log_file = log_file
        self.quiet = quiet
        self.history: List[Alert] = []
        self.handlers: List[Callable[[Alert], None]] = []

        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def register_handler(self, handler: Callable[[Alert], None]) -> None:
        self.handlers.append(handler)

    def dispatch(self, alert: Alert) -> None:
        """Sends alert to console, file, and custom registered handlers."""
        self.history.append(alert)

        if not self.quiet:
            badge = f"[{alert.level}]"
            print(f"ALERT {badge} ({alert.rule_name}) - {alert.message}")

        if self.log_file:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert.to_dict()) + "\n")

        for handler in self.handlers:
            try:
                handler(alert)
            except Exception:
                pass

    def dispatch_all(self, alerts: List[Alert]) -> None:
        for alert in alerts:
            self.dispatch(alert)
