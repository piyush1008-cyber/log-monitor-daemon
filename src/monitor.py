"""Log Monitor Daemon core orchestrator."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Iterable, Optional
from src.alerter import AlertDispatcher
from src.detector import AnomalyDetector
from src.metrics import LogMetrics
from src.parser import LogRecord, parse_line


class LogMonitor:
    """Core log processing engine coordinating parsing, metrics collection, and anomaly alerts."""

    def __init__(
        self,
        detector: Optional[AnomalyDetector] = None,
        alerter: Optional[AlertDispatcher] = None,
    ):
        self.detector = detector or AnomalyDetector()
        self.alerter = alerter or AlertDispatcher()
        self.metrics = LogMetrics()
        self.unparsed_lines = 0

    def ingest_line(self, line: str) -> Optional[LogRecord]:
        """Ingests and evaluates a single raw log string."""
        record = parse_line(line)
        if not record:
            self.unparsed_lines += 1
            return None

        self.metrics.record(record)
        alerts = self.detector.process(record)
        if alerts:
            self.alerter.dispatch_all(alerts)

        return record

    def ingest_stream(self, lines: Iterable[str]) -> LogMetrics:
        """Processes an iterable stream of log lines."""
        for line in lines:
            self.ingest_line(line)
        return self.metrics

    def analyze_file(self, file_path: Path) -> LogMetrics:
        """Processes a log file from start to finish."""
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            return self.ingest_stream(f)
