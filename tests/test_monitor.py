"""Integration tests for LogMonitor orchestrator."""

from datetime import datetime
from src.alerter import AlertDispatcher
from src.detector import AnomalyDetector
from src.monitor import LogMonitor


def test_monitor_end_to_end_stream():
    sample_lines = [
        '192.168.1.1 - - [01/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1024 "-" "Mozilla"',
        '192.168.1.1 - - [01/Nov/2026:10:00:01 +0000] "GET /about HTTP/1.1" 200 2048 "-" "Mozilla"',
        '192.168.1.2 - - [01/Nov/2026:10:00:02 +0000] "GET /.env HTTP/1.1" 404 120 "-" "Mozilla"',
        '# Malformed comment line',
        'invalid line',
    ]

    alerter = AlertDispatcher(quiet=True)
    detector = AnomalyDetector()
    monitor = LogMonitor(detector=detector, alerter=alerter)

    metrics = monitor.ingest_stream(sample_lines)

    assert metrics.total_requests == 3
    assert monitor.unparsed_lines == 2
    assert metrics.status_codes[200] == 2
    assert metrics.status_codes[404] == 1
    assert len(alerter.history) >= 1  # Suspicious path probe alert
