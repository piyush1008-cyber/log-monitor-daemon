"""Tests for anomaly detection logic."""

from datetime import datetime, timedelta
from src.detector import AnomalyDetector
from src.parser import LogRecord


def make_record(ip: str, path: str, status: int, dt: datetime) -> LogRecord:
    return LogRecord(
        ip=ip,
        user="",
        timestamp=dt,
        method="GET",
        path=path,
        protocol="HTTP/1.1",
        status=status,
        bytes_sent=500,
        referer="-",
        user_agent="pytest",
        raw="raw",
    )


def test_detect_suspicious_path():
    detector = AnomalyDetector()
    now = datetime(2026, 11, 1, 12, 0, 0)
    record = make_record("1.2.3.4", "/.env", 404, now)

    alerts = detector.process(record)
    assert len(alerts) >= 1
    assert any(a.rule_name == "SUSPICIOUS_PATH_PROBE" for a in alerts)


def test_detect_ip_rate_spike():
    detector = AnomalyDetector(window_seconds=60, ip_rate_threshold=5)
    now = datetime(2026, 11, 1, 12, 0, 0)

    alerts = []
    for i in range(5):
        rec = make_record("10.0.0.99", "/home", 200, now + timedelta(seconds=i))
        alerts.extend(detector.process(rec))

    assert any(a.rule_name == "HIGH_IP_REQUEST_RATE" for a in alerts)


def test_server_error_burst():
    detector = AnomalyDetector(window_seconds=60, server_error_burst_limit=3)
    now = datetime(2026, 11, 1, 12, 0, 0)

    alerts = []
    for i in range(3):
        rec = make_record("10.0.0.1", "/api/error", 500, now + timedelta(seconds=i))
        alerts.extend(detector.process(rec))

    assert any(a.rule_name == "SERVER_5XX_BURST" for a in alerts)
