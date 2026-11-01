"""Anomaly and security threat detector based on sliding time window metrics."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Deque, Dict, List, Optional
from src.parser import LogRecord


SUSPICIOUS_PATHS = {
    "/.env",
    "/.git/config",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/etc/passwd",
    "/actuator/health",
    "/cgi-bin/test-cgi",
    "/server-status",
    "/xmlrpc.php",
}


@dataclass
class Alert:
    """Represents an alert triggered by anomalous server activity."""
    timestamp: datetime
    level: str  # "INFO", "WARNING", "CRITICAL"
    rule_name: str
    message: str
    context: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "level": self.level,
            "rule": self.rule_name,
            "message": self.message,
            "context": self.context,
        }


class AnomalyDetector:
    """Sliding-window anomaly detector for HTTP traffic logs."""

    def __init__(
        self,
        window_seconds: int = 60,
        error_rate_threshold: float = 0.20,
        ip_rate_threshold: int = 40,
        server_error_burst_limit: int = 5,
    ):
        self.window_duration = timedelta(seconds=window_seconds)
        self.error_rate_threshold = error_rate_threshold
        self.ip_rate_threshold = ip_rate_threshold
        self.server_error_burst_limit = server_error_burst_limit

        self.window: Deque[LogRecord] = deque()
        self.ip_window: Dict[str, Deque[datetime]] = {}
        self.active_alerts: List[Alert] = []

    def _evict_old(self, current_time: datetime) -> None:
        """Evicts events outside the sliding time window."""
        cutoff = current_time - self.window_duration
        while self.window and self.window[0].timestamp < cutoff:
            self.window.popleft()

        for ip in list(self.ip_window.keys()):
            ip_queue = self.ip_window[ip]
            while ip_queue and ip_queue[0] < cutoff:
                ip_queue.popleft()
            if not ip_queue:
                del self.ip_window[ip]

    def process(self, record: LogRecord) -> List[Alert]:
        """Processes a single LogRecord and returns any newly triggered alerts."""
        alerts: List[Alert] = []
        self._evict_old(record.timestamp)

        self.window.append(record)

        if record.ip not in self.ip_window:
            self.ip_window[record.ip] = deque()
        self.ip_window[record.ip].append(record.timestamp)

        # 1. Suspicious Path Probing Detection
        for sus_path in SUSPICIOUS_PATHS:
            if sus_path in record.path.lower():
                alert = Alert(
                    timestamp=record.timestamp,
                    level="WARNING",
                    rule_name="SUSPICIOUS_PATH_PROBE",
                    message=f"Host {record.ip} attempted to access vulnerable path '{record.path}'",
                    context={"ip": record.ip, "path": record.path, "status": record.status},
                )
                alerts.append(alert)
                break

        # 2. IP Rate Spike / Abuse Detection
        ip_count = len(self.ip_window[record.ip])
        if ip_count == self.ip_rate_threshold:
            alert = Alert(
                timestamp=record.timestamp,
                level="WARNING",
                rule_name="HIGH_IP_REQUEST_RATE",
                message=f"IP {record.ip} exceeded threshold with {ip_count} requests in {self.window_duration.seconds}s window",
                context={"ip": record.ip, "requests": ip_count},
            )
            alerts.append(alert)

        # 3. High Error Rate Anomaly (Windowed)
        total_reqs = len(self.window)
        if total_reqs >= 20:
            error_count = sum(1 for r in self.window if r.is_error)
            error_rate = error_count / total_reqs
            if error_rate >= self.error_rate_threshold:
                # Alert once when threshold crossed
                alert = Alert(
                    timestamp=record.timestamp,
                    level="CRITICAL",
                    rule_name="HIGH_ERROR_RATE_SPIKE",
                    message=f"System error rate spiked to {error_rate:.1%} ({error_count}/{total_reqs} requests)",
                    context={"error_rate": round(error_rate, 4), "total_requests": total_reqs, "error_count": error_count},
                )
                alerts.append(alert)

        # 4. 5xx Internal Server Error Burst
        server_errors = [r for r in self.window if r.is_server_error]
        if len(server_errors) >= self.server_error_burst_limit and record.is_server_error:
            alert = Alert(
                timestamp=record.timestamp,
                level="CRITICAL",
                rule_name="SERVER_5XX_BURST",
                message=f"Detected {len(server_errors)} 5xx server errors in the last {self.window_duration.seconds}s",
                context={"server_errors": len(server_errors), "latest_endpoint": record.path},
            )
            alerts.append(alert)

        self.active_alerts.extend(alerts)
        return alerts
