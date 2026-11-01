"""Real-time metrics aggregator for HTTP server logs."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
from src.parser import LogRecord


@dataclass
class LogMetrics:
    """Aggregated traffic metrics from parsed log streams."""
    total_requests: int = 0
    total_bytes: int = 0
    status_codes: Counter = field(default_factory=Counter)
    methods: Counter = field(default_factory=Counter)
    top_endpoints: Counter = field(default_factory=Counter)
    top_ips: Counter = field(default_factory=Counter)
    first_timestamp: Optional[datetime] = None
    last_timestamp: Optional[datetime] = None

    def record(self, log: LogRecord) -> None:
        """Records a new log entry into metric counters."""
        self.total_requests += 1
        self.total_bytes += log.bytes_sent
        self.status_codes[log.status] += 1
        self.methods[log.method] += 1
        self.top_endpoints[log.path] += 1
        self.top_ips[log.ip] += 1

        if self.first_timestamp is None or log.timestamp < self.first_timestamp:
            self.first_timestamp = log.timestamp
        if self.last_timestamp is None or log.timestamp > self.last_timestamp:
            self.last_timestamp = log.timestamp

    @property
    def error_count(self) -> int:
        return sum(count for status, count in self.status_codes.items() if status >= 400)

    @property
    def error_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.error_count / self.total_requests

    @property
    def duration_seconds(self) -> float:
        if not self.first_timestamp or not self.last_timestamp:
            return 0.0
        delta = (self.last_timestamp - self.first_timestamp).total_seconds()
        return max(delta, 1.0)

    @property
    def requests_per_second(self) -> float:
        if self.duration_seconds == 0:
            return 0.0
        return self.total_requests / self.duration_seconds

    def summary(self) -> Dict:
        """Returns structured dictionary of aggregated metrics."""
        return {
            "total_requests": self.total_requests,
            "total_bytes_sent": self.total_bytes,
            "error_rate_pct": round(self.error_rate * 100, 2),
            "requests_per_sec": round(self.requests_per_second, 2),
            "status_distribution": dict(self.status_codes),
            "http_methods": dict(self.methods),
            "top_5_endpoints": self.top_endpoints.most_common(5),
            "top_5_ips": self.top_ips.most_common(5),
        }
