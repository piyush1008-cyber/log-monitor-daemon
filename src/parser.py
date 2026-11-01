"""Parser module for web server access logs (Combined Log Format / Common Log Format)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


# Regular expression for Apache / Nginx Combined Log Format:
# $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
COMBINED_LOG_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+'
    r'(?P<identd>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>[^\s"]+)(?:\s+(?P<protocol>[^"]+))?"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

APACHE_DATETIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


@dataclass
class LogRecord:
    """Represents a structured HTTP server access log entry."""
    ip: str
    user: str
    timestamp: datetime
    method: str
    path: str
    protocol: str
    status: int
    bytes_sent: int
    referer: str
    user_agent: str
    raw: str

    @property
    def is_error(self) -> bool:
        """Returns True if the response code indicates a 4xx client or 5xx server error."""
        return self.status >= 400

    @property
    def is_server_error(self) -> bool:
        """Returns True if the response code indicates a 5xx server error."""
        return self.status >= 500

    @property
    def is_client_error(self) -> bool:
        """Returns True if the response code indicates a 4xx client error."""
        return 400 <= self.status < 500


def parse_timestamp(timestamp_str: str) -> datetime:
    """Parses Apache / Nginx datetime format (e.g. 10/Oct/2026:13:55:36 +0000) or ISO format."""
    try:
        return datetime.strptime(timestamp_str, APACHE_DATETIME_FORMAT)
    except ValueError:
        try:
            # Fallback without timezone
            clean_ts = timestamp_str.split()[0]
            return datetime.strptime(clean_ts, "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            return datetime.now()


def parse_line(line: str) -> Optional[LogRecord]:
    """Parses a single log line into a LogRecord. Returns None if unparseable."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    match = COMBINED_LOG_REGEX.match(line)
    if not match:
        return None

    data = match.groupdict()
    bytes_sent = int(data["size"]) if data["size"].isdigit() else 0

    return LogRecord(
        ip=data["ip"],
        user=data["user"] if data["user"] != "-" else "",
        timestamp=parse_timestamp(data["time"]),
        method=data["method"],
        path=data["path"],
        protocol=data.get("protocol") or "HTTP/1.1",
        status=int(data["status"]),
        bytes_sent=bytes_sent,
        referer=data.get("referer") or "-",
        user_agent=data.get("user_agent") or "-",
        raw=line,
    )
