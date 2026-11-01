"""Script to generate realistic sample Apache/Nginx access log files for testing and demos."""

import random
from datetime import datetime, timedelta
from pathlib import Path


IPS = [
    "192.168.1.15", "10.0.0.42", "172.16.0.8", "192.168.1.88",
    "203.0.113.195", "198.51.100.2", "198.51.100.77"
]

NORMAL_PATHS = [
    ("/", "GET", 200, 1420),
    ("/about", "GET", 200, 3200),
    ("/api/v1/products", "GET", 200, 4850),
    ("/api/v1/products/42", "GET", 200, 1120),
    ("/login", "POST", 200, 450),
    ("/dashboard", "GET", 200, 6800),
    ("/static/css/main.css", "GET", 200, 12400),
    ("/static/js/bundle.js", "GET", 200, 45200),
    ("/non-existent-page", "GET", 404, 280),
]

SUSPICIOUS_PATHS = [
    ("/.env", "GET", 404, 180),
    ("/wp-admin", "GET", 403, 210),
    ("/phpmyadmin", "GET", 404, 180),
    ("/.git/config", "GET", 404, 180),
]

ERROR_PATHS = [
    ("/api/v1/checkout", "POST", 500, 520),
    ("/api/v1/payment", "POST", 502, 340),
    ("/api/v1/inventory", "GET", 503, 290),
]


def generate_log_line(ip: str, method: str, path: str, status: int, size: int, dt: datetime) -> str:
    ts = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "{user_agent}"'


def create_sample_log(output_file: Path, total_records: int = 150) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    base_time = datetime(2026, 11, 1, 10, 0, 0)
    lines = []

    # 1. Normal traffic baseline
    for i in range(total_records - 40):
        dt = base_time + timedelta(seconds=i * 2)
        ip = random.choice(IPS)
        path, method, status, size = random.choice(NORMAL_PATHS)
        lines.append(generate_log_line(ip, method, path, status, size, dt))

    # 2. Suspicious path probing
    for i, (path, method, status, size) in enumerate(SUSPICIOUS_PATHS):
        dt = base_time + timedelta(seconds=120 + i * 2)
        lines.append(generate_log_line("203.0.113.99", method, path, status, size, dt))

    # 3. High-rate IP burst (scraping / brute force)
    for i in range(25):
        dt = base_time + timedelta(seconds=180 + (i * 0.5))
        lines.append(generate_log_line("198.51.100.99", "GET", "/api/v1/products", 200, 4850, dt))

    # 4. 5xx Server Error burst
    for i in range(10):
        dt = base_time + timedelta(seconds=240 + i)
        path, method, status, size = random.choice(ERROR_PATHS)
        lines.append(generate_log_line(random.choice(IPS), method, path, status, size, dt))

    # Sort lines chronologically
    with open(output_file, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")

    print(f"Sample log generated: {output_file} ({len(lines)} lines)")


if __name__ == "__main__":
    create_sample_log(Path("samples/access.log"))
