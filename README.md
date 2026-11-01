# Log Monitor Daemon

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests: Pytest](https://img.shields.io/badge/tests-pytest-brightgreen.svg)](https://docs.pytest.org/)
[![Architecture: Event-Driven](https://img.shields.io/badge/architecture-event--driven-orange.svg)](https://github.com/piyush1008-cyber/log-monitor-daemon)
[![Code Style: Clean OOP](https://img.shields.io/badge/code%20style-clean%20OOP-purple.svg)](https://github.com/piyush1008-cyber/log-monitor-daemon)

> **High-performance, zero-dependency streaming log monitor and security anomaly detector written in Python.** Designed for real-time SRE/DevOps observability, server log analytics, sliding-window spike detection, and automated threat alerting.

---

## Architecture Overview

```mermaid
flowchart LR
    A[Access Log Stream\nApache / Nginx] --> B[Log Parser\nRegex Lexer]
    B --> C[LogRecord Dataclass]
    C --> D[Metrics Aggregator\nCounter & Throughput]
    C --> E[Sliding Window Engine\nDeque-based O(1) Eviction]
    E --> F{Rule Evaluators}
    F -->|Probe Check| G[Suspicious Path Alerts]
    F -->|Burst Check| H[IP Rate Spike Alerts]
    F -->|Error Threshold| I[5xx Burst / Spike Alerts]
    G & H & I --> J[Alert Dispatcher\nConsole / JSONL / Webhook]
```

---

## Key Features

- **Standard Log Format Support:** Parses Nginx & Apache Combined Log Format (`IP`, `Identd`, `User`, `Time`, `Method`, `Path`, `Status`, `Bytes`, `Referer`, `User-Agent`).
- **Sliding-Window Anomaly Detection:** Constant-time `O(1)` amortized deque eviction tracking error rates and request bursts over configurable time windows (e.g. 60 seconds).
- **Proactive Threat Detection:** Flags vulnerability scanning targeting sensitive files (`/.env`, `/wp-admin`, `/.git/config`, `/phpmyadmin`).
- **DoS & Scraping Guard:** Flags single-source IP address request surges exceeding rate limits.
- **5xx Server Error Bursts:** Automatically surfaces infrastructure outages and microservice failure spikes.
- **Zero Production Dependencies:** Pure Python standard library implementation with zero external runtime bloat.

---

## Directory Structure

```
log-monitor-daemon/
├── main.py                     # CLI entry point (analyze, demo, watch)
├── generate_samples.py         # Realistic traffic & anomaly generator
├── requirements.txt            # Test runner dependencies
├── LICENSE                     # MIT License
├── README.md                   # Documentation & guide
├── src/
│   ├── __init__.py
│   ├── parser.py               # Combined Log Format regex parser
│   ├── detector.py             # Sliding-window anomaly detection
│   ├── metrics.py              # Real-time traffic metrics collector
│   ├── alerter.py              # Multi-destination alert dispatcher
│   └── monitor.py              # Core daemon orchestrator
└── tests/
    ├── test_parser.py          # Log regex unit tests
    ├── test_detector.py        # Sliding-window anomaly tests
    └── test_monitor.py         # End-to-end integration tests
```

---

## Quickstart & Usage

### 1. Run Automated Demo with Anomaly Simulation
```bash
python main.py demo
```
This generates a synthetic dataset containing normal traffic alongside vulnerability scans and a 500 error spike, ingests it, and displays the real-time alert feed and analysis report.

### 2. Analyze Existing Production Logs
```bash
python main.py analyze /var/log/nginx/access.log --window 60 --error-threshold 0.15 --save-alerts
```

#### CLI Options:
| Flag | Default | Description |
|------|---------|-------------|
| `--window` | `60` | Sliding window duration in seconds |
| `--error-threshold` | `0.20` | Fraction of errors (0.0 - 1.0) required to trigger error spike alerts |
| `--ip-threshold` | `30` | Maximum requests per IP in window before rate limit warning |
| `--save-alerts` | `False` | Persist detected alerts to `alerts.log` in structured JSONL format |

---

## Running the Test Suite

Execute the unit and integration tests with `pytest`:

```bash
pytest -v
```

Sample output:
```
tests/test_parser.py::test_parse_valid_combined_log PASSED               [ 20%]
tests/test_parser.py::test_parse_error_statuses PASSED                   [ 40%]
tests/test_parser.py::test_parse_invalid_or_comment_line PASSED          [ 60%]
tests/test_detector.py::test_detect_suspicious_path PASSED               [ 80%]
tests/test_detector.py::test_detect_ip_rate_spike PASSED                 [100%]
tests/test_monitor.py::test_monitor_end_to_end_stream PASSED            [100%]
```

---

## Author & License

- **Author:** Piyush Kangle ([@piyush1008-cyber](https://github.com/piyush1008-cyber))
- **Email:** piyushkangle@gmail.com
- **License:** [MIT License](LICENSE)
