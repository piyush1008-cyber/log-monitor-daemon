"""Command-line interface for the Log Monitor Daemon."""

import argparse
import sys
from pathlib import Path
from src.alerter import AlertDispatcher
from src.detector import AnomalyDetector
from src.monitor import LogMonitor
from generate_samples import create_sample_log


def print_banner():
    banner = """
===================================================================
       LOG MONITOR DAEMON - Real-Time Server Traffic Analyzer       
===================================================================
    """
    print(banner)


def display_report(monitor: LogMonitor, alert_count: int):
    m = monitor.metrics
    summary = m.summary()

    print("\n" + "=" * 65)
    print("                      TRAFFIC ANALYSIS REPORT                     ")
    print("=" * 65)
    print(f"Total Requests Processed:  {summary['total_requests']}")
    print(f"Total Data Transferred:    {summary['total_bytes_sent'] / 1024:.2f} KB")
    print(f"Overall Error Rate:        {summary['error_rate_pct']}%")
    print(f"Traffic Throughput:        {summary['requests_per_sec']} req/sec")
    print(f"Total Alerts Triggered:    {alert_count}")

    print("\n--- HTTP Status Distribution ---")
    for code, count in sorted(summary['status_distribution'].items()):
        status_desc = "OK" if code < 400 else ("Client Error" if code < 500 else "Server Error")
        print(f"  HTTP {code} ({status_desc}): {count} requests ({count / max(1, m.total_requests):.1%})")

    print("\n--- Top Requested Endpoints ---")
    for path, count in summary['top_5_endpoints']:
        print(f"  {path:<35} : {count:>4} hits")

    print("\n--- Top Active IP Addresses ---")
    for ip, count in summary['top_5_ips']:
        print(f"  {ip:<20} : {count:>4} requests")
    print("=" * 65 + "\n")


def cmd_analyze(args):
    log_path = Path(args.file)
    if not log_path.exists():
        print(f"Error: Log file '{log_path}' not found.")
        sys.exit(1)

    print(f"[*] Ingesting and analyzing log file: {log_path}...")
    alerter = AlertDispatcher(log_file=Path("alerts.log") if args.save_alerts else None)
    detector = AnomalyDetector(
        window_seconds=args.window,
        error_rate_threshold=args.error_threshold,
        ip_rate_threshold=args.ip_threshold,
    )
    monitor = LogMonitor(detector=detector, alerter=alerter)
    monitor.analyze_file(log_path)

    display_report(monitor, len(alerter.history))


def cmd_demo(args):
    sample_file = Path("samples/access.log")
    print("[*] Generating realistic sample server logs with anomalies...")
    create_sample_log(sample_file, total_records=180)

    print("\n[*] Running Log Monitor Daemon over generated traffic...")
    alerter = AlertDispatcher(log_file=Path("samples/detected_alerts.jsonl"))
    detector = AnomalyDetector(window_seconds=60, error_rate_threshold=0.15, ip_rate_threshold=20)
    monitor = LogMonitor(detector=detector, alerter=alerter)
    monitor.analyze_file(sample_file)

    display_report(monitor, len(alerter.history))


def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Log Monitor Daemon - Server Access Log Anomaly Detector")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # analyze
    analyze_parser = subparsers.add_parser("analyze", help="Analyze an existing access log file")
    analyze_parser.add_argument("file", help="Path to access.log file")
    analyze_parser.add_argument("--window", type=int, default=60, help="Sliding window in seconds (default: 60)")
    analyze_parser.add_argument("--error-threshold", type=float, default=0.20, help="Error rate trigger (default: 0.20)")
    analyze_parser.add_argument("--ip-threshold", type=int, default=30, help="Per-IP request burst threshold (default: 30)")
    analyze_parser.add_argument("--save-alerts", action="store_true", help="Save alerts to alerts.log")
    analyze_parser.set_defaults(func=cmd_analyze)

    # demo
    demo_parser = subparsers.add_parser("demo", help="Generate sample logs and execute automated analysis demo")
    demo_parser.set_defaults(func=cmd_demo)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
