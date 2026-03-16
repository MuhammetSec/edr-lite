"""Minimal EDR-like process monitor (v1.0)

Discovers newly spawned processes using psutil, logs new process
observations to JSONL, applies pattern-based suspicious detection with
risk scoring/severity, writes all detections to alerts JSONL and prints
only HIGH/CRITICAL, and supports burst scanning to catch short-lived processes.
"""

import time
import socket
import platform
import argparse
from datetime import datetime, timezone

from monitor import ProcessMonitor
from rules import find_suspicious, get_suspicious_keywords
from logger import write_jsonl

__version__ = "1.0.0"

# File paths for JSONL outputs
PROCESS_EVENTS = "logs/process_log.jsonl"
ALERTS = "logs/alerts.jsonl"  # All detections are stored here now
SLEEP_SECONDS = 1
# Console output threshold
# Only print HIGH/CRITICAL (>=70); MEDIUM/LOW are logged silently.
PRINT_THRESHOLD = 70


def _utc_now_iso_z() -> str:
    """Return current UTC time in ISO8601 with trailing 'Z'."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def make_event_dict(proc_info: dict) -> dict:
    """Add host and first_seen fields to a process info dict."""
    e = proc_info.copy()
    e.setdefault("first_seen", _utc_now_iso_z())
    e["host"] = socket.gethostname()
    return e


def _parse_args():
    """Parse CLI arguments for interval and burst scanning settings."""
    parser = argparse.ArgumentParser(description="Minimal EDR-like process monitor")
    parser.add_argument(
        "--interval",
        type=float,
        default=None,
        help="Scan interval in seconds (overrides default)",
    )
    parser.add_argument(
        "--burst",
        type=int,
        default=10,
        help="Number of rapid scans per interval to catch short-lived processes (default: 10)",
    )
    parser.add_argument(
        "--burst-sleep",
        type=float,
        default=0.05,
        help="Sleep between burst scans in seconds (default: 0.05)",
    )
    parser.add_argument(
        "--log-all",
        action="store_true",
        help="Log all processes to process_log.jsonl (default: off, only alerts are logged)",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    monitor = ProcessMonitor()
    system = platform.system()
    keyword_count = len(get_suspicious_keywords())
    sleep_seconds = max(0.2, args.interval) if args.interval is not None else SLEEP_SECONDS
    print(f"Starting minimal EDR-like process monitor v{__version__} on {system}.")
    print(
        f"Monitoring {keyword_count} suspicious patterns every {sleep_seconds:.1f}s. Press Ctrl-C to stop."
    )
    try:
        while True:
            t0 = time.time()
            # Burst scanning to catch very short-lived processes
            for _ in range(max(1, args.burst)):
                new = monitor.scan()
                for p in new:
                    event = make_event_dict(p)
                    
                    # Optional: log all processes if --log-all is enabled
                    if args.log_all:
                        write_jsonl(PROCESS_EVENTS, event)

                    # Check rules against name/exe/cmdline
                    texts = [p.get("name") or "", p.get("exe") or "", p.get("cmdline") or ""]
                    result = find_suspicious(texts)
                    
                    if result["matches"]:
                        # Format matches for logging
                        match_list = [f"{pattern}({score})" for pattern, score in result["matches"]]
                        score = result["total_score"]
                        
                        alert = {
                            "pid": p.get("pid"),
                            "severity": result["severity"],
                            "risk_score": score,
                            "matches": match_list,
                            "event": event,
                            "timestamp": _utc_now_iso_z(),
                        }
                        # Always log detections to alerts.jsonl
                        alert["status"] = "DETECTION"
                        write_jsonl(ALERTS, alert)

                        # Print only for HIGH/CRITICAL
                        if score >= PRINT_THRESHOLD:
                            color = "\033[91m" if result["severity"] == "CRITICAL" else "\033[93m"
                            reset = "\033[0m"
                            print(f"{color}🚨 [DETECTION - {result['severity']}]{reset}")
                            print(f"   PID: {p.get('pid')} | Score: {score}")
                            print(f"   Matches: {match_list}")
                            print(f"   Command: {(p.get('cmdline') or '')[:100]}")
                            print()

                time.sleep(max(0.0, args.burst_sleep))

            # Respect outer interval accounting for burst time
            elapsed = time.time() - t0
            remainder = sleep_seconds - elapsed
            if remainder > 0:
                time.sleep(remainder)
    except KeyboardInterrupt:
        print("Stopping monitor.")


if __name__ == "__main__":
    main()