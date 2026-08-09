"""Minimal EDR-like process monitor (v1.1)

Discovers newly spawned processes using psutil, applies pattern-based
suspicious detection with risk scoring/severity, routes findings by severity
(alerts vs. review queue), honours the review tool's whitelist, and supports
burst scanning to catch short-lived processes.
"""

import time
import socket
import platform
import argparse
from datetime import datetime, timezone
from typing import List

from monitor import ProcessMonitor
from rules import find_suspicious, get_suspicious_keywords
from logger import write_jsonl, read_jsonl

__version__ = "1.1.0"

# File paths for JSONL outputs
PROCESS_EVENTS = "logs/process_log.jsonl"
ALERTS = "logs/alerts.jsonl"
REVIEW_QUEUE = "logs/review_queue.jsonl"
WHITELIST = "logs/whitelist.jsonl"
SLEEP_SECONDS = 1

# Severity routing.
#   >= 70  HIGH/CRITICAL -> alerts.jsonl, printed to console
#   >= 40  MEDIUM        -> review_queue.jsonl, silent, triaged by review_tool.py
#   <  40  LOW           -> noise floor, not persisted (use --log-all for raw telemetry)
PRINT_THRESHOLD = 70
REVIEW_THRESHOLD = 40


def _utc_now_iso_z() -> str:
    """Return current UTC time in ISO8601 with trailing 'Z'."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def make_event_dict(proc_info: dict) -> dict:
    """Add host and first_seen fields to a process info dict."""
    e = proc_info.copy()
    e.setdefault("first_seen", _utc_now_iso_z())
    e["host"] = socket.gethostname()
    return e


def load_whitelist(path: str = WHITELIST) -> List[str]:
    """Return lowercased cmdline patterns approved via review_tool.py.

    Read once at startup; entries added mid-run apply from the next restart.
    """
    patterns = []
    for record in read_jsonl(path):
        pattern = record.get("cmdline_pattern")
        if pattern:
            patterns.append(pattern.lower())
    return patterns


def is_whitelisted(cmdline: str, whitelist: List[str]) -> bool:
    """Return True if `cmdline` matches any approved pattern."""
    lowered = (cmdline or "").lower()
    return any(pattern in lowered for pattern in whitelist)


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
        help="Log every observed process to process_log.jsonl (default: off)",
    )
    return parser.parse_args()


def handle_detection(proc: dict, event: dict, result: dict) -> None:
    """Route one detection to the right log and print it if severe enough."""
    score = result["total_score"]
    match_list = [f"{pattern}({score})" for pattern, score in result["matches"]]

    detection = {
        "pid": proc.get("pid"),
        "severity": result["severity"],
        "risk_score": score,
        "matches": match_list,
        "event": event,
        "timestamp": _utc_now_iso_z(),
    }

    if score >= PRINT_THRESHOLD:
        detection["status"] = "ALERT"
        write_jsonl(ALERTS, detection)
        color = "\033[91m" if result["severity"] == "CRITICAL" else "\033[93m"
        reset = "\033[0m"
        # flush so alerts appear immediately when stdout is a pipe or file
        print(f"{color}🚨 [DETECTION - {result['severity']}]{reset}", flush=True)
        print(f"   PID: {proc.get('pid')} | Score: {score}", flush=True)
        print(f"   Matches: {match_list}", flush=True)
        print(f"   Command: {(proc.get('cmdline') or '')[:100]}", flush=True)
        print(flush=True)
    elif score >= REVIEW_THRESHOLD:
        detection["status"] = "REVIEW"
        write_jsonl(REVIEW_QUEUE, detection)


def main() -> None:
    args = _parse_args()
    monitor = ProcessMonitor()
    whitelist = load_whitelist()
    system = platform.system()
    keyword_count = len(get_suspicious_keywords())
    sleep_seconds = max(0.2, args.interval) if args.interval is not None else SLEEP_SECONDS

    print(f"Starting minimal EDR-like process monitor v{__version__} on {system}.", flush=True)
    print(
        f"Monitoring {keyword_count} suspicious patterns every {sleep_seconds:.1f}s. "
        f"Press Ctrl-C to stop.",
        flush=True,
    )
    if whitelist:
        print(f"Whitelist loaded: {len(whitelist)} approved patterns.", flush=True)

    try:
        while True:
            t0 = time.time()
            # Burst scanning to catch very short-lived processes
            for _ in range(max(1, args.burst)):
                for p in monitor.scan():
                    event = make_event_dict(p)

                    if args.log_all:
                        write_jsonl(PROCESS_EVENTS, event)

                    if is_whitelisted(p.get("cmdline"), whitelist):
                        continue

                    # Check rules against name/exe/cmdline
                    texts = [p.get("name") or "", p.get("exe") or "", p.get("cmdline") or ""]
                    result = find_suspicious(texts)

                    if result["matches"]:
                        handle_detection(p, event, result)

                time.sleep(max(0.0, args.burst_sleep))

            # Respect outer interval accounting for burst time
            remainder = sleep_seconds - (time.time() - t0)
            if remainder > 0:
                time.sleep(remainder)
    except KeyboardInterrupt:
        print("Stopping monitor.", flush=True)


if __name__ == "__main__":
    main()
