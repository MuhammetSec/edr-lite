"""
Process monitoring using psutil.

Provides ProcessMonitor class that tracks newly spawned processes
by maintaining a set of seen PIDs and returning only new ones on each scan.
"""

import psutil
from typing import Dict, List, Set


class ProcessMonitor:
    """Scans running processes and yields only newly seen PIDs."""

    def __init__(self) -> None:
        self.seen: Set[int] = set() # Set of seen PIDs to track new processes

    def scan(self) -> List[Dict]:
        """Return list of new process info dicts discovered since last scan."""
        new = []
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "create_time", "username"]):
            try:
                info = proc.info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            pid = info.get("pid")
            if pid is None:
                continue
            if pid in self.seen:
                continue

            self.seen.add(pid)

            # normalize cmdline to a single string for logging/rules
            cmdline = info.get("cmdline") or []
            if isinstance(cmdline, (list, tuple)):
                cmdline_str = " ".join(cmdline)
            else:
                cmdline_str = str(cmdline)

            new.append(
                {
                    "pid": pid,
                    "name": info.get("name"),
                    "exe": info.get("exe"),
                    "cmdline": cmdline_str,
                    "create_time": info.get("create_time"),
                    "username": info.get("username"),
                }
            )

        return new
