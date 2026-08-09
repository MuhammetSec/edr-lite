"""Process monitoring using psutil.

Provides ProcessMonitor, which tracks newly spawned processes and returns only
the ones it has not reported before.
"""

import psutil
from typing import Dict, List, Set, Tuple

# A process is identified by (pid, create_time) rather than pid alone. The OS
# recycles PIDs, so a bare int key would silently treat a brand new process as
# already-seen once its number came back around.
ProcessKey = Tuple[int, float]


class ProcessMonitor:
    """Scans running processes and yields only newly seen ones."""

    def __init__(self) -> None:
        self.seen: Set[ProcessKey] = set()

    def scan(self) -> List[Dict]:
        """Return list of new process info dicts discovered since last scan."""
        new = []
        alive: Set[ProcessKey] = set()

        for proc in psutil.process_iter(
            ["pid", "name", "exe", "cmdline", "create_time", "username"]
        ):
            try:
                info = proc.info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            pid = info.get("pid")
            if pid is None:
                continue

            key: ProcessKey = (pid, info.get("create_time") or 0.0)
            alive.add(key)
            if key in self.seen:
                continue

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

        # Forget processes that have exited. Tracking stays in memory only, but
        # pruning keeps the set bounded during long runs instead of growing
        # once per process the host has ever started.
        self.seen = alive
        return new
