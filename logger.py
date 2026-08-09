"""JSONL logging utilities.

Reads and writes Python objects as JSON Lines, creating parent directories as
needed. Shared by the monitor and the review tool so both agree on the format.
"""

import json
import os
from typing import Any, Dict, Iterable, List


def ensure_dir_for(path: str) -> None:
    """Create the parent directory of `path` if it does not exist."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def write_jsonl(path: str, obj: Any) -> None:
    """Append a Python object as a JSON line to `path`.

    Creates parent directories as needed.
    """
    ensure_dir_for(path)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def rewrite_jsonl(path: str, records: Iterable[Any]) -> None:
    """Replace `path` with `records`, one JSON object per line.

    Used for mutable working files such as the review queue; append-only logs
    should go through `write_jsonl` instead.
    """
    ensure_dir_for(path)
    with open(path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def read_jsonl(path: str) -> List[Dict]:
    """Return every record in `path`, or an empty list if it does not exist.

    Malformed lines are skipped rather than raising, so a log truncated
    mid-write does not take the reader down with it.
    """
    records: List[Dict] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        return []
    return records


def read_last_n(path: str, n: int = 10) -> List[Dict]:
    """Return the last `n` records of `path` (handy for debugging)."""
    return read_jsonl(path)[-n:]
