"""JSONL logging utilities.

Provides functions to write Python objects as JSON Lines to files,
with automatic directory creation. Includes a helper to read the last N lines
for debugging purposes.
"""

import json
import os
from typing import Any


def ensure_dir_for(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)


def write_jsonl(path: str, obj: Any) -> None:
    """Append a Python object as a JSON line to `path`.

    Creates parent directories as needed.
    """
    ensure_dir_for(path)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def read_last_n(path: str, n: int = 10):
    """Utility to read last n lines (not used by monitor, handy for debugging)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return [json.loads(x) for x in lines[-n:]]
    except FileNotFoundError:
        return []
