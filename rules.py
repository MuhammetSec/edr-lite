"""Suspicious pattern detection with risk scoring.

Defines platform-specific suspicious patterns (Windows, Unix/Linux/macOS) with
associated risk scores, matches them against process command lines, and derives
a severity level (CRITICAL/HIGH/MEDIUM/LOW).

Patterns fall into two classes:

``INDICATORS``
    Tools and techniques that are meaningful on their own (``powershell``,
    ``base64 -d``, ``/dev/tcp``). At least one indicator must match before
    anything is reported.

``MODIFIERS``
    Shell chaining punctuation and URL tokens (``|``, ``;``, ``http://``).
    These occur in a large share of perfectly ordinary command lines, so they
    only contribute score once an indicator has already matched. Scoring them
    standalone is what made a browser's ``--features=A|B`` flag look like a
    threat.
"""

import platform
import re
from typing import Dict, Iterable, List, Optional, Tuple

# Risk scores: CRITICAL=100, HIGH=70, MEDIUM=40, LOW=20
# Pattern format: (pattern, risk_score)

# Platform-specific indicators with risk scores
WINDOWS_INDICATORS: List[Tuple[str, int]] = [
    ("-enc", 100),  # Encoded command - highly suspicious
    ("-encodedcommand", 100),
    ("powershell", 70),
    ("pwsh", 70),
    ("rundll32", 80),  # Often used in attacks
    ("mshta", 80),
    ("regsvr32", 70),
    ("certutil", 60),  # Can download files
    ("bitsadmin", 60),
    ("cmd.exe /c", 50),
    ("cmd /c", 50),
    ("wscript", 50),
    ("cscript", 50),
]

UNIX_INDICATORS: List[Tuple[str, int]] = [
    ("/dev/tcp", 90),  # Direct TCP connection - very suspicious
    ("base64 -d", 80),  # Decoding - often malicious
    ("bash -c", 60),
    ("sh -c", 60),
    ("/bin/bash -c", 60),
    ("/bin/sh -c", 60),
    ("nc -", 70),  # Netcat
    ("netcat", 70),
    ("python -c", 50),
    ("perl -e", 50),
    ("ruby -e", 50),
    ("curl", 25),  # Lower - often legitimate
    ("wget", 25),  # Lower - often legitimate
]

# Context amplifiers. Never reported on their own - see module docstring.
MODIFIERS: List[Tuple[str, int]] = [
    ("download", 45),
    ("http://", 35),
    ("https://", 25),
    ("&&", 20),
    ("||", 20),
    ("|", 15),
    (";", 15),
]

_WORD = re.compile(r"\w")


def get_rule_sets(
    system: Optional[str] = None,
) -> Tuple[List[Tuple[str, int]], List[Tuple[str, int]]]:
    """Return ``(indicators, modifiers)`` for `system` (default: this host).

    `system` accepts the same values as ``platform.system()``; note that macOS
    reports ``"Darwin"``. Unknown platforms fall back to every indicator.
    """
    name = (system or platform.system()).lower()

    if name == "windows":
        indicators = WINDOWS_INDICATORS
    elif name in ("darwin", "linux"):  # darwin = macOS
        indicators = UNIX_INDICATORS
    else:
        indicators = WINDOWS_INDICATORS + UNIX_INDICATORS

    return indicators, MODIFIERS


def get_suspicious_keywords(system: Optional[str] = None) -> List[Tuple[str, int]]:
    """Return every pattern in play for `system`, indicators first."""
    indicators, modifiers = get_rule_sets(system)
    return indicators + modifiers


def calculate_severity(total_score: int) -> str:
    """Convert a total risk score into a severity label."""
    if total_score >= 100:
        return "CRITICAL"
    elif total_score >= 70:
        return "HIGH"
    elif total_score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def _matches_word_bounded(text: str, pattern: str) -> bool:
    """Return True if `pattern` occurs in `text` outside of a longer word.

    ``curl`` should fire on ``curl http://x`` but not on ``/usr/lib/libcurl.dylib``.
    Only alphanumeric pattern edges are boundary-checked; a pattern that starts
    or ends with punctuation (``-enc``, ``/dev/tcp``, ``|``) keeps plain
    substring semantics on that side, since there is no word to be buried in.
    """
    start = 0
    while True:
        i = text.find(pattern, start)
        if i == -1:
            return False
        end = i + len(pattern)
        head_ok = not (pattern[0].isalnum() and i > 0 and _WORD.match(text[i - 1]))
        tail_ok = not (
            pattern[-1].isalnum() and end < len(text) and _WORD.match(text[end])
        )
        if head_ok and tail_ok:
            return True
        start = i + 1


def _collect(patterns: List[Tuple[str, int]], texts: List[str]) -> Dict[str, int]:
    """Return ``{pattern: score}`` for every pattern matching any of `texts`."""
    found: Dict[str, int] = {}
    for pattern, score in patterns:
        lowered_pattern = pattern.lower()
        for text in texts:
            if _matches_word_bounded(text, lowered_pattern):
                # Keep the highest score if a pattern is listed more than once
                if found.get(pattern, -1) < score:
                    found[pattern] = score
                break
    return found


def _drop_subsumed(found: Dict[str, int]) -> Dict[str, int]:
    """Drop patterns that are substrings of another matched pattern.

    ``bash -c`` already implies ``sh -c`` and ``-encodedcommand`` implies
    ``-enc``. Scoring both counts a single technique twice, which is what
    inflated one shell invocation to 120 points.
    """
    return {
        pattern: score
        for pattern, score in found.items()
        if not any(pattern != other and pattern in other for other in found)
    }


def find_suspicious(texts: Iterable[str], system: Optional[str] = None) -> Dict:
    """Return matched suspicious patterns with risk scores.

    Returns a detection only when at least one indicator matched; modifiers
    alone are treated as noise.

    Returns:
        {
            "matches": [(pattern, score), ...],   # highest score first
            "total_score": int,
            "severity": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO"
        }
    """
    indicators, modifiers = get_rule_sets(system)
    lowered = [t.lower() for t in texts if t]

    anchored = _collect(indicators, lowered)
    if not anchored:
        return {"matches": [], "total_score": 0, "severity": "INFO"}

    found = _drop_subsumed({**anchored, **_collect(modifiers, lowered)})

    total_score = sum(found.values())
    # Stable sort: equal scores keep rule-declaration order.
    matches = sorted(found.items(), key=lambda item: item[1], reverse=True)

    return {
        "matches": matches,
        "total_score": total_score,
        "severity": calculate_severity(total_score),
    }
