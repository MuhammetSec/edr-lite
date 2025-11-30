"""Suspicious pattern detection with risk scoring.

Defines platform-specific suspicious keywords (Windows, Unix/Linux/macOS)
with associated risk scores. Provides functions to match patterns against
process command lines and calculate severity levels (CRITICAL/HIGH/MEDIUM/LOW).
"""

import platform
from typing import Iterable, List, Dict, Tuple

# Risk scores: CRITICAL=100, HIGH=70, MEDIUM=40, LOW=20
# Pattern format: (pattern, risk_score)

# Platform-specific suspicious keywords with risk scores
WINDOWS_SUSPICIOUS: List[Tuple[str, int]] = [
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

UNIX_SUSPICIOUS: List[Tuple[str, int]] = [
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

# Common suspicious patterns for all platforms
COMMON_SUSPICIOUS: List[Tuple[str, int]] = [
    ("download", 45),
    ("http://", 35),
    ("https://", 25),
    ("&&", 20),
    ("||", 20),
    ("|", 15),
    (";", 15),
]


def get_suspicious_keywords() -> List[Tuple[str, int]]:
    """Return platform-specific suspicious keywords with risk scores."""
    system = platform.system().lower()
    
    if system == "windows":
        return WINDOWS_SUSPICIOUS + COMMON_SUSPICIOUS
    elif system in ("darwin", "linux"):
        return UNIX_SUSPICIOUS + COMMON_SUSPICIOUS
    else:
        # Fallback: combine all
        return WINDOWS_SUSPICIOUS + UNIX_SUSPICIOUS + COMMON_SUSPICIOUS


def calculate_severity(total_score: int) -> str:
    """Convert total risk score to severity level."""
    if total_score >= 100:
        return "CRITICAL"
    elif total_score >= 70:
        return "HIGH"
    elif total_score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def find_suspicious(texts: Iterable[str]) -> Dict:
    """Return matched suspicious patterns with risk scores.

    Returns:
        {
            "matches": [(pattern, score), ...],
            "total_score": int,
            "severity": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"
        }
    """
    keywords = get_suspicious_keywords()
    found = {}  # pattern -> score
    lowered = [t.lower() for t in texts if t]
    
    for pattern, score in keywords:
        pattern_lower = pattern.lower()
        for t in lowered:
            if pattern_lower in t:
                # Take highest score if pattern matches multiple times
                if pattern not in found or found[pattern] < score:
                    found[pattern] = score
                break
    
    if not found:
        return {"matches": [], "total_score": 0, "severity": "INFO"}
    
    total_score = sum(found.values())
    severity = calculate_severity(total_score)
    matches = [(k, v) for k, v in sorted(found.items(), key=lambda x: x[1], reverse=True)]
    
    return {
        "matches": matches,
        "total_score": total_score,
        "severity": severity
    }
