# AGENTS.md

## 1. Project Overview

- Minimal EDR-like process monitor for newly spawned processes.
- Scans live processes, matches command lines against lightweight suspicious-pattern rules, scores findings, writes JSONL alerts, and prints only high-severity alerts from the entry point.
- Tech stack: Python 3.8+, `psutil`, standard library only, no web framework, no ORM, no background service framework.
- Current version: `v1.0.0`.
- Stability: initial stable release; behavior is intentionally minimal and conservative.

## 2. Architecture & File Roles

- `main.py`
  - Entry point.
  - Parses CLI arguments.
  - Owns the main polling loop.
  - Applies print threshold behavior.
  - Prints alert output to console.
  - Must not become a rules-definition module.
  - Must not become a JSONL writer module.

- `monitor.py`
  - Scans processes via `psutil`.
  - Tracks seen PIDs in memory.
  - Extracts process metadata safely.
  - Applies rule matching to process data.
  - Must not print to console.
  - Must not persist state to disk.
  - Must not own review workflows.

- `rules.py`
  - Defines suspicious patterns.
  - Defines risk scores.
  - Defines platform-aware matching logic.
  - Must contain no disk I/O.
  - Must contain no console output.
  - Must not embed CLI behavior.

- `logger.py`
  - Writes structured JSONL entries to disk.
  - Handles append-only log output.
  - Must not print to console.
  - Must not contain severity/threshold presentation logic.

- `review_tool.py`
  - Standalone CLI for reviewing `alerts.jsonl`.
  - Supports manual triage / stats / listing workflows.
  - Must stay separate from the live monitoring loop.

- `logs/`
  - Output directory for JSONL artifacts.
  - Primary files:
    - `alerts.jsonl`
    - `process_log.jsonl`
    - `whitelist.jsonl`
  - May also contain `review_queue.jsonl` for optional review workflows.

## 3. Critical Rules — DO NOT violate these

- DO NOT add console print statements to `logger.py`.
- Printing belongs in `main.py`.
- DO NOT translate `burst` to any other language in comments or strings.
- DO NOT add new dependencies without updating [requirements.txt](requirements.txt).
- DO NOT change the JSONL schema of `alerts.jsonl` without updating all readers.
- DO NOT modify `self.seen` logic in `monitor.py`; in-memory-only tracking is intentional.
- DO NOT add `colorama` or any other color library; ANSI escape codes are used directly.
- The seen PID set is intentionally NOT persisted to disk in `v1.0`.

## 4. Coding Style & Conventions

- Add type hints to all function signatures.
- Add docstrings to all public functions and classes.
- Use `or ""` for None-safe string operations when reading optional process fields.
  - Example: `p.get("cmdline") or ""`
- `platform.system()` returns `"Darwin"` on macOS; never assume `"macOS"`.
- All timestamps must be UTC ISO8601 with trailing `Z`.
- Use `_utc_now_iso_z()` for timestamp generation.
- Risk scores must match `rules.py` exactly.
  - Examples: `curl=25`, `wget=25`, `bash -c=60`, `python -c=50`, `powershell=70`
- Severity thresholds:
  - `CRITICAL >= 100`
  - `HIGH >= 70`
  - `MEDIUM >= 40`
  - `LOW < 40`

## 5. What Needs Verification Before Changing Rules

- If any pattern is added, removed, or rescored in `rules.py`:
  - Update corresponding expected outputs in [README.md](README.md).
  - Re-check all score examples in the Testing section of [README.md](README.md).
  - Verify that print-threshold behavior in `main.py` still makes sense.
  - Re-check platform-specific examples for Unix and Windows.
  - Re-check severity labels after score changes.

## 6. Known Intentional Limitations (Do Not "Fix" These)

- Seen PIDs reset on restart; this is `v1.0` behavior, not a bug.
- `whoami`, `uname -a`, and `id` are intentionally not flagged.
- `curl` and `wget` have intentionally low scores (`25`) because they are often legitimate.
- Short-lived processes may be missed without `--burst`; this is documented behavior.
- Process tracking is intentionally memory-only.
- Low/medium findings are logged silently; only high-severity alerts are printed.

## 7. Safe Test Commands

- Unix test 1
  - Command:
    - `bash -c "sleep 2; echo 'curl http://example.com'"`
  - Expected severity: `CRITICAL`
  - Expected score: `135`
  - Expected matches:
    - `bash -c(60)`
    - `http://(35)`
    - `curl(25)`
    - `;(15)`

- Unix test 2
  - Command:
    - `bash -c "sleep 2; echo 'hello' | sed 's/hello/ok/'"`
  - Expected severity: `HIGH`
  - Expected score: `75`
  - Expected matches:
    - `bash -c(60)`
    - `|(15)`

- Unix test 3
  - Command:
    - `bash -c "sleep 2; echo 'python -c \"print(1)\"'"`
  - Expected severity: `CRITICAL`
  - Expected score: `125`
  - Expected matches:
    - `bash -c(60)`
    - `python -c(50)`
    - `;(15)`

- Windows test 4
  - Command:
    - `powershell -Command "Start-Sleep -Seconds 2; Write-Output 'Invoke-Expression'"`
  - Expected severity: `HIGH`
  - Expected score: `70`
  - Expected matches:
    - `powershell(70)`

- Windows test 5
  - Command:
    - `powershell -Command "Start-Sleep -Seconds 2; Write-Output 'EncodedCommand'"`
  - Expected severity: `CRITICAL`
  - Expected score: `170`
  - Expected matches:
    - `-encodedcommand(100)`
    - `powershell(70)`