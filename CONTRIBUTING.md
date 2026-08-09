# Contributing / Developer Notes

Working notes for anyone changing this codebase, including future me. Read
section 3 before touching the detection engine.

## 1. Project Overview

- Minimal EDR-like process monitor for newly spawned processes.
- Scans live processes, matches command lines against scored suspicious-pattern
  rules, routes findings by severity, and writes JSONL logs.
- Tech stack: Python 3.8+, `psutil`, standard library only. No web framework,
  no ORM, no background service framework.
- Current version: `v1.1.0`.
- Tests: `python3 -m unittest discover -s tests` (no extra dependencies).

## 2. Architecture & File Roles

- `main.py`
  - Entry point and owner of the polling loop.
  - Parses CLI arguments, applies the whitelist, calls the rule engine, routes
    each detection by severity, prints alerts.
  - Must not define detection patterns.
  - Must not write JSONL directly; it goes through `logger.py`.

- `monitor.py`
  - Collection only: enumerates processes via `psutil` and returns the ones not
    yet reported.
  - Must not print to console.
  - Must not persist state to disk.
  - Must not evaluate rules — that is `rules.py`, called from `main.py`.

- `rules.py`
  - Defines suspicious patterns, risk scores, and the matching logic.
  - Must contain no disk I/O.
  - Must contain no console output.
  - Must not embed CLI behaviour.

- `logger.py`
  - Reads and writes JSONL. The only module that touches log files.
  - Must not print to console.
  - Must not contain severity or threshold logic.

- `review_tool.py`
  - Standalone CLI for triaging `logs/review_queue.jsonl`.
  - Must stay separate from the live monitoring loop.

- `tests/`
  - `test_rules.py` asserts every score published in `README.md`.
  - `test_monitor.py` uses a stub `psutil`; no real processes are touched.

- `logs/`
  - `alerts.jsonl` — HIGH/CRITICAL (score >= 70), append-only.
  - `review_queue.jsonl` — MEDIUM (score 40-69), rewritten as items are triaged.
  - `whitelist.jsonl` — approved patterns, read by the monitor at startup.
  - `process_log.jsonl` — raw telemetry, only written with `--log-all`.

## 3. Detection Engine Invariants

The engine got these wrong in v1.0 and they are the reason v1.1 exists. Do not
regress them.

- **Patterns are split into indicators and modifiers.** Indicators (`bash -c`,
  `powershell`, `base64 -d`) are meaningful alone. Modifiers (`|`, `;`, `&&`,
  `||`, `http://`, `https://`, `download`) are not — they appear in a large
  share of ordinary command lines. Nothing is reported unless at least one
  indicator matched.
- **Overlapping patterns score once.** `bash -c` contains `sh -c`;
  `-encodedcommand` contains `-enc`. `_drop_subsumed()` removes any matched
  pattern that is a substring of another matched pattern.
- **Matching is word-bounded on alphanumeric edges.** `curl` must not fire on
  `libcurl.dylib`, and `nc -` must not fire on `sync -f`. Patterns whose edge
  is punctuation (`-enc`, `/dev/tcp`, `|`) keep plain substring semantics on
  that side.
- Severity thresholds: `CRITICAL >= 100`, `HIGH >= 70`, `MEDIUM >= 40`,
  `LOW < 40`. `INFO` means no indicator matched.
- Risk scores are fixed: `curl=25`, `wget=25`, `bash -c=60`, `python -c=50`,
  `powershell=70`, `-encodedcommand=100`.

## 4. Coding Style & Conventions

- Type hints on all function signatures.
- Docstrings on all public functions and classes.
- Use `or ""` for None-safe string operations on optional process fields, e.g.
  `p.get("cmdline") or ""`.
- `platform.system()` returns `"Darwin"` on macOS; never assume `"macOS"`.
- All timestamps are UTC ISO8601 with a trailing `Z`, produced by
  `_utc_now_iso_z()`.
- Console output uses raw ANSI escape codes. Do not add `colorama` or any other
  colour library.
- Alert prints pass `flush=True` so output is not swallowed when stdout is a
  pipe or file.
- No new runtime dependencies without updating `requirements.txt`.

## 5. Before Changing Detection Rules

If a pattern is added, removed, rescored, or reclassified:

1. Run `python3 -m unittest discover -s tests`. `test_rules.py` asserts the
   exact scores published in the README, so it will fail on drift.
2. Update the affected examples in `README.md` — both the English and Turkish
   sections.
3. Re-check that severity routing in `main.py` still makes sense.
4. Confirm the false-positive tests in `TestModifiersNeedAnAnchor` still pass;
   they encode real noise observed on a live macOS host.

Do not change the JSONL schema of `alerts.jsonl` without updating
`review_tool.py`, which reads it.

## 6. Known Intentional Limitations

- Process tracking is in memory only; the seen set does not survive a restart.
  It is keyed by `(pid, create_time)` so recycled PIDs are correctly treated as
  new processes, and it is pruned each scan so it stays bounded.
- Detection is command-line pattern matching only. No parent/child lineage, no
  file or network telemetry. See the roadmap in `README.md`.
- `whoami`, `uname -a`, and `id` are intentionally not flagged.
- `curl` and `wget` score low (`25`) because they are usually legitimate.
- Short-lived processes may be missed without `--burst`.
- LOW findings (score < 40) are not persisted. Use `--log-all` to capture raw
  telemetry for everything the monitor observed.

## 7. Verified Test Cases

Scores below are asserted in `tests/test_rules.py`.

| Platform | Command | Severity | Score | Matches |
| --- | --- | --- | --- | --- |
| Unix | `bash -c "sleep 2; echo 'curl http://example.com'"` | CRITICAL | 135 | `bash -c(60)`, `http://(35)`, `curl(25)`, `;(15)` |
| Unix | `bash -c "sleep 2; echo 'hello' \| sed 's/hello/ok/'"` | HIGH | 90 | `bash -c(60)`, `\|(15)`, `;(15)` |
| Unix | `bash -c "sleep 2; echo 'python -c \"print(1)\"'"` | CRITICAL | 125 | `bash -c(60)`, `python -c(50)`, `;(15)` |
| Windows | `powershell -Command "Start-Sleep -Seconds 2; Write-Output 'hello'"` | HIGH | 85 | `powershell(70)`, `;(15)` |
| Windows | `powershell -Command "Start-Sleep -Seconds 2; Write-Output '-EncodedCommand'"` | CRITICAL | 185 | `-encodedcommand(100)`, `powershell(70)`, `;(15)` |

All of these are safe: they echo strings containing suspicious tokens and never
download or execute anything.
