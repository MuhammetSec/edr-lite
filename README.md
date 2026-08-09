 > 🇹🇷 Turkish version is available at the bottom of this file

# Minimal EDR-like Process Monitor

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-informational?style=for-the-badge&logo=linux&logoColor=white&color=0078D4)
![Version](https://img.shields.io/badge/Version-v1.1.0-brightgreen?style=for-the-badge)
![Tests](https://img.shields.io/badge/Tests-28%20passing-success?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

A small endpoint-telemetry tool: it watches for newly spawned processes, scores
their command lines against a suspicious-pattern ruleset, and routes findings by
severity. About 700 lines of Python plus a test suite, with one runtime
dependency (`psutil`).

It is a learning project, not a product — there is no kernel driver, no agent
infrastructure, and no response capability. What it does implement end to end is
the part that interested me: **turning noisy process telemetry into a small
number of findings worth looking at.**

---

## Table of Contents

- [How Detection Works](#how-detection-works)
- [Cutting the False Positives](#cutting-the-false-positives)
- [Architecture](#architecture)
- [Setup](#setup)
- [Running the Monitor](#running-the-monitor)
- [Review Tool](#review-tool)
- [Example Output](#example-output)
- [Risk Scores](#risk-scores)
- [File Structure](#file-structure)
- [Testing](#testing)
- [Known Limitations](#known-limitations)
- [Roadmap](#roadmap)
- [🇹🇷 Türkçe Dokümantasyon](#-türkçe-dokümantasyon)

---

## How Detection Works

Each new process contributes its `name`, `exe`, and `cmdline` to a match pass.
Patterns come in two classes:

| Class | Examples | Behaviour |
| --- | --- | --- |
| **Indicator** | `bash -c`, `powershell`, `base64 -d`, `/dev/tcp`, `curl` | Meaningful on its own. At least one must match or nothing is reported. |
| **Modifier** | `\|`, `;`, `&&`, `\|\|`, `http://`, `https://`, `download` | Only contributes score once an indicator has matched. |

Matched scores are summed and mapped to a severity:

```
CRITICAL >= 100    HIGH >= 70    MEDIUM >= 40    LOW < 40
```

Severity then decides where the finding goes:

| Score | Severity | Destination |
| --- | --- | --- |
| >= 70 | HIGH / CRITICAL | `logs/alerts.jsonl` + printed to console in colour |
| 40-69 | MEDIUM | `logs/review_queue.jsonl`, silent — triaged with `review_tool.py` |
| < 40 | LOW | Dropped as noise (use `--log-all` to keep raw telemetry) |

Two rules keep the arithmetic honest:

- **Overlapping patterns score once.** `bash -c` contains `sh -c`, and
  `-encodedcommand` contains `-enc`. A matched pattern that is a substring of
  another matched pattern is discarded, so one technique is counted one time.
- **Matching is word-bounded on alphanumeric edges.** `curl` fires on
  `curl http://x` but not on `/usr/lib/libcurl.dylib`; `nc -` fires on netcat but
  not on `sync -f`.

## Cutting the False Positives

The first version scored shell punctuation on its own. On a live macOS
workstation that ruleset logged **147 detections, of which 144 (98%) were a
single browser's renderer processes** — because a Chromium feature flag happens
to contain a pipe character:

```
--origin-trial-disabled-features=CanvasTextNg|WebAssemblyCustomDescriptors
```

A `|` is not evidence of anything. It is a shell operator *when a shell is
involved*, which is exactly what the indicator/modifier split encodes. Together
with substring subsumption and word boundaries, every one of those 144 alerts
now scores zero, while the genuine test cases score the same or higher.

These cases are pinned in `tests/test_rules.py` so the noise cannot come back.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                            main.py                               │
│  Entry point. Parses CLI args, owns the polling loop, applies    │
│  the whitelist, calls the rule engine, routes by severity,       │
│  prints alerts.                                                  │
└───────┬───────────────────┬──────────────────────┬───────────────┘
        │ scan()            │ find_suspicious()    │ write_jsonl()
        ▼                   ▼                      ▼
┌────────────────┐  ┌──────────────────┐  ┌──────────────────────┐
│   monitor.py   │  │     rules.py     │  │      logger.py       │
│ Enumerates     │  │ Patterns, risk   │  │ Reads and writes     │
│ processes via  │  │ scores, matching │  │ JSONL. The only      │
│ psutil.        │  │ and severity.    │  │ module touching      │
│ Collection     │  │ Pure logic, no   │  │ log files.           │
│ only.          │  │ I/O.             │  │                      │
└────────────────┘  └──────────────────┘  └──────────┬───────────┘
                                                     │
                                                     ▼
                                        ┌────────────────────────┐
                                        │         logs/          │
                                        │  alerts.jsonl          │
                                        │  review_queue.jsonl    │
                                        │  whitelist.jsonl       │
                                        │  process_log.jsonl     │
                                        └───────────┬────────────┘
                                                    │ reads / updates
                                                    ▼
                                        ┌────────────────────────┐
                                        │     review_tool.py     │
                                        │  Triage MEDIUM finds:  │
                                        │  whitelist or promote  │
                                        │  to a confirmed threat │
                                        └────────────────────────┘
```

Collection (`monitor.py`), detection logic (`rules.py`), and persistence
(`logger.py`) are kept apart; `main.py` is the only place that orchestrates
them. The whitelist closes the loop: what you mark safe in `review_tool.py` is
read back by the monitor on its next start.

---

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt  # psutil
```

## Running the Monitor

```bash
python3 main.py
```

```
Starting minimal EDR-like process monitor v1.1.0 on Darwin.
Monitoring 20 suspicious patterns every 1.0s. Press Ctrl-C to stop.
```

| Option | Default | Purpose |
| --- | --- | --- |
| `--interval N` | `1` | Seconds between scan cycles |
| `--burst N` | `10` | Rapid scans per cycle, to catch short-lived processes |
| `--burst-sleep N` | `0.05` | Seconds between burst scans |
| `--log-all` | off | Also write every observed process to `process_log.jsonl` |

Polling means a process that lives for a few milliseconds can start and exit
between two scans. `--burst` trades a little CPU for a much better chance of
catching it:

```bash
python3 main.py --burst 10 --burst-sleep 0.05
```

## Review Tool

MEDIUM findings do not interrupt you — they queue up for triage:

```bash
python3 review_tool.py           # Walk pending records
python3 review_tool.py --all     # Include already-reviewed records
python3 review_tool.py --stats   # Summary counts
```

For each record you can mark it **Safe** (appends to `whitelist.jsonl`, so the
monitor stops flagging it), **Threat** (promotes it to `alerts.jsonl`), or skip.

---

## Example Output

A detection at HIGH or above, printed to the console:

```
🚨 [DETECTION - CRITICAL]
   PID: 31425 | Score: 135
   Matches: ['bash -c(60)', 'http://(35)', 'curl(25)', ';(15)']
   Command: bash -c sleep 2; echo 'curl http://example.com'
```

The same finding in `logs/alerts.jsonl`:

```json
{
  "pid": 31425,
  "severity": "CRITICAL",
  "risk_score": 135,
  "matches": ["bash -c(60)", "http://(35)", "curl(25)", ";(15)"],
  "event": {
    "pid": 31425,
    "name": "bash",
    "exe": "/bin/bash",
    "cmdline": "bash -c sleep 2; echo 'curl http://example.com'",
    "create_time": 1773664906.2,
    "username": "user",
    "first_seen": "2026-03-16T18:41:46.919485Z",
    "host": "workstation.local"
  },
  "timestamp": "2026-03-16T18:41:46.919485Z",
  "status": "ALERT"
}
```

### Generating alerts safely

These commands only *echo* strings containing suspicious tokens — nothing is
downloaded or executed. The `sleep` keeps the process alive long enough to be
observed. Run them in a second terminal while the monitor is running.

**Linux / macOS**

```bash
bash -c "sleep 2; echo 'curl http://example.com'"
# CRITICAL, score 135 — bash -c(60), http://(35), curl(25), ;(15)

bash -c "sleep 2; echo 'hello' | sed 's/hello/ok/'"
# HIGH, score 90 — bash -c(60), |(15), ;(15)

bash -c "sleep 2; echo 'python -c \"print(1)\"'"
# CRITICAL, score 125 — bash -c(60), python -c(50), ;(15)
```

**Windows (PowerShell)**

```powershell
powershell -Command "Start-Sleep -Seconds 2; Write-Output 'hello'"
# HIGH, score 85 — powershell(70), ;(15)

powershell -Command "Start-Sleep -Seconds 2; Write-Output '-EncodedCommand'"
# CRITICAL, score 185 — -encodedcommand(100), powershell(70), ;(15)
```

Every score above is asserted in `tests/test_rules.py`.

---

## Risk Scores

**Indicators — high (80-100)**
- Encoded commands (`-enc`, `-encodedcommand`)
- Direct TCP connections (`/dev/tcp`)
- Base64 decoding (`base64 -d`)
- LOLBins (`rundll32`, `mshta`)

**Indicators — medium (50-79)**
- Shell interpreters with inline commands (`bash -c`, `powershell`, `pwsh`)
- Netcat (`nc -`, `netcat`), `regsvr32`, `certutil`, `bitsadmin`
- Script interpreters with inline code (`python -c`, `perl -e`, `ruby -e`)

**Indicators — low (20-49)**
- Network fetch tools (`curl`, `wget`) — usually legitimate, so scored low

**Modifiers (15-45)** — only count alongside an indicator
- `download`, `http://`, `https://`, `&&`, `||`, `|`, `;`

Windows and Unix indicator sets are selected automatically from
`platform.system()`; modifiers apply everywhere.

---

## File Structure

```
main.py            # Entry point, polling loop, severity routing
monitor.py         # Process enumeration via psutil
rules.py           # Patterns, risk scores, matching logic
logger.py          # JSONL read/write
review_tool.py     # Triage CLI for MEDIUM findings
tests/             # unittest suite, no extra dependencies
logs/
├── alerts.jsonl        # HIGH/CRITICAL (>= 70), append-only
├── review_queue.jsonl  # MEDIUM (40-69), rewritten as items are triaged
├── whitelist.jsonl     # Approved patterns, read by the monitor at startup
└── process_log.jsonl   # Raw telemetry, only with --log-all
```

`alerts.jsonl` and `review_queue.jsonl` share one schema:
`{pid, severity, risk_score, matches, event, timestamp, status}`, where `event`
is `{pid, name, exe, cmdline, create_time, username, first_seen, host}`.
Timestamps are UTC ISO8601 with a trailing `Z`.

---

## Testing

```bash
python3 -m unittest discover -s tests -v
```

28 tests, no dependencies beyond the standard library. `test_monitor.py` runs
against a stub `psutil`, so the suite touches no real processes. The suite
asserts the exact scores published in this README — if a rule changes and the
docs are not updated, the tests fail.

---

## Known Limitations

- **Detection is command-line pattern matching only.** No parent/child lineage,
  no file or network telemetry. A malicious binary with an innocuous command
  line is invisible to it.
- **Process tracking is in memory.** The seen set does not survive a restart. It
  is keyed by `(pid, create_time)` so recycled PIDs are correctly treated as new
  processes, and it is pruned every scan so it stays bounded.
- **Polling can miss very short-lived processes**, even with `--burst`.
- **LOW findings are not persisted.** Use `--log-all` if you want everything.
- `whoami`, `uname -a`, and `id` are deliberately not flagged.
- The whitelist is loaded at startup; entries added mid-run apply after a
  restart.

---

## Roadmap

- **Parent/child process lineage** — track ancestry and spawn chains
- **Persistent baselines** — carry seen processes and whitelists across restarts
- **Extended telemetry** — file writes to sensitive paths, outbound connections
- **Configuration file** — YAML/JSON for rules, thresholds, and log paths
- **Packaging** — `pipx` install, systemd/launchd service templates
- **Integrations** — webhook alerts, syslog forwarding

See [CONTRIBUTING.md](CONTRIBUTING.md) for architecture notes and the rules that
govern changes to the detection engine.

## License

MIT — see [LICENSE](LICENSE).

---
---

# 🇹🇷 Türkçe Dokümantasyon

> 🇬🇧 English version is available at the top of this file

# Minimal EDR Benzeri Süreç İzleyici

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-informational?style=for-the-badge&logo=linux&logoColor=white&color=0078D4)
![Version](https://img.shields.io/badge/Sürüm-v1.1.0-brightgreen?style=for-the-badge)
![Tests](https://img.shields.io/badge/Test-28%20ge%C3%A7iyor-success?style=for-the-badge)
![License](https://img.shields.io/badge/Lisans-MIT-yellow?style=for-the-badge)

Küçük bir uç nokta telemetri aracı: yeni başlayan süreçleri izler, komut
satırlarını şüpheli örüntü kural setine karşı puanlar ve bulguları önem düzeyine
göre yönlendirir. Yaklaşık 700 satır Python ve bir test paketi; tek çalışma
zamanı bağımlılığı `psutil`.

Bu bir öğrenme projesi, ürün değil — kernel sürücüsü, ajan altyapısı veya
müdahale yeteneği yok. Uçtan uca uyguladığı şey beni asıl ilgilendiren kısım:
**gürültülü süreç telemetrisini, bakmaya değer az sayıda bulguya dönüştürmek.**

---

## İçindekiler (TR)

- [Tespit Nasıl Çalışıyor](#tespit-nasıl-çalışıyor)
- [False Positive'leri Kesmek](#false-positiveleri-kesmek)
- [Mimari](#mimari)
- [Kurulum](#kurulum)
- [İzleyiciyi Çalıştırma](#i̇zleyiciyi-çalıştırma)
- [İnceleme Aracı](#i̇nceleme-aracı)
- [Örnek Çıktı](#örnek-çıktı)
- [Risk Puanları](#risk-puanları)
- [Dosya Yapısı](#dosya-yapısı)
- [Testler](#testler)
- [Bilinen Sınırlamalar](#bilinen-sınırlamalar)
- [Yol Haritası](#yol-haritası)

---

## Tespit Nasıl Çalışıyor

Her yeni süreç `name`, `exe` ve `cmdline` alanlarıyla eşleştirmeye girer.
Örüntüler iki sınıfa ayrılır:

| Sınıf | Örnekler | Davranış |
| --- | --- | --- |
| **Gösterge (Indicator)** | `bash -c`, `powershell`, `base64 -d`, `/dev/tcp`, `curl` | Tek başına anlamlı. En az biri eşleşmezse hiçbir şey raporlanmaz. |
| **Değiştirici (Modifier)** | `\|`, `;`, `&&`, `\|\|`, `http://`, `https://`, `download` | Yalnızca bir gösterge eşleştikten sonra puana katkı yapar. |

Eşleşen puanlar toplanır ve bir önem düzeyine eşlenir:

```
CRITICAL >= 100    HIGH >= 70    MEDIUM >= 40    LOW < 40
```

Önem düzeyi bulgunun nereye gideceğini belirler:

| Puan | Önem | Hedef |
| --- | --- | --- |
| >= 70 | HIGH / CRITICAL | `logs/alerts.jsonl` + konsola renkli yazdırılır |
| 40-69 | MEDIUM | `logs/review_queue.jsonl`, sessiz — `review_tool.py` ile incelenir |
| < 40 | LOW | Gürültü olarak elenir (`--log-all` ile ham telemetri saklanır) |

İki kural aritmetiği dürüst tutar:

- **Örtüşen örüntüler bir kez sayılır.** `bash -c` içinde `sh -c`,
  `-encodedcommand` içinde `-enc` geçer. Başka bir eşleşmenin alt dizesi olan
  örüntü elenir; böylece tek bir teknik tek kez puanlanır.
- **Eşleşme alfanümerik kenarlarda kelime sınırlıdır.** `curl`,
  `curl http://x` üzerinde tetiklenir ama `/usr/lib/libcurl.dylib` üzerinde
  tetiklenmez; `nc -` netcat'te tetiklenir ama `sync -f` üzerinde tetiklenmez.

## False Positive'leri Kesmek

İlk sürüm shell noktalama işaretlerini tek başına puanlıyordu. Canlı bir macOS
iş istasyonunda bu kural seti **147 tespit kaydetti; bunların 144'ü (%98) tek
bir tarayıcının renderer süreçleriydi** — çünkü bir Chromium feature flag'i
içinde boru karakteri geçiyor:

```
--origin-trial-disabled-features=CanvasTextNg|WebAssemblyCustomDescriptors
```

Bir `|` hiçbir şeyin kanıtı değildir. *Bir shell işin içindeyse* bir shell
operatörüdür — gösterge/değiştirici ayrımının kodladığı şey tam olarak bu. Alt
dize eleme ve kelime sınırlarıyla birlikte, o 144 uyarının tamamı artık sıfır
puan alıyor; gerçek test vakaları ise aynı veya daha yüksek puanda kalıyor.

Bu vakalar `tests/test_rules.py` içinde sabitlendi, gürültü geri gelemez.

---

## Mimari

```
┌──────────────────────────────────────────────────────────────────┐
│                            main.py                               │
│  Giriş noktası. CLI argümanlarını ayrıştırır, döngüyü yönetir,   │
│  beyaz listeyi uygular, kural motorunu çağırır, önem düzeyine    │
│  göre yönlendirir, uyarıları yazdırır.                           │
└───────┬───────────────────┬──────────────────────┬───────────────┘
        │ scan()            │ find_suspicious()    │ write_jsonl()
        ▼                   ▼                      ▼
┌────────────────┐  ┌──────────────────┐  ┌──────────────────────┐
│   monitor.py   │  │     rules.py     │  │      logger.py       │
│ psutil ile     │  │ Örüntüler, risk  │  │ JSONL okur ve yazar. │
│ süreçleri      │  │ puanları,        │  │ Log dosyalarına      │
│ listeler.      │  │ eşleştirme ve    │  │ dokunan tek modül.   │
│ Yalnızca       │  │ önem düzeyi.     │  │                      │
│ toplama.       │  │ Saf mantık.      │  │                      │
└────────────────┘  └──────────────────┘  └──────────┬───────────┘
                                                     │
                                                     ▼
                                        ┌────────────────────────┐
                                        │         logs/          │
                                        │  alerts.jsonl          │
                                        │  review_queue.jsonl    │
                                        │  whitelist.jsonl       │
                                        │  process_log.jsonl     │
                                        └───────────┬────────────┘
                                                    │ okur / günceller
                                                    ▼
                                        ┌────────────────────────┐
                                        │     review_tool.py     │
                                        │  MEDIUM bulguları      │
                                        │  incele: beyaz listeye │
                                        │  al veya tehdide yükselt│
                                        └────────────────────────┘
```

Toplama (`monitor.py`), tespit mantığı (`rules.py`) ve kalıcılık (`logger.py`)
ayrı tutulur; bunları orkestre eden tek yer `main.py`'dir. Beyaz liste döngüyü
kapatır: `review_tool.py` içinde güvenli işaretlediğin şey, izleyici bir sonraki
başlangıcında geri okunur.

---

## Kurulum

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt  # psutil
```

## İzleyiciyi Çalıştırma

```bash
python3 main.py
```

```
Starting minimal EDR-like process monitor v1.1.0 on Darwin.
Monitoring 20 suspicious patterns every 1.0s. Press Ctrl-C to stop.
```

| Seçenek | Varsayılan | Amaç |
| --- | --- | --- |
| `--interval N` | `1` | Tarama döngüleri arası saniye |
| `--burst N` | `10` | Döngü başına hızlı tarama sayısı (kısa ömürlü süreçler için) |
| `--burst-sleep N` | `0.05` | Burst taramaları arası saniye |
| `--log-all` | kapalı | Gözlenen her süreci `process_log.jsonl`'a da yazar |

Yoklama (polling) yöntemi, birkaç milisaniye yaşayan bir sürecin iki tarama
arasında başlayıp bitmesi anlamına gelir. `--burst` biraz CPU karşılığında onu
yakalama şansını belirgin şekilde artırır:

```bash
python3 main.py --burst 10 --burst-sleep 0.05
```

## İnceleme Aracı

MEDIUM bulgular seni bölmez — inceleme için kuyruğa girer:

```bash
python3 review_tool.py           # Bekleyen kayıtları gez
python3 review_tool.py --all     # İncelenmiş kayıtları da göster
python3 review_tool.py --stats   # Özet sayılar
```

Her kayıt için **Safe** (`whitelist.jsonl`'a eklenir, izleyici artık işaretlemez),
**Threat** (`alerts.jsonl`'a yükseltilir) veya atla seçeneklerini kullanabilirsin.

---

## Örnek Çıktı

HIGH ve üzeri bir tespit, konsola yazdırılır:

```
🚨 [DETECTION - CRITICAL]
   PID: 31425 | Score: 135
   Matches: ['bash -c(60)', 'http://(35)', 'curl(25)', ';(15)']
   Command: bash -c sleep 2; echo 'curl http://example.com'
```

### Güvenli şekilde uyarı üretme

Aşağıdaki komutlar şüpheli belirteçler içeren dizeleri yalnızca *ekrana basar* —
hiçbir şey indirilmez veya çalıştırılmaz. `sleep`, sürecin gözlenebilecek kadar
yaşamasını sağlar. İzleyici çalışırken ikinci bir terminalde çalıştır.

**Linux / macOS**

```bash
bash -c "sleep 2; echo 'curl http://example.com'"
# CRITICAL, puan 135 — bash -c(60), http://(35), curl(25), ;(15)

bash -c "sleep 2; echo 'hello' | sed 's/hello/ok/'"
# HIGH, puan 90 — bash -c(60), |(15), ;(15)

bash -c "sleep 2; echo 'python -c \"print(1)\"'"
# CRITICAL, puan 125 — bash -c(60), python -c(50), ;(15)
```

**Windows (PowerShell)**

```powershell
powershell -Command "Start-Sleep -Seconds 2; Write-Output 'hello'"
# HIGH, puan 85 — powershell(70), ;(15)

powershell -Command "Start-Sleep -Seconds 2; Write-Output '-EncodedCommand'"
# CRITICAL, puan 185 — -encodedcommand(100), powershell(70), ;(15)
```

Yukarıdaki her puan `tests/test_rules.py` içinde doğrulanıyor.

---

## Risk Puanları

**Göstergeler — yüksek (80-100)**
- Kodlanmış komutlar (`-enc`, `-encodedcommand`)
- Doğrudan TCP bağlantıları (`/dev/tcp`)
- Base64 çözme (`base64 -d`)
- LOLBin'ler (`rundll32`, `mshta`)

**Göstergeler — orta (50-79)**
- Satır içi komutlu shell yorumlayıcıları (`bash -c`, `powershell`, `pwsh`)
- Netcat (`nc -`, `netcat`), `regsvr32`, `certutil`, `bitsadmin`
- Satır içi kodlu script yorumlayıcıları (`python -c`, `perl -e`, `ruby -e`)

**Göstergeler — düşük (20-49)**
- Ağ indirme araçları (`curl`, `wget`) — genellikle meşru olduğu için düşük

**Değiştiriciler (15-45)** — yalnızca bir göstergeyle birlikte sayılır
- `download`, `http://`, `https://`, `&&`, `||`, `|`, `;`

Windows ve Unix gösterge setleri `platform.system()` ile otomatik seçilir;
değiştiriciler her platformda geçerlidir.

---

## Dosya Yapısı

```
main.py            # Giriş noktası, döngü, önem düzeyi yönlendirmesi
monitor.py         # psutil ile süreç listeleme
rules.py           # Örüntüler, risk puanları, eşleştirme mantığı
logger.py          # JSONL okuma/yazma
review_tool.py     # MEDIUM bulgular için inceleme CLI'ı
tests/             # unittest paketi, ek bağımlılık yok
logs/
├── alerts.jsonl        # HIGH/CRITICAL (>= 70), yalnızca ekleme
├── review_queue.jsonl  # MEDIUM (40-69), incelendikçe yeniden yazılır
├── whitelist.jsonl     # Onaylanmış örüntüler, başlangıçta okunur
└── process_log.jsonl   # Ham telemetri, yalnızca --log-all ile
```

`alerts.jsonl` ve `review_queue.jsonl` aynı şemayı paylaşır:
`{pid, severity, risk_score, matches, event, timestamp, status}`; `event` ise
`{pid, name, exe, cmdline, create_time, username, first_seen, host}`.
Zaman damgaları `Z` sonekli UTC ISO8601'dir.

---

## Testler

```bash
python3 -m unittest discover -s tests -v
```

28 test, standart kütüphane dışında bağımlılık yok. `test_monitor.py` sahte bir
`psutil` ile çalışır, yani paket gerçek süreçlere dokunmaz. Paket bu README'de
yayınlanan puanları birebir doğrular — bir kural değişip doküman güncellenmezse
testler kırılır.

---

## Bilinen Sınırlamalar

- **Tespit yalnızca komut satırı örüntü eşleştirmesidir.** Ebeveyn/çocuk süreç
  soyağacı, dosya veya ağ telemetrisi yok. Masum bir komut satırına sahip
  kötücül bir ikili dosya görünmez kalır.
- **Süreç takibi bellektedir.** Görülen küme yeniden başlatmayı atlatmaz.
  `(pid, create_time)` ile anahtarlanır; böylece geri dönüştürülen PID'ler doğru
  şekilde yeni süreç sayılır ve her taramada budanarak sınırlı kalır.
- **Yoklama, çok kısa ömürlü süreçleri kaçırabilir** (`--burst` ile bile).
- **LOW bulgular saklanmaz.** Her şeyi istiyorsan `--log-all` kullan.
- `whoami`, `uname -a` ve `id` bilinçli olarak işaretlenmez.
- Beyaz liste başlangıçta yüklenir; çalışma sırasında eklenenler yeniden
  başlatmadan sonra geçerli olur.

---

## Yol Haritası

- **Ebeveyn/çocuk süreç soyağacı** — süreç atalarını ve zincirlerini takip etme
- **Kalıcı temel çizgiler** — görülen süreçleri ve beyaz listeyi yeniden
  başlatmalar arasında taşıma
- **Genişletilmiş telemetri** — hassas yollara dosya yazımı, giden bağlantılar
- **Yapılandırma dosyası** — kurallar, eşikler ve log yolları için YAML/JSON
- **Paketleme** — `pipx` kurulumu, systemd/launchd servis şablonları
- **Entegrasyonlar** — webhook uyarıları, syslog yönlendirme

Mimari notlar ve tespit motorunda değişiklik yaparken uyulması gereken kurallar
için [CONTRIBUTING.md](CONTRIBUTING.md) dosyasına bakın.

## Lisans

MIT — bkz. [LICENSE](LICENSE).
