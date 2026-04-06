# ⚡ SMAF ANAV — Static Malware Analysis Automation Framework

```
 ███████╗███╗   ███╗ █████╗ ███████╗     █████╗ ███╗   ██╗ █████╗ ██╗   ██╗
 ██╔════╝████╗ ████║██╔══██╗██╔════╝    ██╔══██╗████╗  ██║██╔══██╗██║   ██║
 ███████╗██╔████╔██║███████║█████╗      ███████║██╔██╗ ██║███████║██║   ██║
 ╚════██║██║╚██╔╝██║██╔══██║██╔══╝      ██╔══██║██║╚██╗██║██╔══██║╚██╗ ██╔╝
 ███████║██║ ╚═╝ ██║██║  ██║██║         ██║  ██║██║ ╚████║██║  ██║ ╚████╔╝ 
 ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝         ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝  ╚═══╝  v1.0
```

> **Static Malware Analysis Automation Framework** — Automate file-type detection, string extraction, deobfuscation, and malware family identification from PE executables using industry-grade tools.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?style=flat-square&logo=windows)
![Tools](https://img.shields.io/badge/Tools-TrID%20%7C%20strings.exe%20%7C%20FLOSS-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Tool Chain](#-tool-chain)
- [Installation](#-installation)
- [Usage](#-usage)
- [Output Example](#-output-example)
- [Report Formats](#-report-formats)
- [Malware Families Detected](#-malware-families-detected)
- [Project Structure](#-project-structure)
- [Disclaimer](#-disclaimer)

---

## 🔍 Overview

**SMAF ANAV** is a Python-based static malware analysis automation script designed for security researchers and malware analysts. It takes one or more PE executable samples and runs them through a multi-tool pipeline to extract actionable threat intelligence — all without executing the malware.

The framework performs:
- **File type identification** via TrID signature matching
- **String extraction** via strings.exe (ASCII + Unicode)
- **Deobfuscated string recovery** via FLOSS (stack & decoded strings)
- **Malware family classification** using a built-in IOC signature database

Results are exported as both a **human-readable text report** and a **styled HTML report**.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔎 File Type Detection | Uses TrID to identify file type with confidence percentages |
| 📝 String Extraction | Extracts all ASCII/Unicode strings (min length 4) via strings.exe |
| 🔓 FLOSS Deobfuscation | Recovers stack strings and decoded strings hidden from static analysis |
| 🧬 Malware Family ID | Matches IOC signatures against known malware families |
| 🌐 URL/Domain Extraction | Automatically flags embedded URLs and domains |
| ⚠️ Suspicious Keyword Detection | Highlights dangerous API calls and keywords |
| 📊 Dual Report Output | Generates both `.txt` and `.html` analysis reports |
| 🛫 Pre-flight Checks | Validates all tools and sample files before analysis begins |

---

## 🛠 Tool Chain

SMAF ANAV relies on three external tools that must be present in the same directory:

| Tool | Purpose | Download |
|---|---|---|
| **TrID** | File type identification via binary signatures | [mark0.net](https://mark0.net/soft-trid-e.html) |
| **strings.exe** | String extraction from PE files | [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/strings) |
| **FLOSS** | Deobfuscated string extraction | [GitHub - mandiant/flare-floss](https://github.com/mandiant/flare-floss) |

---

## 💻 Installation

### Prerequisites

- Windows OS
- Python 3.8 or higher

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/smaf-anav.git
cd smaf-anav

# 2. Place required tools in the project folder
#    - trid.exe + triddefs.trd
#    - strings.exe / strings64.exe / strings64a.exe
#    - floss.exe

# 3. Place your malware sample(s) in the same folder
#    (use .malz extension or rename safely)

# 4. Run the analyzer
python analyzer.py <sample.exe>
```

---

## 🚀 Usage

```bash
# Analyze a single sample
python analyzer.py malware_sample.exe

# The script will automatically:
# [1] Check all tools are present
# [2] Validate the sample file
# [3] Run TrID → strings.exe → FLOSS
# [4] Match against malware signature database
# [5] Export reports
```

### Example Run

```
PRE-FLIGHT: TOOL AVAILABILITY CHECK
  ✔ trid      → trid
  ✔ strings   → strings
  ✔ floss     → floss

PRE-FLIGHT: SAMPLE VALIDATION
  ✔ Found: TotalAware2.exe (14.50 KB)
  ℹ Total samples queued for analysis: 1

ANALYSING: TotalAware2.exe
  ℹ Running TrID ...
  ℹ Running strings.exe ...
  ℹ Running FLOSS (this may take a moment) ...
  ℹ Matching against malware signature database ...
```

---

## 📄 Output Example

### File Metadata
```
MD5    : 5a5d48d3796d7998bc805ee9a3725eeb
SHA1   : d64d02073a102afb236631c7301084bbac882faa
SHA256 : 32a4c49f2db185ebab27b668eb5e3cba57bb9461c785dc4432a2cd054640f1bd
```

### File Type Detection (TrID)
```
69.1%  (.EXE)  Generic CIL Executable (.NET, Mono, etc.)
 9.9%  (.EXE)  Win64 Executable (generic)
```

### Suspicious Keywords Detected
```
hookedKeyboardCallbackAsync
hookedLowLevelKeyboardProc
hookId
midHook
SetHook
UnhookWindowsHookEx
CallNextHookEx
```

### Malware Family Identification
```
#1  TotalAV_Rogue       → Rogue Antivirus / Scareware (TotalAV-style)   [LOW]
#2  Generic_Keylogger   → Generic Keylogger Behavior                    [MEDIUM]
#3  AgentTesla          → Agent Tesla Info-Stealer / Keylogger           [LOW]
```

---

## 📊 Report Formats

After analysis, two report files are saved automatically:

| Format | Filename | Description |
|---|---|---|
| 📝 Text | `malware_analysis_YYYYMMDD_HHMMSS.txt` | Full plaintext report |
| 🌐 HTML | `malware_analysis_YYYYMMDD_HHMMSS.html` | Styled browser-viewable report |

---

## 🧬 Malware Families Detected

The built-in signature database currently covers:

- `TotalAV_Rogue` — Rogue Antivirus / Scareware
- `Generic_Keylogger` — Keyboard hook-based keyloggers
- `AgentTesla` — Info-stealer / keylogger
- *(More signatures can be added to the database easily)*

---

## 📁 Project Structure

```
smaf-anav/
│
├── analyzer.py              # Main analysis script
├── README.md                # This file
│
├── tools/                   # External tool binaries (not included)
│   ├── trid.exe
│   ├── triddefs.trd
│   ├── strings.exe
│   ├── strings64.exe
│   ├── strings64a.exe
│   └── floss.exe
│
├── samples/                 # Place malware samples here (.malz recommended)
│   └── Rams1.exe.malz
│
└── reports/                 # Auto-generated analysis reports
    ├── malware_analysis_*.txt
    └── malware_analysis_*.html
```

---

## ⚠️ Disclaimer

> This tool is intended **strictly for educational and research purposes** in controlled, isolated environments (e.g., sandboxed VMs with no network access).
>
> **Do NOT run malware samples on production or personal machines.**  
> The author takes no responsibility for misuse of this tool.  
> Always follow responsible disclosure and applicable laws in your jurisdiction.

---

## 👤 Author

**Baani** — Malware Analyst / Security Researcher  
📍 Pakistan

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

*Built with ❤️ for the malware analysis community*
