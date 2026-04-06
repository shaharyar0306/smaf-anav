#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          STATIC MALWARE ANALYSIS AUTOMATION FRAMEWORK v1.0                 ║
║          Analyst Tools: TrID | strings.exe | FLOSS                         ║
║          Targets: Any .exe / sample files supplied at runtime              ║
╚══════════════════════════════════════════════════════════════════════════════╝

Author      : Malware Analysis Team
Description : Automated static analysis pipeline for malware samples.
              Performs file-type detection, string extraction, and malware
              family identification using TrID, strings.exe, and FLOSS.
Usage       : python static_malware_analysis.py sample1.exe sample2.exe ...
              python static_malware_analysis.py --dir C:\\Samples
              python static_malware_analysis.py --glob "C:\\Samples\\*.exe"
"""

import os
import sys
import subprocess
import hashlib
import json
import re
import argparse
import shutil
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

# No default samples — user must supply files via CLI, --dir, or --glob

# CLI tool paths — override via --trid / --strings / --floss arguments
# or set environment variables: TRID_PATH, STRINGS_PATH, FLOSS_PATH
TOOL_DEFAULTS = {
    "trid":    os.environ.get("TRID_PATH",    "trid"),
    "strings": os.environ.get("STRINGS_PATH", "strings"),
    "floss":   os.environ.get("FLOSS_PATH",   "floss"),
}

# Minimum string length for extraction
MIN_STRING_LENGTH = 4

# ─────────────────────────────────────────────────────────────────────────────
#  MALWARE FAMILY SIGNATURE DATABASE
#  Each entry: { "family": str, "description": str, "indicators": [str] }
#  Indicators are regex patterns matched against extracted strings.
# ─────────────────────────────────────────────────────────────────────────────

MALWARE_SIGNATURES = [
    # ── Ransomware ────────────────────────────────────────────────────────────
    {
        "family": "WannaCry",
        "description": "WannaCry / WannaCrypt Ransomware",
        "indicators": [
            r"WannaCry", r"WNCRY", r"wncrypt", r"tasksche\.exe",
            r"mssecsvc", r"icacls.*\/grant", r"Please Read Me",
            r"bitcoin", r"tor2web", r"\.onion",
        ],
    },
    {
        "family": "Locky",
        "description": "Locky Ransomware",
        "indicators": [
            r"locky", r"\.locky", r"_Locky_recover", r"_HELP_instructions",
            r"RSA-2048", r"decrypt.*files",
        ],
    },
    {
        "family": "REvil_Sodinokibi",
        "description": "REvil / Sodinokibi Ransomware",
        "indicators": [
            r"sodinokibi", r"revil", r"readme.*txt", r"random_ext",
            r"expand.*32752", r"-noni -ep bypass",
        ],
    },
    {
        "family": "Ryuk",
        "description": "Ryuk Ransomware",
        "indicators": [
            r"RyukReadMe", r"RYUK", r"Hermes", r"Net Send",
            r"icacls.*\/reset", r"shadow.*copy.*delete",
        ],
    },
    {
        "family": "GandCrab",
        "description": "GandCrab Ransomware",
        "indicators": [
            r"GandCrab", r"GDCB-DECRYPT", r"gandcrab",
            r"\.GDCB", r"\.GRAB", r"\.KRAB",
        ],
    },
    {
        "family": "LockBit",
        "description": "LockBit Ransomware",
        "indicators": [
            r"LockBit", r"lockbit", r"Restore-My-Files",
            r"\.lockbit", r"abcde123",
        ],
    },
    {
        "family": "Conti",
        "description": "Conti Ransomware",
        "indicators": [
            r"conti", r"README_CONTI", r"CONTI_LOG",
            r"contirecovery", r"\.CONTI",
        ],
    },
    {
        "family": "Maze",
        "description": "Maze Ransomware",
        "indicators": [
            r"MAZE", r"maze", r"DECRYPT-FILES", r"\.maze",
            r"send.*email.*files",
        ],
    },
    {
        "family": "Dharma_CrySiS",
        "description": "Dharma / CrySiS Ransomware",
        "indicators": [
            r"CrySiS", r"dharma", r"\.dharma", r"\.wallet",
            r"\.adobe", r"info\.hta", r"FILES ENCRYPTED",
        ],
    },
    {
        "family": "BlackCat_ALPHV",
        "description": "BlackCat / ALPHV Ransomware",
        "indicators": [
            r"ALPHV", r"blackcat", r"RECOVER.*FILES",
            r"\.alphv", r"noname",
        ],
    },

    # ── Remote Access Trojans (RATs) ──────────────────────────────────────────
    {
        "family": "njRAT",
        "description": "njRAT / Bladabindi Remote Access Trojan",
        "indicators": [
            r"njRAT", r"bladabindi", r"njq8", r"HdR",
            r"lol\.exe", r"nj-q8", r"Microsoft\.Win32\.Registry",
            r"cmd\.exe.*\/k", r"netsh.*firewall",
        ],
    },
    {
        "family": "AsyncRAT",
        "description": "AsyncRAT Remote Access Trojan",
        "indicators": [
            r"AsyncRAT", r"async.*client", r"Async.*Server",
            r"pastebin.*raw", r"anti.*sandbox", r"SendPlugin",
        ],
    },
    {
        "family": "QuasarRAT",
        "description": "Quasar RAT",
        "indicators": [
            r"QuasarRAT", r"Quasar", r"xRAT",
            r"Client\.exe", r"Plugins", r"KeyLogger",
        ],
    },
    {
        "family": "DarkComet",
        "description": "DarkComet RAT",
        "indicators": [
            r"DarkComet", r"DARKCOMET", r"DC_MUTEX",
            r"DICR", r"XTREME", r"remcos",
        ],
    },
    {
        "family": "Remcos",
        "description": "Remcos RAT",
        "indicators": [
            r"Remcos", r"remcos", r"Breaking-Security",
            r"REMCOS_MUTEX", r"remc", r"Licenced to",
        ],
    },
    {
        "family": "NanoCore",
        "description": "NanoCore RAT",
        "indicators": [
            r"NanoCore", r"nanocore", r"CoreClientPlugin",
            r"SurveillancePlugin", r"nano.*client",
        ],
    },

    # ── Info-Stealers ─────────────────────────────────────────────────────────
    {
        "family": "AgentTesla",
        "description": "Agent Tesla Info-Stealer / Keylogger",
        "indicators": [
            r"AgentTesla", r"agent.*tesla", r"SmtpClient",
            r"GetAsyncKeyState", r"clipboard.*monitor",
            r"imap\..*\.com", r"ftp.*upload",
            r"\.GetKeyboardState", r"TotalAware",
        ],
    },
    {
        "family": "FormBook",
        "description": "FormBook / xLoader Info-Stealer",
        "indicators": [
            r"FormBook", r"formbook", r"xloader",
            r"GrabBrowser", r"hook.*ntdll",
        ],
    },
    {
        "family": "RedLine",
        "description": "RedLine Stealer",
        "indicators": [
            r"RedLine", r"redline", r"RecordBreaker",
            r"SteamID", r"GrabBrowsers", r"Telegram.*token",
        ],
    },
    {
        "family": "Vidar",
        "description": "Vidar Stealer",
        "indicators": [
            r"vidar", r"Vidar", r"grabber", r"steal.*wallet",
            r"steam.*friends", r"ftp.*upload.*zip",
        ],
    },
    {
        "family": "AZORult",
        "description": "AZORult Info-Stealer",
        "indicators": [
            r"azorult", r"AZORult", r"prntScr",
            r"GrabHistory", r"Browsers.*Password",
        ],
    },
    {
        "family": "Raccoon",
        "description": "Raccoon Stealer",
        "indicators": [
            r"raccoon", r"Raccoon", r"machineId",
            r"steal.*telegram", r"BotId",
        ],
    },

    # ── Banking Trojans ───────────────────────────────────────────────────────
    {
        "family": "Emotet",
        "description": "Emotet Banking Trojan / Loader",
        "indicators": [
            r"emotet", r"Emotet", r"heodo", r"banking.*trojan",
            r"powershell.*encoded", r"regsvr32.*scrobj",
        ],
    },
    {
        "family": "TrickBot",
        "description": "TrickBot Banking Trojan",
        "indicators": [
            r"trickbot", r"TrickBot", r"Trick",
            r"moduleconfig", r"group_tag", r"systeminfo",
        ],
    },
    {
        "family": "Zeus_Zbot",
        "description": "Zeus / Zbot Banking Trojan",
        "indicators": [
            r"zeus", r"zbot", r"KINS", r"GameOver",
            r"cfg_path", r"bot_id", r"botnet",
        ],
    },
    {
        "family": "Dridex",
        "description": "Dridex Banking Trojan",
            "indicators": [
            r"dridex", r"Dridex", r"botconf",
            r"inject.*browser", r"MemoryModule",
        ],
    },

    # ── Worms & Propagators ───────────────────────────────────────────────────
    {
        "family": "Conficker",
        "description": "Conficker / Downadup Worm",
        "indicators": [
            r"conficker", r"downadup", r"MS08-067",
            r"NetpwPathCanonicalize", r"svchost.*netsvcs",
        ],
    },

    # ── Downloaders & Loaders ─────────────────────────────────────────────────
    {
        "family": "GuLoader",
        "description": "GuLoader / CloudEyE Downloader",
        "indicators": [
            r"GuLoader", r"guloader", r"CloudEyE",
            r"VirtualAlloc.*shellcode", r"NtAllocateVirtualMemory",
        ],
    },
    {
        "family": "SmokeLoader",
        "description": "SmokeLoader Malware Loader",
        "indicators": [
            r"SmokeLoader", r"smoke.*loader", r"Dofoil",
            r"inject.*explorer", r"hollow.*process",
        ],
    },

    # ── Adware / PUPs ─────────────────────────────────────────────────────────
    {
        "family": "TotalAV_Rogue",
        "description": "Rogue Antivirus / Scareware (TotalAV-style)",
        "indicators": [
            r"TotalAV", r"TotalAware", r"total.*aware",
            r"Your PC is infected", r"virus.*detected",
            r"scan.*now", r"purchase.*license", r"activate.*protection",
            r"threats.*found", r"performance.*issues",
        ],
    },
    {
        "family": "Generic_Adware",
        "description": "Generic Adware / PUP",
        "indicators": [
            r"adware", r"PUP", r"toolbar",
            r"browser.*hijack", r"search.*redirect",
            r"coupon", r"deal.*offer",
        ],
    },

    # ── Generic Suspicious Behaviors ─────────────────────────────────────────
    {
        "family": "Generic_Keylogger",
        "description": "Generic Keylogger Behavior",
        "indicators": [
            r"GetAsyncKeyState", r"SetWindowsHookEx",
            r"WH_KEYBOARD", r"keylog", r"keystroke",
        ],
    },
    {
        "family": "Generic_Dropper",
        "description": "Generic Dropper / Injector",
        "indicators": [
            r"VirtualAllocEx", r"WriteProcessMemory",
            r"CreateRemoteThread", r"NtUnmapViewOfSection",
            r"hollow.*process", r"shellcode",
        ],
    },
    {
        "family": "Generic_NetworkC2",
        "description": "Generic C2 / Beaconing Behavior",
        "indicators": [
            r"InternetOpenUrl", r"HttpSendRequest",
            r"WinInet", r"cmd\.exe.*\/c", r"powershell.*bypass",
            r"\.onion", r"pastebin\.com", r"raw\.githubusercontent",
        ],
    },
]

# ─────────────────────────────────────────────────────────────────────────────
#  COLOUR / FORMATTING HELPERS (ANSI)
# ─────────────────────────────────────────────────────────────────────────────

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_RED  = "\033[41m"
    BG_DARK = "\033[40m"

def banner():
    print(f"""
{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════════════════╗
║   ███████╗███╗   ███╗ █████╗     █████╗ ███╗   ██╗ █████╗ ██╗   ██╗  ║
║   ██╔════╝████╗ ████║██╔══██╗   ██╔══██╗████╗  ██║██╔══██╗██║   ██║  ║
║   ███████╗██╔████╔██║███████║   ███████║██╔██╗ ██║███████║██║   ██║  ║
║   ╚════██║██║╚██╔╝██║██╔══██║   ██╔══██║██║╚██╗██║██╔══██║╚██╗ ██╔╝  ║
║   ███████║██║ ╚═╝ ██║██║  ██║   ██║  ██║██║ ╚████║██║  ██║ ╚████╔╝   ║
║   ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝  ╚═══╝   ║
╠══════════════════════════════════════════════════════════════════════════╣
║       Static Malware Analysis Automation Framework  v1.0               ║
║       Tools: TrID  |  strings.exe  |  FLOSS                            ║
╚══════════════════════════════════════════════════════════════════════════╝
{C.RESET}""")

def section(title: str):
    width = 72
    print(f"\n{C.BLUE}{C.BOLD}{'─' * width}")
    print(f"  {title}")
    print(f"{'─' * width}{C.RESET}")

def ok(msg):    print(f"  {C.GREEN}[✔]{C.RESET} {msg}")
def warn(msg):  print(f"  {C.YELLOW}[!]{C.RESET} {msg}")
def err(msg):   print(f"  {C.RED}[✘]{C.RESET} {msg}")
def info(msg):  print(f"  {C.CYAN}[i]{C.RESET} {msg}")
def detail(msg):print(f"      {C.DIM}{msg}{C.RESET}")

# ─────────────────────────────────────────────────────────────────────────────
#  UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def compute_hashes(filepath: str) -> dict:
    """Compute MD5, SHA1, SHA256 of a file."""
    hashes = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                for h in hashes.values():
                    h.update(chunk)
        return {k: v.hexdigest() for k, v in hashes.items()}
    except Exception as e:
        return {"error": str(e)}

def file_size(filepath: str) -> str:
    """Return human-readable file size."""
    try:
        size = os.path.getsize(filepath)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"
    except Exception:
        return "Unknown"

def run_tool(cmd: list, timeout: int = 120) -> tuple[str, str, int]:
    """Run an external CLI tool and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        return "", f"Tool not found: {cmd[0]}", -1
    except subprocess.TimeoutExpired:
        return "", f"Timeout after {timeout}s", -2
    except Exception as e:
        return "", str(e), -3

def tool_available(tool_path: str) -> bool:
    return shutil.which(tool_path) is not None or os.path.isfile(tool_path)

# ─────────────────────────────────────────────────────────────────────────────
#  ANALYSIS MODULES
# ─────────────────────────────────────────────────────────────────────────────

def detect_filetype(filepath: str, trid_path: str) -> dict:
    """
    Run TrID against the sample and parse results.
    Returns: { "raw": str, "detections": [ {"pct": float, "type": str} ] }
    """
    result = {"raw": "", "detections": [], "error": None}

    if not tool_available(trid_path):
        result["error"] = f"TrID not found at '{trid_path}'. Set --trid or TRID_PATH."
        return result

    stdout, stderr, rc = run_tool([trid_path, "-v", filepath])

    if rc < 0:
        result["error"] = stderr
        return result

    result["raw"] = stdout

    # Parse lines like: "  50.0% (.EXE) Win32 Executable MS Visual C++ (generic) (31038/45)"
    pattern = re.compile(r"(\d+\.\d+)%\s+\(([^)]+)\)\s+(.+)")
    for line in stdout.splitlines():
        m = pattern.search(line)
        if m:
            result["detections"].append({
                "pct": float(m.group(1)),
                "ext": m.group(2).strip(),
                "type": m.group(3).strip(),
            })

    return result


def extract_strings(filepath: str, strings_path: str, min_len: int = MIN_STRING_LENGTH) -> dict:
    """
    Run strings.exe against the sample.
    Returns: { "raw": str, "strings": [str], "count": int, "error": str|None }
    """
    result = {"raw": "", "strings": [], "count": 0, "error": None}

    if not tool_available(strings_path):
        result["error"] = f"strings not found at '{strings_path}'. Set --strings or STRINGS_PATH."
        return result

    # strings.exe (Sysinternals) or GNU strings
    # -n <len> for minimum length; -accepteula for Sysinternals
    cmd = [strings_path, "-n", str(min_len), "-accepteula", filepath]
    stdout, stderr, rc = run_tool(cmd, timeout=60)

    if rc < 0:
        # Retry without -accepteula (GNU strings)
        cmd = [strings_path, "-n", str(min_len), filepath]
        stdout, stderr, rc = run_tool(cmd, timeout=60)

    if rc < 0:
        result["error"] = stderr
        return result

    result["raw"] = stdout
    result["strings"] = [s for s in stdout.splitlines() if s.strip()]
    result["count"] = len(result["strings"])
    return result


def extract_floss_strings(filepath: str, floss_path: str) -> dict:
    """
    Run FLOSS (FireEye/Mandiant Labs) against the sample.
    FLOSS deobfuscates encoded / stack strings.
    Returns: { "raw": str, "strings": [str], "count": int, "error": str|None }
    """
    result = {"raw": "", "strings": [], "count": 0, "error": None}

    if not tool_available(floss_path):
        result["error"] = f"FLOSS not found at '{floss_path}'. Set --floss or FLOSS_PATH."
        return result

    stdout, stderr, rc = run_tool([floss_path, "--no-progress", filepath], timeout=300)

    if rc < 0:
        result["error"] = stderr
        return result

    result["raw"] = stdout
    result["strings"] = [s for s in stdout.splitlines() if s.strip()]
    result["count"] = len(result["strings"])
    return result


def classify_strings(string_list: list) -> dict:
    """
    Categorise extracted strings into meaningful groups.
    Returns a dict of category → [matched strings].
    """
    categories = {
        "URLs / Domains":           r"https?://|ftp://|\.onion|(?:[a-zA-Z0-9\-]+\.){2,}[a-zA-Z]{2,}",
        "IP Addresses":             r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "Registry Keys":            r"(?:HKEY_|HKLM|HKCU|HKU|HKCR|SOFTWARE\\|SYSTEM\\)",
        "Windows API Calls":        r"(?:VirtualAlloc|CreateProcess|OpenProcess|WriteProcessMemory|"
                                    r"CreateRemoteThread|SetWindowsHookEx|RegSetValue|"
                                    r"InternetOpen|HttpSendRequest|WinExec|ShellExecute|"
                                    r"NtAllocateVirtualMemory|NtWriteVirtualMemory)",
        "File Paths":               r"[A-Za-z]:\\|%[A-Z]+%|\\\\[A-Za-z]",
        "Email Addresses":          r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "Base64 Encoded Data":      r"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
        "PowerShell / CMD Cmds":    r"(?i)powershell|cmd\.exe|\/c\s|\/k\s|bypass|downloadstring|"
                                    r"iex\s|invoke-expression|EncodedCommand",
        "Cryptographic Indicators": r"AES|RSA|SHA|MD5|crypt|encrypt|decrypt|ransom|bitcoin|wallet",
        "Suspicious Keywords":      r"(?i)keylog|inject|hook|shellcode|payload|dropper|"
                                    r"backdoor|rat\b|stealer|botnet|c2|c&c|exfil",
        "SMTP / Mail":              r"(?i)smtp|imap|pop3|mail\.send|mailmessage|smtpclient",
        "Mutex / Sync Objects":     r"(?i)mutex|CreateMutex|OpenMutex|semaphore",
        "Debug / Anti-Analysis":    r"(?i)IsDebuggerPresent|CheckRemoteDebuggerPresent|"
                                    r"NtQueryInformationProcess|sandbox|vmware|virtualbox|vbox",
    }

    categorised = defaultdict(list)
    for s in string_list:
        for cat, pattern in categories.items():
            if re.search(pattern, s):
                categorised[cat].append(s)
                break  # assign to first matching category only

    return dict(categorised)


def identify_malware_family(all_strings: list) -> list:
    """
    Match extracted strings against the signature database.
    Returns list of matched families sorted by match-count descending.
    """
    combined = "\n".join(all_strings)
    matches = []

    for sig in MALWARE_SIGNATURES:
        hit_patterns = []
        for pattern in sig["indicators"]:
            if re.search(pattern, combined, re.IGNORECASE):
                hit_patterns.append(pattern)
        if hit_patterns:
            matches.append({
                "family":      sig["family"],
                "description": sig["description"],
                "hits":        len(hit_patterns),
                "patterns":    hit_patterns,
                "confidence":  _confidence(len(hit_patterns), len(sig["indicators"])),
            })

    matches.sort(key=lambda x: x["hits"], reverse=True)
    return matches


def _confidence(hits: int, total: int) -> str:
    ratio = hits / max(total, 1)
    if ratio >= 0.75:
        return "HIGH"
    elif ratio >= 0.40:
        return "MEDIUM"
    else:
        return "LOW"

# ─────────────────────────────────────────────────────────────────────────────
#  REPORT RENDERING
# ─────────────────────────────────────────────────────────────────────────────

def print_sample_report(sample_path: str, report: dict):
    """Pretty-print the full analysis report for one sample."""

    filename = os.path.basename(sample_path)
    section(f"SAMPLE: {filename}")

    # ── File Metadata ─────────────────────────────────────────────────────────
    print(f"\n{C.BOLD}  [FILE METADATA]{C.RESET}")
    info(f"Path      : {sample_path}")
    info(f"Size      : {report['metadata']['size']}")
    info(f"MD5       : {report['metadata']['hashes'].get('md5', 'N/A')}")
    info(f"SHA1      : {report['metadata']['hashes'].get('sha1', 'N/A')}")
    info(f"SHA256    : {report['metadata']['hashes'].get('sha256', 'N/A')}")

    # ── File Type (TrID) ──────────────────────────────────────────────────────
    print(f"\n{C.BOLD}  [FILE TYPE DETECTION — TrID]{C.RESET}")
    ft = report.get("filetype", {})
    if ft.get("error"):
        err(ft["error"])
    elif ft.get("detections"):
        for d in ft["detections"][:5]:
            bar_len = int(d["pct"] / 2)
            bar = f"{C.GREEN}{'█' * bar_len}{C.DIM}{'░' * (50 - bar_len)}{C.RESET}"
            print(f"    {bar} {C.BOLD}{d['pct']:5.1f}%{C.RESET}  ({d['ext']})  {d['type']}")
    else:
        warn("No file-type detections returned by TrID.")

    # ── Strings (strings.exe) ─────────────────────────────────────────────────
    print(f"\n{C.BOLD}  [STRING EXTRACTION — strings.exe]{C.RESET}")
    st = report.get("strings_tool", {})
    if st.get("error"):
        err(st["error"])
    else:
        ok(f"Extracted {st['count']:,} strings (min length {MIN_STRING_LENGTH})")
        cats = report.get("strings_categorised", {})
        if cats:
            for cat, items in cats.items():
                print(f"\n    {C.YELLOW}▸ {cat}{C.RESET} ({len(items)} items)")
                for item in items[:8]:
                    detail(item[:100])
                if len(items) > 8:
                    detail(f"... and {len(items) - 8} more")

    # ── FLOSS Strings ─────────────────────────────────────────────────────────
    print(f"\n{C.BOLD}  [DEOBFUSCATED STRINGS — FLOSS]{C.RESET}")
    fl = report.get("floss", {})
    if fl.get("error"):
        err(fl["error"])
    else:
        ok(f"FLOSS extracted {fl['count']:,} strings (includes decoded / stack strings)")
        floss_cats = report.get("floss_categorised", {})
        if floss_cats:
            for cat, items in floss_cats.items():
                print(f"\n    {C.CYAN}▸ {cat}{C.RESET} ({len(items)} items — FLOSS)")
                for item in items[:6]:
                    detail(item[:100])
                if len(items) > 6:
                    detail(f"... and {len(items) - 6} more")

    # ── Malware Family ────────────────────────────────────────────────────────
    print(f"\n{C.BOLD}  [MALWARE FAMILY IDENTIFICATION]{C.RESET}")
    families = report.get("families", [])
    if not families:
        warn("No known malware family signatures matched — sample may be novel or clean.")
    else:
        for rank, fam in enumerate(families[:5], 1):
            conf_colour = {
                "HIGH":   C.RED,
                "MEDIUM": C.YELLOW,
                "LOW":    C.DIM,
            }.get(fam["confidence"], C.WHITE)

            print(f"\n    {C.BOLD}#{rank}  {fam['family']}{C.RESET}")
            print(f"        Description : {fam['description']}")
            print(f"        Confidence  : {conf_colour}{C.BOLD}{fam['confidence']}{C.RESET}"
                  f"  ({fam['hits']} / {len([s for s in MALWARE_SIGNATURES if s['family'] == fam['family']][0]['indicators'])} indicators matched)")
            print(f"        Matched IOCs:")
            for pat in fam["patterns"]:
                detail(pat)


def write_json_report(reports: dict, output_path: str):
    """Serialise all reports to a JSON file."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2, default=str)
    ok(f"JSON report saved → {output_path}")


# ─────────────────────────────────────────────────────────────────────────────
#  TEXT REPORT  (detailed, structured, analyst-grade)
# ─────────────────────────────────────────────────────────────────────────────

def write_text_report(reports: dict, output_path: str):
    """Write a comprehensive plain-text analyst report."""
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    SEP = "=" * 80
    DIV = "-" * 80
    HDR = "~" * 80

    lines = [
        SEP,
        "       STATIC MALWARE ANALYSIS REPORT — CONFIDENTIAL",
        f"       Generated  : {ts}",
        f"       Samples    : {len(reports)}",
        f"       Framework  : TrID | strings.exe | FLOSS",
        SEP,
        "",
    ]

    # ── Executive summary table ───────────────────────────────────────────────
    lines += [
        "EXECUTIVE SUMMARY",
        DIV,
        f"  {'#':<3} {'Sample':<22} {'Size':<10} {'Top File Type':<30} {'Top Family':<22} {'Conf'}",
        f"  {'─'*3} {'─'*22} {'─'*10} {'─'*30} {'─'*22} {'─'*6}",
    ]
    for idx, (sp, rep) in enumerate(reports.items(), 1):
        fn    = os.path.basename(sp)[:21]
        sz    = rep["metadata"]["size"][:9]
        dets  = rep["filetype"].get("detections", [])
        ft_s  = (dets[0]["type"][:29] if dets else "Unknown")
        fams  = rep.get("families", [])
        fam_s = (fams[0]["family"][:21] if fams else "Unidentified")
        con_s = (fams[0]["confidence"] if fams else "N/A")
        lines.append(f"  {idx:<3} {fn:<22} {sz:<10} {ft_s:<30} {fam_s:<22} {con_s}")
    lines += ["", SEP, ""]

    # ── Per-sample detail ─────────────────────────────────────────────────────
    for sp, rep in reports.items():
        fn = os.path.basename(sp)
        lines += [
            HDR,
            f"  SAMPLE: {fn}",
            HDR,
            "",
            "  ┌─ FILE METADATA",
            f"  │   Path      : {sp}",
            f"  │   Size      : {rep['metadata']['size']}",
            f"  │   MD5       : {rep['metadata']['hashes'].get('md5',  'N/A')}",
            f"  │   SHA1      : {rep['metadata']['hashes'].get('sha1', 'N/A')}",
            f"  │   SHA256    : {rep['metadata']['hashes'].get('sha256','N/A')}",
            f"  │   Analysed  : {rep.get('timestamp', 'N/A')}",
            "  └" + "─" * 60,
            "",
        ]

        # File type
        lines.append("  ┌─ FILE TYPE DETECTION  (TrID)")
        dets = rep.get("filetype", {}).get("detections", [])
        if rep["filetype"].get("error"):
            lines.append(f"  │   ERROR: {rep['filetype']['error']}")
        elif dets:
            for d in dets[:5]:
                bar = "█" * int(d["pct"] / 2) + "░" * (50 - int(d["pct"] / 2))
                lines.append(f"  │   [{bar}] {d['pct']:5.1f}%  ({d['ext']})  {d['type']}")
        else:
            lines.append("  │   No detections returned.")
        lines += ["  └" + "─" * 60, ""]

        # Strings stats
        st_cnt = rep.get("strings_tool", {}).get("count", 0)
        fl_cnt = rep.get("floss",        {}).get("count", 0)
        lines += [
            "  ┌─ STRING EXTRACTION STATISTICS",
            f"  │   strings.exe : {st_cnt:,} strings extracted",
            f"  │   FLOSS       : {fl_cnt:,} strings extracted (includes decoded/stack strings)",
            f"  │   Combined    : {st_cnt + fl_cnt:,} total strings",
            "  └" + "─" * 60,
            "",
        ]

        # Categorised strings — both tools merged
        merged_cats: dict = defaultdict(list)
        for cat, items in rep.get("strings_categorised", {}).items():
            merged_cats[cat].extend(items)
        for cat, items in rep.get("floss_categorised", {}).items():
            for item in items:
                if item not in merged_cats[cat]:
                    merged_cats[cat].append(item)

        if merged_cats:
            lines.append("  ┌─ CATEGORISED STRINGS  (top 10 per category)")
            for cat, items in merged_cats.items():
                lines.append(f"  │")
            for cat, items in merged_cats.items():
                lines.append(f"  │   [{cat}]  — {len(items)} item(s)")
                for item in items[:10]:
                    lines.append(f"  │       {item[:100]}")
                if len(items) > 10:
                    lines.append(f"  │       ... {len(items)-10} more not shown")
            lines += ["  └" + "─" * 60, ""]

        # Malware family
        families = rep.get("families", [])
        lines.append("  ┌─ MALWARE FAMILY IDENTIFICATION")
        if not families:
            lines.append("  │   No known malware family signatures matched.")
            lines.append("  │   Sample may be novel, clean, or heavily obfuscated.")
        else:
            for rank, fam in enumerate(families[:5], 1):
                total_ind = len([
                    s for s in MALWARE_SIGNATURES
                    if s["family"] == fam["family"]
                ][0]["indicators"])
                lines += [
                    f"  │",
                    f"  │   #{rank}  {fam['family']}",
                    f"  │       Description : {fam['description']}",
                    f"  │       Confidence  : {fam['confidence']}  "
                    f"({fam['hits']}/{total_ind} indicators matched)",
                    f"  │       Matched IOC Patterns:",
                ]
                for pat in fam["patterns"]:
                    lines.append(f"  │           • {pat}")
        lines += ["  └" + "─" * 60, "", ""]

    # ── Footer ────────────────────────────────────────────────────────────────
    lines += [
        SEP,
        "  DISCLAIMER: This report is generated by an automated static analysis",
        "  framework. Results should be validated by a qualified malware analyst.",
        "  Static analysis alone may not detect all threats.",
        SEP,
    ]

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    ok(f"Text report saved  → {output_path}")


# ─────────────────────────────────────────────────────────────────────────────
#  HTML REPORT  (professional, self-contained, dark-theme cyber aesthetic)
# ─────────────────────────────────────────────────────────────────────────────

def _conf_class(conf: str) -> str:
    return {"HIGH": "conf-high", "MEDIUM": "conf-med", "LOW": "conf-low"}.get(conf, "conf-low")

def _esc(s: str) -> str:
    """HTML-escape a string."""
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))

def write_html_report(reports: dict, output_path: str):
    """Generate a self-contained, professional dark-theme HTML report."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_samples  = len(reports)
    total_families = sum(1 for r in reports.values() if r.get("families"))
    total_strings  = sum(
        r.get("strings_tool", {}).get("count", 0) + r.get("floss", {}).get("count", 0)
        for r in reports.values()
    )

    # ── CSS ───────────────────────────────────────────────────────────────────
    css = """
    :root {
      --bg:       #0a0d14;
      --surface:  #0f1520;
      --card:     #141b2d;
      --border:   #1e2d4a;
      --accent:   #00d4ff;
      --accent2:  #ff4757;
      --accent3:  #2ed573;
      --accent4:  #ffa502;
      --text:     #c8d6f0;
      --muted:    #5a6a8a;
      --high:     #ff4757;
      --med:      #ffa502;
      --low:      #5a6a8a;
      --font-mono: 'Courier New', Courier, monospace;
      --font-main: 'Segoe UI', system-ui, sans-serif;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { scroll-behavior: smooth; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-main);
      font-size: 14px;
      line-height: 1.6;
      min-height: 100vh;
    }

    /* ── Animated grid background ── */
    body::before {
      content: '';
      position: fixed; inset: 0; z-index: -1;
      background-image:
        linear-gradient(rgba(0,212,255,.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,212,255,.03) 1px, transparent 1px);
      background-size: 40px 40px;
      pointer-events: none;
    }

    /* ── Header ── */
    header {
      background: linear-gradient(135deg, #0a0d14 0%, #0f1a30 50%, #0a0d14 100%);
      border-bottom: 1px solid var(--border);
      padding: 32px 48px 28px;
      position: relative;
      overflow: hidden;
    }
    header::after {
      content: '';
      position: absolute;
      bottom: 0; left: 0; right: 0; height: 2px;
      background: linear-gradient(90deg, transparent, var(--accent), transparent);
    }
    .header-grid { display: flex; align-items: flex-start; gap: 32px; }
    .logo-block { flex-shrink: 0; }
    .logo-icon {
      width: 64px; height: 64px;
      background: linear-gradient(135deg, #00d4ff22, #00d4ff44);
      border: 1px solid var(--accent);
      border-radius: 12px;
      display: flex; align-items: center; justify-content: center;
      font-size: 28px;
    }
    .header-text h1 {
      font-size: 22px; font-weight: 700; letter-spacing: .08em;
      color: #fff; text-transform: uppercase;
    }
    .header-text h1 span { color: var(--accent); }
    .header-text p { color: var(--muted); margin-top: 4px; font-size: 13px; }
    .header-meta {
      margin-left: auto; text-align: right;
      display: flex; flex-direction: column; gap: 4px;
    }
    .header-meta span {
      font-family: var(--font-mono);
      font-size: 11px; color: var(--muted);
      background: #ffffff08; border: 1px solid var(--border);
      padding: 2px 10px; border-radius: 4px;
    }
    .header-meta span b { color: var(--accent); }

    /* ── Navigation tabs ── */
    .nav-bar {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 0 48px;
      display: flex; gap: 0; overflow-x: auto;
    }
    .nav-tab {
      padding: 14px 22px;
      font-size: 12px; font-weight: 600; letter-spacing: .06em;
      text-transform: uppercase; cursor: pointer;
      color: var(--muted);
      border-bottom: 2px solid transparent;
      transition: all .2s; white-space: nowrap; user-select: none;
    }
    .nav-tab:hover  { color: var(--text); }
    .nav-tab.active { color: var(--accent); border-bottom-color: var(--accent); }

    /* ── Layout ── */
    main { max-width: 1400px; margin: 0 auto; padding: 32px 48px 64px; }

    /* ── Stat cards ── */
    .stat-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px; margin-bottom: 32px;
    }
    .stat-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 20px 24px;
      position: relative; overflow: hidden;
    }
    .stat-card::before {
      content: '';
      position: absolute; top: 0; left: 0; right: 0; height: 2px;
    }
    .stat-card.blue::before  { background: var(--accent);  }
    .stat-card.red::before   { background: var(--accent2); }
    .stat-card.green::before { background: var(--accent3); }
    .stat-card.amber::before { background: var(--accent4); }
    .stat-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing:.07em; }
    .stat-value { font-size: 32px; font-weight: 700; color: #fff; font-family: var(--font-mono); margin-top: 4px; }
    .stat-sub   { font-size: 11px; color: var(--muted); margin-top: 2px; }

    /* ── Section headers ── */
    .section-header {
      display: flex; align-items: center; gap: 12px;
      margin: 36px 0 16px;
    }
    .section-header h2 {
      font-size: 13px; font-weight: 700;
      text-transform: uppercase; letter-spacing: .1em;
      color: var(--accent);
    }
    .section-header::after {
      content: ''; flex: 1; height: 1px;
      background: linear-gradient(90deg, var(--border), transparent);
    }

    /* ── Summary table ── */
    .table-wrap { overflow-x: auto; border-radius: 10px; border: 1px solid var(--border); }
    table { width: 100%; border-collapse: collapse; }
    thead { background: #0d1525; }
    thead th {
      padding: 12px 16px;
      font-size: 11px; font-weight: 600; text-transform: uppercase;
      letter-spacing: .07em; color: var(--muted);
      text-align: left; white-space: nowrap;
      border-bottom: 1px solid var(--border);
    }
    tbody tr {
      border-bottom: 1px solid var(--border);
      transition: background .15s;
    }
    tbody tr:last-child { border-bottom: none; }
    tbody tr:hover { background: #ffffff04; }
    tbody td {
      padding: 12px 16px;
      font-size: 13px; vertical-align: middle;
    }
    .mono { font-family: var(--font-mono); font-size: 12px; }
    .hash { color: var(--muted); font-size: 11px; font-family: var(--font-mono); word-break: break-all; }

    /* ── Confidence badges ── */
    .badge {
      display: inline-block; padding: 2px 10px;
      border-radius: 20px; font-size: 10px; font-weight: 700;
      letter-spacing: .08em; text-transform: uppercase;
    }
    .conf-high { background: #ff475722; color: var(--high); border: 1px solid #ff475744; }
    .conf-med  { background: #ffa50222; color: var(--med);  border: 1px solid #ffa50244; }
    .conf-low  { background: #5a6a8a22; color: var(--muted);border: 1px solid #5a6a8a44; }

    /* ── Sample detail cards ── */
    .sample-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      margin-bottom: 28px;
      overflow: hidden;
    }
    .sample-card-header {
      background: linear-gradient(90deg, #0d1525, #111c35);
      border-bottom: 1px solid var(--border);
      padding: 18px 24px;
      display: flex; align-items: center; gap: 14px;
    }
    .sample-icon {
      width: 42px; height: 42px;
      background: #00d4ff18; border: 1px solid #00d4ff33;
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
      font-size: 18px; flex-shrink: 0;
    }
    .sample-name { font-size: 16px; font-weight: 700; color: #fff; }
    .sample-path { font-size: 11px; color: var(--muted); font-family: var(--font-mono); }
    .sample-body { padding: 24px; display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
    @media (max-width: 900px) { .sample-body { grid-template-columns: 1fr; } }

    /* ── Info panels ── */
    .panel {
      background: #0d1525;
      border: 1px solid var(--border);
      border-radius: 8px; overflow: hidden;
    }
    .panel-title {
      padding: 10px 16px;
      font-size: 11px; font-weight: 700;
      text-transform: uppercase; letter-spacing: .08em;
      color: var(--accent);
      border-bottom: 1px solid var(--border);
      background: #0a1020;
      display: flex; align-items: center; gap: 8px;
    }
    .panel-body { padding: 14px 16px; }
    .kv-row { display: flex; gap: 8px; margin-bottom: 6px; font-size: 12px; }
    .kv-key { color: var(--muted); flex-shrink: 0; width: 70px; }
    .kv-val { color: var(--text); word-break: break-all; }

    /* ── Progress bars (file type) ── */
    .ft-row { margin-bottom: 10px; }
    .ft-label { display: flex; justify-content: space-between; font-size: 11px; margin-bottom: 4px; }
    .ft-name  { color: var(--text); }
    .ft-pct   { color: var(--accent); font-family: var(--font-mono); font-weight: 600; }
    .ft-bar-track { height: 4px; background: var(--border); border-radius: 2px; }
    .ft-bar-fill  {
      height: 4px; border-radius: 2px;
      background: linear-gradient(90deg, var(--accent), #0088aa);
      transition: width .8s ease;
    }
    .ft-ext { font-size: 10px; color: var(--muted); margin-top: 1px; }

    /* ── String category pills ── */
    .cat-grid { display: flex; flex-wrap: wrap; gap: 8px; }
    .cat-pill {
      background: #1a2540; border: 1px solid var(--border);
      border-radius: 6px; padding: 6px 12px;
      font-size: 11px; cursor: pointer;
      transition: all .2s;
      display: flex; align-items: center; gap: 6px;
    }
    .cat-pill:hover { border-color: var(--accent); color: var(--accent); }
    .cat-pill .cnt {
      background: var(--accent); color: #000;
      border-radius: 10px; padding: 0 6px;
      font-size: 10px; font-weight: 700;
    }
    .cat-detail {
      display: none; margin-top: 12px;
      background: #0a0f1c; border: 1px solid var(--border);
      border-radius: 6px; padding: 12px;
      font-family: var(--font-mono); font-size: 11px;
      max-height: 200px; overflow-y: auto;
      line-height: 1.8;
    }
    .cat-detail.open { display: block; }
    .cat-detail div { color: var(--text); word-break: break-all; border-bottom: 1px solid #1a2030; padding: 2px 0; }
    .cat-detail div:last-child { border-bottom: none; }

    /* ── Family matches ── */
    .family-match {
      background: #0d1525; border: 1px solid var(--border);
      border-radius: 8px; margin-bottom: 12px; overflow: hidden;
    }
    .family-match-hdr {
      padding: 12px 16px;
      display: flex; align-items: center; gap: 12px;
      border-bottom: 1px solid var(--border);
    }
    .family-rank {
      width: 26px; height: 26px; border-radius: 50%;
      background: var(--accent); color: #000;
      display: flex; align-items: center; justify-content: center;
      font-size: 11px; font-weight: 800; flex-shrink: 0;
    }
    .family-name { font-size: 14px; font-weight: 700; color: #fff; }
    .family-desc { font-size: 11px; color: var(--muted); }
    .family-match-body { padding: 12px 16px; }
    .ioc-list {
      display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px;
    }
    .ioc-tag {
      background: #ff475710; border: 1px solid #ff475730;
      color: #ff8090; border-radius: 4px;
      padding: 2px 8px; font-family: var(--font-mono);
      font-size: 10px;
    }
    .hit-meter {
      display: flex; align-items: center; gap: 10px;
      font-size: 11px; color: var(--muted); margin-bottom: 6px;
    }
    .hit-pips { display: flex; gap: 3px; }
    .pip { width: 8px; height: 8px; border-radius: 2px; background: var(--border); }
    .pip.on { background: var(--accent2); }

    /* ── Full-width panels ── */
    .full-col { grid-column: 1 / -1; }

    /* ── Scrollbars ── */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--surface); }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--muted); }

    /* ── Tab sections ── */
    .tab-section { display: none; }
    .tab-section.active { display: block; }

    /* ── Footer ── */
    footer {
      margin-top: 64px; padding: 24px 48px;
      border-top: 1px solid var(--border);
      background: var(--surface);
      font-size: 11px; color: var(--muted);
      display: flex; justify-content: space-between; align-items: center;
    }
    footer span b { color: var(--accent); }
    """

    # ── JS ────────────────────────────────────────────────────────────────────
    js = """
    // Tab switching
    document.querySelectorAll('.nav-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-section').forEach(s => s.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById(tab.dataset.target).classList.add('active');
      });
    });

    // Toggle string category details
    document.querySelectorAll('.cat-pill').forEach(pill => {
      pill.addEventListener('click', () => {
        const detail = pill.nextElementSibling;
        if (detail && detail.classList.contains('cat-detail')) {
          detail.classList.toggle('open');
        }
      });
    });
    """

    # ── Build body ────────────────────────────────────────────────────────────
    def stat_cards():
        high_conf = sum(
            1 for r in reports.values()
            if r.get("families") and r["families"][0]["confidence"] == "HIGH"
        )
        return f"""
        <div class="stat-row">
          <div class="stat-card blue">
            <div class="stat-label">Samples Analysed</div>
            <div class="stat-value">{total_samples}</div>
            <div class="stat-sub">TrID + strings + FLOSS</div>
          </div>
          <div class="stat-card red">
            <div class="stat-label">Families Matched</div>
            <div class="stat-value">{total_families}</div>
            <div class="stat-sub">{high_conf} high-confidence hit(s)</div>
          </div>
          <div class="stat-card green">
            <div class="stat-label">Strings Extracted</div>
            <div class="stat-value">{total_strings:,}</div>
            <div class="stat-sub">Across all samples</div>
          </div>
          <div class="stat-card amber">
            <div class="stat-label">Analysis Engine</div>
            <div class="stat-value" style="font-size:18px;margin-top:8px">STATIC</div>
            <div class="stat-sub">No execution / sandbox</div>
          </div>
        </div>"""

    def summary_tab():
        rows = ""
        for idx, (sp, rep) in enumerate(reports.items(), 1):
            fn   = _esc(os.path.basename(sp))
            sz   = rep["metadata"]["size"]
            md5  = rep["metadata"]["hashes"].get("md5",  "N/A")
            sha2 = rep["metadata"]["hashes"].get("sha256","N/A")
            dets = rep["filetype"].get("detections", [])
            ft_s = _esc(dets[0]["type"]) if dets else "Unknown"
            pct  = f"{dets[0]['pct']:.1f}%" if dets else "—"
            fams = rep.get("families", [])
            fam_s  = _esc(fams[0]["family"]) if fams else "Unidentified"
            conf_s = fams[0]["confidence"] if fams else "N/A"
            st_cnt = rep.get("strings_tool", {}).get("count", 0)
            fl_cnt = rep.get("floss",        {}).get("count", 0)
            rows += f"""
            <tr>
              <td class="mono">{idx}</td>
              <td><b style="color:#fff">{fn}</b></td>
              <td class="mono">{sz}</td>
              <td class="hash">{md5}</td>
              <td class="hash" style="max-width:220px;overflow:hidden;text-overflow:ellipsis">{sha2}</td>
              <td>{ft_s} <span style="color:var(--accent);font-size:11px">({pct})</span></td>
              <td><span class="badge {_conf_class(conf_s)}">{conf_s}</span></td>
              <td><b style="color:#fff">{fam_s}</b></td>
              <td class="mono">{(st_cnt+fl_cnt):,}</td>
            </tr>"""
        return f"""
        <div class="section-header"><h2>&#9679; Executive Summary</h2></div>
        {stat_cards()}
        <div class="section-header"><h2>&#9679; Sample Overview Table</h2></div>
        <div class="table-wrap">
          <table>
            <thead><tr>
              <th>#</th><th>Filename</th><th>Size</th>
              <th>MD5</th><th>SHA-256</th>
              <th>Primary File Type</th><th>Confidence</th>
              <th>Top Family Match</th><th>Strings</th>
            </tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>"""

    def cat_section(cats: dict, tool_label: str) -> str:
        if not cats:
            return f'<p style="color:var(--muted);font-size:12px">No categorised strings from {tool_label}.</p>'
        out = f'<p style="font-size:11px;color:var(--muted);margin-bottom:10px">Click a category to expand. Source: <b style="color:var(--accent)">{_esc(tool_label)}</b></p>'
        out += '<div class="cat-grid">'
        for cat, items in cats.items():
            out += f'<div><div class="cat-pill"><span>{_esc(cat)}</span><span class="cnt">{len(items)}</span></div>'
            out += '<div class="cat-detail">'
            for item in items[:30]:
                out += f'<div>{_esc(item[:120])}</div>'
            if len(items) > 30:
                out += f'<div style="color:var(--muted)">… {len(items)-30} more not shown</div>'
            out += '</div></div>'
        out += '</div>'
        return out

    def samples_tab():
        out = ""
        for sp, rep in reports.items():
            fn = os.path.basename(sp)
            hashes = rep["metadata"]["hashes"]
            dets   = rep["filetype"].get("detections", [])
            ft_err = rep["filetype"].get("error")
            st     = rep.get("strings_tool", {})
            fl     = rep.get("floss", {})
            fams   = rep.get("families", [])

            # metadata panel
            meta_panel = f"""
            <div class="panel">
              <div class="panel-title">&#128196; File Metadata</div>
              <div class="panel-body">
                <div class="kv-row"><span class="kv-key">Size</span><span class="kv-val">{_esc(rep['metadata']['size'])}</span></div>
                <div class="kv-row"><span class="kv-key">MD5</span><span class="kv-val mono">{_esc(hashes.get('md5','N/A'))}</span></div>
                <div class="kv-row"><span class="kv-key">SHA1</span><span class="kv-val mono">{_esc(hashes.get('sha1','N/A'))}</span></div>
                <div class="kv-row"><span class="kv-key">SHA256</span><span class="kv-val mono" style="font-size:10px">{_esc(hashes.get('sha256','N/A'))}</span></div>
                <div class="kv-row"><span class="kv-key">Scanned</span><span class="kv-val">{_esc(rep.get('timestamp','N/A'))}</span></div>
              </div>
            </div>"""

            # file type panel
            if ft_err:
                ft_body = f'<p style="color:var(--accent2);font-size:12px">{_esc(ft_err)}</p>'
            elif dets:
                bars = ""
                for d in dets[:5]:
                    w = d["pct"]
                    bars += f"""
                    <div class="ft-row">
                      <div class="ft-label">
                        <span class="ft-name">{_esc(d['type'][:45])}</span>
                        <span class="ft-pct">{d['pct']:.1f}%</span>
                      </div>
                      <div class="ft-bar-track"><div class="ft-bar-fill" style="width:{w}%"></div></div>
                      <div class="ft-ext">Extension: {_esc(d['ext'])}</div>
                    </div>"""
                ft_body = bars
            else:
                ft_body = '<p style="color:var(--muted);font-size:12px">No detections.</p>'

            ft_panel = f"""
            <div class="panel">
              <div class="panel-title">&#128269; File Type Detection (TrID)</div>
              <div class="panel-body">{ft_body}</div>
            </div>"""

            # strings stats panel
            st_cnt = st.get("count", 0)
            fl_cnt = fl.get("count", 0)
            st_err = st.get("error","")
            fl_err = fl.get("error","")
            strings_panel = f"""
            <div class="panel">
              <div class="panel-title">&#128196; String Extraction Stats</div>
              <div class="panel-body">
                <div class="kv-row"><span class="kv-key">strings.exe</span>
                  <span class="kv-val mono" style="color:var(--accent3)">{st_cnt:,} strings</span></div>
                {'<div class="kv-row"><span class="kv-key"></span><span class="kv-val" style="color:var(--accent2);font-size:11px">' + _esc(st_err) + '</span></div>' if st_err else ''}
                <div class="kv-row"><span class="kv-key">FLOSS</span>
                  <span class="kv-val mono" style="color:var(--accent4)">{fl_cnt:,} strings</span></div>
                {'<div class="kv-row"><span class="kv-key"></span><span class="kv-val" style="color:var(--accent2);font-size:11px">' + _esc(fl_err) + '</span></div>' if fl_err else ''}
                <div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border)">
                  <div class="kv-row"><span class="kv-key">Combined</span>
                    <span class="kv-val mono" style="color:#fff;font-size:15px;font-weight:700">{(st_cnt+fl_cnt):,}</span></div>
                </div>
              </div>
            </div>"""

            # strings categorised (full width)
            merged: dict = defaultdict(list)
            for cat, items in rep.get("strings_categorised", {}).items():
                merged[cat].extend(items)
            for cat, items in rep.get("floss_categorised", {}).items():
                for item in items:
                    if item not in merged[cat]:
                        merged[cat].append(item)

            cat_panel = f"""
            <div class="panel full-col">
              <div class="panel-title">&#128204; Categorised Strings (strings.exe + FLOSS)</div>
              <div class="panel-body">{cat_section(dict(merged), "strings.exe + FLOSS")}</div>
            </div>"""

            # family matches (full width)
            if not fams:
                fam_html = '<p style="color:var(--muted);font-size:13px;padding:8px 0">No known malware family signatures matched. Sample may be novel, clean, or heavily obfuscated.</p>'
            else:
                fam_html = ""
                for rank, fam in enumerate(fams[:5], 1):
                    total_ind = len([
                        s for s in MALWARE_SIGNATURES
                        if s["family"] == fam["family"]
                    ][0]["indicators"])
                    pips = "".join(
                        f'<div class="pip {"on" if i < fam["hits"] else ""}"></div>'
                        for i in range(total_ind)
                    )
                    ioc_tags = "".join(f'<span class="ioc-tag">{_esc(p)}</span>' for p in fam["patterns"])
                    fam_html += f"""
                    <div class="family-match">
                      <div class="family-match-hdr">
                        <div class="family-rank">{rank}</div>
                        <div>
                          <div class="family-name">{_esc(fam['family'])}</div>
                          <div class="family-desc">{_esc(fam['description'])}</div>
                        </div>
                        <div style="margin-left:auto">
                          <span class="badge {_conf_class(fam['confidence'])}">{fam['confidence']}</span>
                        </div>
                      </div>
                      <div class="family-match-body">
                        <div class="hit-meter">
                          <span>{fam['hits']} of {total_ind} indicators matched</span>
                          <div class="hit-pips">{pips}</div>
                        </div>
                        <div class="ioc-list">{ioc_tags}</div>
                      </div>
                    </div>"""

            fam_panel = f"""
            <div class="panel full-col">
              <div class="panel-title">&#9888; Malware Family Identification</div>
              <div class="panel-body">{fam_html}</div>
            </div>"""

            out += f"""
            <div class="sample-card">
              <div class="sample-card-header">
                <div class="sample-icon">&#128187;</div>
                <div>
                  <div class="sample-name">{_esc(fn)}</div>
                  <div class="sample-path">{_esc(sp)}</div>
                </div>
                <div style="margin-left:auto;display:flex;gap:8px;align-items:center">
                  {('<span class="badge ' + _conf_class(fams[0]["confidence"]) + '">' + fams[0]["confidence"] + ' confidence</span>') if fams else ''}
                  {'<span class="badge conf-low">UNIDENTIFIED</span>' if not fams else ''}
                </div>
              </div>
              <div class="sample-body">
                {meta_panel}
                {ft_panel}
                {strings_panel}
                <div></div>
                {cat_panel}
                {fam_panel}
              </div>
            </div>"""
        return out

    # Build nav tabs for each sample
    sample_tabs = "".join(
        f'<div class="nav-tab" data-target="tab-sample-{i}">'
        f'&#128187; {_esc(os.path.basename(sp))}</div>'
        for i, sp in enumerate(reports.keys())
    )
    sample_sections = "".join(
        f'<div class="tab-section" id="tab-sample-{i}">'
        f'<div class="section-header"><h2>&#9679; Sample Detail: {_esc(os.path.basename(sp))}</h2></div>'
        + "".join(
            f"""<div class="sample-card">
              <div class="sample-card-header">
                <div class="sample-icon">&#128187;</div>
                <div>
                  <div class="sample-name">{_esc(os.path.basename(sp))}</div>
                  <div class="sample-path">{_esc(sp)}</div>
                </div>
              </div>
              <div class="sample-body">
              </div>
            </div>"""
            for _sp, _rep in [(sp, reports[sp])]
        )
        + f'</div>'
        for i, sp in enumerate(reports.keys())
    )

    # ── Assemble full HTML ────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Static Malware Analysis Report — {_esc(ts)}</title>
<style>{css}</style>
</head>
<body>

<header>
  <div class="header-grid">
    <div class="logo-block"><div class="logo-icon">&#9760;</div></div>
    <div class="header-text">
      <h1>Static Malware <span>Analysis</span> Report</h1>
      <p>Tools: TrID &nbsp;|&nbsp; strings.exe &nbsp;|&nbsp; FLOSS &nbsp;&nbsp;&mdash;&nbsp;&nbsp; Framework v1.0</p>
    </div>
    <div class="header-meta">
      <span>Generated: <b>{_esc(ts)}</b></span>
      <span>Samples: <b>{total_samples}</b></span>
      <span>Classification: <b>CONFIDENTIAL</b></span>
    </div>
  </div>
</header>

<div class="nav-bar">
  <div class="nav-tab active" data-target="tab-overview">&#9632; Overview</div>
  <div class="nav-tab" data-target="tab-samples">&#128187; All Samples</div>
  {sample_tabs}
</div>

<main>

  <!-- ── Overview Tab ── -->
  <div class="tab-section active" id="tab-overview">
    {summary_tab()}
  </div>

  <!-- ── All Samples Tab ── -->
  <div class="tab-section" id="tab-samples">
    <div class="section-header"><h2>&#9679; Detailed Sample Reports</h2></div>
    {samples_tab()}
  </div>

  <!-- ── Per-sample Tabs ── -->
  {sample_sections}

</main>

<footer>
  <span>Static Malware Analysis Framework &nbsp;&mdash;&nbsp; TrID | strings.exe | FLOSS</span>
  <span>Generated: <b>{_esc(ts)}</b> &nbsp;|&nbsp; <b style="color:var(--accent2)">CONFIDENTIAL — FOR AUTHORISED USE ONLY</b></span>
</footer>

<script>{js}</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    ok(f"HTML report saved  → {output_path}")

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

def analyse_sample(sample_path: str, tools: dict) -> dict:
    """Run the full static analysis pipeline on one sample."""

    report = {
        "sample":    sample_path,
        "timestamp": datetime.now().isoformat(),
        "metadata":  {
            "size":   file_size(sample_path),
            "hashes": compute_hashes(sample_path),
        },
        "filetype":            {},
        "strings_tool":        {},
        "floss":               {},
        "strings_categorised": {},
        "floss_categorised":   {},
        "families":            [],
    }

    # 1. File-type detection
    info("Running TrID …")
    report["filetype"] = detect_filetype(sample_path, tools["trid"])

    # 2. String extraction (strings.exe)
    info("Running strings.exe …")
    report["strings_tool"] = extract_strings(sample_path, tools["strings"])
    if report["strings_tool"].get("strings"):
        report["strings_categorised"] = classify_strings(report["strings_tool"]["strings"])

    # 3. FLOSS deobfuscated strings
    info("Running FLOSS (this may take a moment) …")
    report["floss"] = extract_floss_strings(sample_path, tools["floss"])
    if report["floss"].get("strings"):
        report["floss_categorised"] = classify_strings(report["floss"]["strings"])

    # 4. Malware family identification
    all_strings = (
        report["strings_tool"].get("strings", [])
        + report["floss"].get("strings", [])
    )
    info("Matching against malware signature database …")
    report["families"] = identify_malware_family(all_strings)

    return report


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Static Malware Analysis Automation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "samples",
        nargs="*",
        default=[],
        metavar="SAMPLE",
        help="One or more malware sample file paths to analyse",
    )
    parser.add_argument(
        "--dir", "-d",
        default=None,
        metavar="DIRECTORY",
        help="Analyse all files in this directory (non-recursive)",
    )
    parser.add_argument(
        "--glob", "-g",
        default=None,
        metavar="PATTERN",
        help='Glob pattern for sample discovery, e.g. "C:\\Samples\\*.exe"',
    )
    parser.add_argument(
        "--recursive", "-r",
        action="store_true",
        help="When using --dir, also scan subdirectories recursively",
    )
    parser.add_argument("--trid",    default=TOOL_DEFAULTS["trid"],    help="Path to TrID binary")
    parser.add_argument("--strings", default=TOOL_DEFAULTS["strings"], help="Path to strings.exe")
    parser.add_argument("--floss",   default=TOOL_DEFAULTS["floss"],   help="Path to FLOSS binary")
    parser.add_argument("--output-dir", default=".", help="Directory for output reports (default: current dir)")
    parser.add_argument("--json",    action="store_true", help="Also save a JSON report")
    parser.add_argument("--no-html", action="store_true", help="Skip HTML report generation")
    parser.add_argument("--no-text", action="store_true", help="Skip plain-text report generation")
    parser.add_argument("--all-strings", action="store_true",
                        help="Print ALL extracted strings instead of categorised excerpts")
    args = parser.parse_args()

    tools = {
        "trid":    args.trid,
        "strings": args.strings,
        "floss":   args.floss,
    }

    # ── Tool availability check ───────────────────────────────────────────────
    section("PRE-FLIGHT: TOOL AVAILABILITY CHECK")
    for name, path in tools.items():
        if tool_available(path):
            ok(f"{name:10s} → {path}")
        else:
            warn(f"{name:10s} → NOT FOUND at '{path}' (set --{name} or env var)")

    # ── Sample collection ─────────────────────────────────────────────────────
    section("PRE-FLIGHT: SAMPLE COLLECTION")
    import glob as _glob

    candidate_paths = list(args.samples)  # positional args

    # --dir  : add all files in directory
    if args.dir:
        if not os.path.isdir(args.dir):
            err(f"--dir path is not a directory: {args.dir}")
        else:
            pattern = "**/*" if args.recursive else "*"
            found = [
                str(p) for p in Path(args.dir).glob(pattern)
                if p.is_file()
            ]
            if found:
                info(f"--dir: found {len(found)} file(s) in {args.dir}")
                candidate_paths.extend(found)
            else:
                warn(f"--dir: no files found in {args.dir}")

    # --glob : shell-style glob pattern
    if args.glob:
        found = _glob.glob(args.glob, recursive=args.recursive)
        found = [p for p in found if os.path.isfile(p)]
        if found:
            info(f"--glob: matched {len(found)} file(s)")
            candidate_paths.extend(found)
        else:
            warn(f"--glob: pattern matched nothing: {args.glob}")

    # Deduplicate while preserving order
    seen = set()
    candidate_paths = [
        p for p in candidate_paths
        if not (os.path.abspath(p) in seen or seen.add(os.path.abspath(p)))
    ]

    # Validate
    section("PRE-FLIGHT: SAMPLE VALIDATION")
    valid_samples = []
    for sp in candidate_paths:
        if os.path.isfile(sp):
            ok(f"Found : {sp}  ({file_size(sp)})")
            valid_samples.append(sp)
        else:
            err(f"Not found : {sp}")

    if not valid_samples:
        err("No valid samples to analyse.")
        print()
        print(f"  {C.YELLOW}Usage examples:{C.RESET}")
        print(f"    python static_malware_analysis.py  Rams1.exe TotalAware2.exe")
        print(f"    python static_malware_analysis.py  --dir C:\\Samples")
        print(f"    python static_malware_analysis.py  --glob \"*.exe\"")
        print(f"    python static_malware_analysis.py  --dir C:\\Samples --recursive")
        print()
        sys.exit(1)

    info(f"Total samples queued for analysis: {len(valid_samples)}")

    # ── Run analysis ──────────────────────────────────────────────────────────
    all_reports = {}
    for sp in valid_samples:
        section(f"ANALYSING: {os.path.basename(sp)}")
        try:
            report = analyse_sample(sp, tools)
            all_reports[sp] = report
            print_sample_report(sp, report)
        except Exception as exc:
            err(f"Unexpected error analysing {sp}: {exc}")

    # ── Summary table ─────────────────────────────────────────────────────────
    section("ANALYSIS SUMMARY")
    print(f"\n  {'Sample':<25} {'File Type':<32} {'Top Family Match':<30} {'Confidence'}")
    print(f"  {'─'*24} {'─'*31} {'─'*29} {'─'*10}")
    for sp, rep in all_reports.items():
        fn   = os.path.basename(sp)[:24]
        ft   = rep["filetype"].get("detections", [])
        ft_s = (ft[0]["type"][:30] if ft else "Unknown")
        fam  = rep["families"]
        fam_s   = (fam[0]["family"][:28] if fam else "Unidentified")
        conf_s  = (fam[0]["confidence"] if fam else "—")
        print(f"  {fn:<25} {ft_s:<32} {fam_s:<30} {conf_s}")

    # ── Output reports ────────────────────────────────────────────────────────
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(args.output_dir, exist_ok=True)

    section("SAVING REPORTS")

    # HTML report — generated by default, skip with --no-html
    if not args.no_html:
        html_path = os.path.join(args.output_dir, f"malware_analysis_{ts_str}.html")
        try:
            write_html_report(all_reports, html_path)
        except Exception as exc:
            err(f"HTML report failed: {exc}")

    # Plain-text report — generated by default, skip with --no-text
    if not args.no_text:
        txt_path = os.path.join(args.output_dir, f"malware_analysis_{ts_str}.txt")
        try:
            write_text_report(all_reports, txt_path)
        except Exception as exc:
            err(f"Text report failed: {exc}")

    # JSON report — opt-in with --json
    if args.json:
        json_path = os.path.join(args.output_dir, f"malware_analysis_{ts_str}.json")
        try:
            write_json_report(all_reports, json_path)
        except Exception as exc:
            err(f"JSON report failed: {exc}")

    section("ANALYSIS COMPLETE")
    ok(f"Processed {len(all_reports)} sample(s) successfully.")
    if not args.no_html:
        info("Open the HTML report in any browser for the full interactive view.")
    print()


if __name__ == "__main__":
    main()