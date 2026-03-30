# AD AutoPwn

**Zero-Auth to Domain Admin — Automated Active Directory Attack Chain**

A fully automated penetration testing tool that chains 19 attack techniques to compromise Active Directory environments. Designed for authorized security assessments.

```
       _   ___      _       _       ___
      /_\ |   \    /_\ _  _| |_ ___| _ \__ __ ___ _
     / _ \| |) |  / _ \ || |  _/ _ \  _/\ V  V / ' \
    /_/ \_\___/  /_/ \_\_,_|\__\___/_|   \_/\_/|_||_|

    ⚡ Zero-Auth to Domain Admin — Attack Chain
    ARP | WPAD | WSUS | PXE | AD CS | SCCM | Roast | RBCD | GPO | DCSync
```

## Features

### Zero-Auth Attacks (no credentials needed)
- **Passive network sniffing** — WPAD, WSUS, PXE, LLMNR, DHCPv6, TFTP detection
- **ARP spoof + NTLM relay** — capture and crack NTLMv2 hashes
- **WPAD poisoning** — mitm6 / Responder IPv6 DNS hijack
- **WSUS relay** — intercept Windows Update NTLM auth (port 8530/8531)
- **PXE boot credential theft** — extract creds from boot images via TFTP
- **NTLM theft file drops** — .library-ms / .theme / .url files on writable shares
- **WebDAV coercion** — WebClient HTTP-to-LDAP relay (bypasses SMB signing)
- **DHCP coercion** — DHCP server machine account relay

### Credential Harvesting
- **Kerberoasting** — extract and auto-crack SPN hashes (hashcat mode 13100/19700)
- **AS-REP Roasting** — crack accounts without pre-auth (hashcat mode 18200)
- **SCCM NAA theft** — extract Network Access Account credentials via sccmhunter

### Privilege Escalation
- **AD CS exploitation** — ESC1 through ESC16 via certipy (auto-enum + exploit)
- **Shadow Credentials** — msDS-KeyCredentialLink via ntlmrelayx or pywhisker
- **RBCD abuse** — Resource-Based Constrained Delegation (addcomputer + S4U2Proxy)
- **GPO abuse** — pyGPOAbuse scheduled task as SYSTEM

### Domain Compromise
- **DCSync** — full domain hash dump via impacket-secretsdump
- **DPAPI backup key** — extract domain DPAPI key for offline credential decryption
- **AppLocker bypass** — LOLBins (mshta, certutil, regsvr32, etc.) + WSUS signed delivery
- **WSUS update injection** — push malicious Windows Updates via wsuks

## Usage

```bash
# Fully automated — zero arguments, auto-discovers everything
sudo ./ad-autopwn.py

# With credentials
./ad-autopwn.py -u jsmith -p 'P@ss123' -d corp.local --dc-ip 10.0.0.1

# Individual phases
./ad-autopwn.py --phase roast -u user -p pass -d corp.local --dc-ip 10.0.0.1
./ad-autopwn.py --phase adcs -u user -p pass -d corp.local --dc-ip 10.0.0.1
./ad-autopwn.py --phase sccm -u user -p pass -d corp.local --dc-ip 10.0.0.1
./ad-autopwn.py --phase sniff --sniff-duration 60
./ad-autopwn.py --phase pxe

# AppLocker bypass
./ad-autopwn.py -u user -p pass --applocker --lolbin mshta --custom-cmd "whoami"

# Dry run (show commands without executing)
./ad-autopwn.py --dry-run --phase full -u user -p pass -d corp.local --dc-ip 10.0.0.1
```

## Available Phases

| Phase | Auth Required | Description |
|-------|--------------|-------------|
| `full` | No (zero-auth) | Complete automated chain |
| `sniff` | No | Passive network discovery |
| `arp` | No | ARP spoof + NTLM capture |
| `wpad` | No | WPAD/LLMNR poisoning |
| `wsus` | No | WSUS NTLM relay |
| `pxe` | No | PXE boot credential theft |
| `roast` | Yes | Kerberoast + AS-REP Roast |
| `adcs` | Yes | AD CS exploitation (ESC1-16) |
| `sccm` | Yes | SCCM NAA credential theft |
| `enum` | Yes | Target enumeration |
| `exploit` | Yes | NTLM reflection exploit |
| `dcsync` | Yes (DA) | Domain hash dump |

## Dependencies

### APT Packages (Kali Linux)

```bash
# Core (required)
apt install python3 impacket-scripts netexec nmap hashcat

# Network attacks
apt install tcpdump responder dsniff arp-scan

# AD exploitation
apt install certipy-ad bloodyad smbclient

# PXE/WIM
apt install atftp wimtools

# Hash cracking
apt install hashcat john
```

### Git Repositories (clone to /opt/tools/)

```bash
git clone https://github.com/mverschu/CVE-2025-33073 /opt/tools/CVE-2025-33073
git clone https://github.com/dirkjanm/krbrelayx /opt/tools/krbrelayx
git clone https://github.com/Wh04m1001/DFSCoerce /opt/tools/DFSCoerce
git clone https://github.com/ShutdownRepo/ShadowCoerce /opt/tools/ShadowCoerce
git clone https://github.com/ShutdownRepo/pywhisker /opt/tools/pywhisker
git clone https://github.com/dirkjanm/PKINITtools /opt/tools/PKINITtools
git clone https://github.com/csandker/pxethiefy /opt/tools/pxethiefy
git clone https://github.com/garrettfoster13/sccmhunter /opt/tools/sccmhunter
git clone https://github.com/dirkjanm/mitm6 /opt/tools/mitm6
git clone https://github.com/Hackndo/pyGPOAbuse /opt/tools/pyGPOAbuse
git clone https://github.com/Hackndo/WebclientServiceScanner /opt/tools/WebclientServiceScanner
git clone https://github.com/p0dalirius/DHCPCoerce /opt/tools/DHCPCoerce
```

### Pipx Packages

```bash
pipx install coercer
pipx install wsuks --system-site-packages
```

### Quick Install (all deps on Kali)

```bash
# Install all APT packages
sudo apt install python3 impacket-scripts netexec nmap hashcat \
  tcpdump responder dsniff arp-scan certipy-ad bloodyad \
  smbclient atftp wimtools john

# Clone all required repos
for repo in mverschu/CVE-2025-33073 dirkjanm/krbrelayx \
  Wh04m1001/DFSCoerce ShutdownRepo/ShadowCoerce \
  ShutdownRepo/pywhisker dirkjanm/PKINITtools \
  csandker/pxethiefy garrettfoster13/sccmhunter \
  dirkjanm/mitm6 Hackndo/pyGPOAbuse \
  Hackndo/WebclientServiceScanner p0dalirius/DHCPCoerce; do
  sudo git clone https://github.com/$repo /opt/tools/$(basename $repo)
done

# Install Python deps for repos
for repo in pywhisker PKINITtools sccmhunter pxethiefy mitm6 pyGPOAbuse; do
  [ -f /opt/tools/$repo/requirements.txt ] && \
    pip3 install -r /opt/tools/$repo/requirements.txt
done

# Pipx packages
pipx install coercer
pipx install wsuks --system-site-packages

# Install ad-autopwn
sudo cp ad-autopwn.py /usr/local/bin/ad-autopwn
sudo chmod +x /usr/local/bin/ad-autopwn
```

## Tested Against

- **GOAD (Game of Active Directory)** — Orange Cyberdefense AD lab
- Validated on AWS eu-west-1 with GOAD-Light (3 VMs, 2 domains)
- Kerberoasted 3 accounts (auto-cracked with rockyou.txt)
- AS-REP roasted 1 account (auto-cracked)
- Found AD CS ESC8, DCSync 20 hashes + krbtgt

## Disclaimer

**For authorized penetration testing and security research only.**

This tool is designed for use by security professionals during authorized engagements. Unauthorized access to computer systems is illegal. Always obtain written permission before testing.

## Author

Triop AB — [https://triop.se](https://triop.se)

## License

MIT
