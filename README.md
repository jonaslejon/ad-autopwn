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

### Credential Harvesting
- **Kerberoasting** — extract and auto-crack SPN hashes (hashcat mode 13100/19700)
- **AS-REP Roasting** — crack accounts without pre-auth (hashcat mode 18200)
- **SCCM NAA theft** — extract Network Access Account credentials via sccmhunter

### Privilege Escalation
- **AD CS exploitation** — ESC1 through ESC16 via certipy (auto-enum + exploit)
- **Shadow Credentials** — msDS-KeyCredentialLink via ntlmrelayx or pywhisker
- **RBCD abuse** — Resource-Based Constrained Delegation (addcomputer + S4U2Proxy)
- **GPO abuse** — pyGPOAbuse scheduled task as SYSTEM
- **WebDAV coercion** — WebClient HTTP→LDAP relay (bypasses SMB signing)
- **DHCP coercion** — DHCP server machine account relay

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
./ad-autopwn.py --phase sniff --sniff-duration 60
./ad-autopwn.py --phase pxe
./ad-autopwn.py --phase sccm -u user -p pass -d corp.local --dc-ip 10.0.0.1

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

Runs on Kali Linux with standard tools:

```
# Core (required)
apt install python3 impacket-scripts netexec nmap hashcat

# Recommended
apt install tcpdump responder certipy-ad bloodyad dsniff arp-scan john

# Optional
pip install pywhisker coercer
```

## Tested Against

- **GOAD (Game of Active Directory)** — Orange Cyberdefense AD lab
- Validated on AWS eu-west-1 with GOAD-Light (3 VMs, 2 domains)
- Successfully: Kerberoasted 3 accounts, AS-REP roasted 1, found AD CS ESC8, DCSync 20 hashes + krbtgt

## Disclaimer

**For authorized penetration testing and security research only.**

This tool is designed for use by security professionals during authorized engagements. Unauthorized access to computer systems is illegal. Always obtain written permission before testing.

## Author

Triop AB — [https://triop.se](https://triop.se)

## License

For authorized security assessments only.
