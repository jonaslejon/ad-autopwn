# AD AutoPwn

**Zero-Auth to Domain Admin — Automated Active Directory Attack Chain**

A fully automated penetration testing tool that chains 25+ attack
techniques to compromise Active Directory environments. Designed for
authorized security assessments.

```
       _   ___      _       _       ___
      /_\ |   \    /_\ _  _| |_ ___| _ \__ __ ___ _
     / _ \| |) |  / _ \ || |  _/ _ \  _/\ V  V / ' \
    /_/ \_\___/  /_/ \_\_,_|\__\___/_|   \_/\_/|_||_|

    ⚡ Zero-Auth to Domain Admin — Attack Chain
    Discover | Sniff | ARP | WPAD | WSUS | PXE | AD CS | SCCM | Roast
    BloodHound | Reflect | Loot | RBCD+KCD | DCSync | DPAPI
```

## Features

### Pre-auth username & credential discovery (zero creds)
- **kerbrute** KRB-AS-REQ user enumeration (lockout-safe)
- **CLDAP NetLogon ping** username enumeration (lockout-safe)
- **AS-REP roast** of all candidates (free hashes for accounts with `DONT_REQ_PREAUTH`)
- **pre2k auto-test** (Windows 2000 compatibility default-password machines)
- **Single-password spray** (lockout-aware, opt-in via `--spray-password`)

### Layer-2 / passive zero-auth attacks
- **Passive network sniffing** — WPAD, WSUS, PXE, LLMNR, DHCPv6, TFTP, SCCM ProxyDHCP detection
- **ARP spoof + NTLM relay** — capture and crack NTLMv2 hashes
- **WPAD poisoning** — mitm6 / Responder IPv6 DNS hijack
- **WSUS relay** — intercept Windows Update NTLM auth (port 8530/8531)
- **PXE boot credential theft** — extract creds from boot images via TFTP/WIM
- **NTLM theft file drops** — `.library-ms` / `.theme` / `.url` files on writable shares
- **WebDAV coercion** — WebClient HTTP → LDAP relay (bypasses SMB signing)
- **DHCP coercion** — DHCP server machine account relay

### Authentication-reflection bypass (Synacktiv 2026)
- **CVE-2025-58726 ghost-SPN** Kerberos AP-REQ reflection (auto-fired by BloodHound auto-action)
- **CVE-2026-24294 LPE** — SMB-on-arbitrary-tcpport reflection (Win11 24H2 / Server 2025 pre-March-2026)
- **CVE-2026-26128 LPE** — Kerberos loopback via Unicode SPN
- **Unicode-SPN fallback** when CVE-2025-33073 path is patched

### Credential harvesting (post-auth)
- **Kerberoasting** — extract and auto-crack SPN hashes (hashcat mode 13100/19700)
- **AS-REP Roasting** — crack accounts without pre-auth (hashcat mode 18200)
- **Timeroast** — SNTP-MS hashes from any domain-joined machine (hashcat mode 31300)
- **LAPS password recovery** + **userPassword LDAP attribute** + **description-leaked passwords** (mined from nxc enrichment battery)
- **SCCM NAA theft** — extract Network Access Account credentials via sccmhunter

### Graph-driven attack chains (BloodHound)
- **`bloodhound-python -c All`** collection + ZIP analysis
- **High-value findings** — Domain/Enterprise/Schema Admins, Kerberoastable, AS-REP roastable, unconstrained delegation, RBCD inbound, LAPS, AdminCount
- **Actionable-edge analysis** — controlled-principal closure (you + transitive group memberships) → ACE edges where you are the principal: `WriteSPN`, `AddKeyCredentialLink`, `GenericAll/Write`, `WriteDacl/Owner`, `WriteAccountRestrictions`, `AddAllowedToAct`, `ForceChangePassword`
- **Auto-action chain** — automatically fires matching primitives:
  - `WriteSPN → ghost-SPN upgrade` (CVE-2025-58726)
  - `AddKeyCredentialLink → shadow credentials → PKINIT → NT hash`
  - `GenericAll / WriteAccountRestrictions on Computer → RBCD chain → admin TGS`

### Privilege escalation primitives
- **AD CS exploitation** — ESC1-ESC16 via certipy (auto-enum + exploit)
  - ESC8 (web-enrollment relay)
  - ESC9/ESC10 UPN-swap (CVE-2022-26923 bypass)
  - ESC4 template modify+exploit+restore (cwd-safe)
  - Certihound enumeration with certipy fallback (NT-hash auth)
- **Shadow Credentials** — msDS-KeyCredentialLink via ntlmrelayx or pywhisker
- **RBCD abuse** — Resource-Based Constrained Delegation (addcomputer + S4U2Self + S4U2Proxy)
- **RBCD+KCD chain orchestrator** — full WriteSPN → ghost-SPN → RBCD → S4U2Proxy → `-altservice` rewrite, in one phase
- **TGS sname rewrite** (tgssub-style KCD protocol-transition bypass) — standalone or inline via `-altservice`
- **Dollar Ticket** — KDC's automatic `$`-suffix retry on principal lookup → TGT for Linux user via auto-created `<user>$` machine account → GSSAPI SSH
- **GPO abuse** — pyGPOAbuse scheduled task as SYSTEM

### Domain compromise
- **DCSync** — full domain hash dump via impacket-secretsdump
- **DPAPI backup key** — extract domain DPAPI key for offline credential decryption
- **AppLocker bypass** — LOLBins (mshta, certutil, regsvr32, etc.) + WSUS signed delivery
- **WSUS update injection** — push malicious Windows Updates via wsuks

### Post-exploitation loot
- **Process command-line harvest** — `Get-CimInstance Win32_Process` via `nxc -x`; regex-greps for passwords in mysql/sqlcmd/runas/KeePass/`--password` style flags
- **KeePass vault discovery + crack** — find `*.kdbx` in `C:\Users`, download via smbclient, `keepass2john | hashcat -m 13400`

## Usage

```bash
# Fully automated — zero-cred chain (auto-discovers everything)
sudo ./ad-autopwn.py

# With credentials — full chain
./ad-autopwn.py -u jsmith -p 'P@ss123' -d corp.local --dc-ip 10.0.0.1

# AWS / VPC labs (Layer 2 attacks blocked) — auto-discovery still works
sudo ./ad-autopwn.py --no-arp --no-wpad

# Pre-auth credential discovery (lockout-safe)
sudo ./ad-autopwn.py --phase discover --no-arp --no-wpad

# BloodHound graph collection + automatic high-value analysis
./ad-autopwn.py --phase bloodhound -u user -p pass -d corp.local \
                --dc-ip 10.0.0.1 --dc-fqdn dc01.corp.local

# Dollar Ticket — TGT for 'root' via auto-created root$ machine acct
./ad-autopwn.py -u user -p pass -d corp.local --dc-ip 10.0.0.1 \
                --phase dollar-ticket --target-user root

# RBCD+KCD chain — full ghost-SPN + RBCD + altservice rewrite, one shot
./ad-autopwn.py -u user -p pass -d corp.local --dc-ip 10.0.0.1 \
                --phase rbcd-kcd -T VHAGAR$ --alt-spn HTTP/vhagar.corp.local

# AppLocker bypass
./ad-autopwn.py -u user -p pass --applocker --lolbin mshta --custom-cmd "whoami"

# Dry run (print every command, run nothing — even background processes)
./ad-autopwn.py --dry-run -u user -p pass -d corp.local --dc-ip 10.0.0.1
```

## Available phases

| Phase             | Auth   | Description |
|-------------------|--------|-------------|
| `full`            | optional | Complete automated chain (auto-detects with or without creds) |
| `sniff`           | none   | Passive L2 traffic discovery |
| `discover`        | none   | kerbrute + CLDAP + AS-REP + pre2k + (opt-in) spray |
| `arp`             | none   | ARP spoof + NTLM capture |
| `wpad`            | none   | WPAD/LLMNR poisoning (mitm6 / Responder) |
| `wsus`            | none   | WSUS NTLM relay |
| `pxe`             | none   | PXE boot credential theft |
| `enum`            | yes    | Target enumeration (relay targets, unconstrained delegation, WebClient hosts) |
| `enrich`          | yes    | nxc 13-module battery (LAPS, timeroast, MAQ, nopac, zerologon, …) + auto-consumer |
| `bloodhound`      | yes    | `bloodhound-python -c All` + analysis + auto-action chains |
| `roast`           | yes    | Kerberoast + AS-REP Roast |
| `adcs`            | yes    | AD CS exploitation (ESC1-ESC16) |
| `sccm`            | yes    | SCCM NAA credential theft |
| `exploit`         | yes    | NTLM reflection / coercion exploit on a specific target |
| `dcsync`          | yes (DA) | Domain hash dump |
| `loot`            | yes    | Process cmdline harvest + KeePass discovery/crack |
| `tgs-rewrite`     | none   | Offline ccache sname rewrite (tgssub-style KCD bypass) |
| `dollar-ticket`   | yes    | KDC `$`-suffix retry attack (Linux GSSAPI target) |
| `rbcd-kcd`        | yes    | Full RBCD+KCD chain orchestrator (WriteSPN → ghost → RBCD → S4U+altservice) |
| `reflect-tcpport` | yes    | CVE-2026-24294 LPE primitive (SMB-on-tcpport) |
| `reflect-loopback`| yes    | CVE-2026-26128 LPE primitive (Kerberos loopback via Unicode SPN) |
| `kerb-reflect`    | yes    | CVE-2025-58726 ghost-SPN AP-REQ reflection |

## Dependencies

### APT (Kali Linux)

```bash
apt install python3 impacket-scripts netexec nmap hashcat tcpdump \
  responder dsniff arp-scan certipy-ad bloodyad bloodhound.py \
  smbclient atftp wimtools john seclists
```

### Git repositories (clone to `/opt/tools/`)

```bash
git clone https://github.com/mverschu/CVE-2025-33073        /opt/tools/CVE-2025-33073
git clone https://github.com/dirkjanm/krbrelayx              /opt/tools/krbrelayx
git clone https://github.com/Wh04m1001/DFSCoerce             /opt/tools/DFSCoerce
git clone https://github.com/ShutdownRepo/ShadowCoerce       /opt/tools/ShadowCoerce
git clone https://github.com/ShutdownRepo/pywhisker          /opt/tools/pywhisker
git clone https://github.com/dirkjanm/PKINITtools            /opt/tools/PKINITtools
git clone https://github.com/csandker/pxethiefy              /opt/tools/pxethiefy
git clone https://github.com/garrettfoster13/sccmhunter      /opt/tools/sccmhunter
git clone https://github.com/dirkjanm/mitm6                  /opt/tools/mitm6
git clone https://github.com/Hackndo/pyGPOAbuse              /opt/tools/pyGPOAbuse
git clone https://github.com/Hackndo/WebclientServiceScanner /opt/tools/WebclientServiceScanner
git clone https://github.com/almandin/Certihound             /opt/tools/Certihound
```

### Pipx packages

```bash
pipx install coercer
pipx install wsuks --system-site-packages
```

### Other binaries

- `kerbrute` — grab the latest binary from
  <https://github.com/ropnop/kerbrute/releases> — install to `/usr/local/bin/`
- `userenum-cldap` — companion CLDAP NetLogon-ping enumerator (lives in
  this repo as `userenum-cldap.py`; install to `/usr/local/bin/userenum-cldap`)
- `asn1tools` — `pip install asn1tools` (CLDAP enum runtime dep)

### Quick install (all deps on Kali)

```bash
# APT packages
sudo apt install python3 impacket-scripts netexec nmap hashcat tcpdump \
  responder dsniff arp-scan certipy-ad bloodyad bloodhound.py \
  smbclient atftp wimtools john seclists

# All required repos
for repo in mverschu/CVE-2025-33073 dirkjanm/krbrelayx \
            Wh04m1001/DFSCoerce ShutdownRepo/ShadowCoerce \
            ShutdownRepo/pywhisker dirkjanm/PKINITtools \
            csandker/pxethiefy garrettfoster13/sccmhunter \
            dirkjanm/mitm6 Hackndo/pyGPOAbuse \
            Hackndo/WebclientServiceScanner almandin/Certihound; do
  sudo git clone "https://github.com/$repo" "/opt/tools/$(basename $repo)"
done

# Python deps for repos that need them
for repo in pywhisker PKINITtools sccmhunter pxethiefy mitm6 pyGPOAbuse Certihound; do
  [ -f "/opt/tools/$repo/requirements.txt" ] && \
    pip3 install --break-system-packages -r "/opt/tools/$repo/requirements.txt"
done

# Pipx packages
pipx install coercer
pipx install wsuks --system-site-packages

# kerbrute (ropnop) binary
sudo wget -q -O /usr/local/bin/kerbrute \
  https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
sudo chmod +x /usr/local/bin/kerbrute

# CLDAP userenum runtime dep
sudo pip3 install --break-system-packages asn1tools

# userenum-cldap companion script (this repo)
sudo wget -q -O /usr/local/bin/userenum-cldap \
  https://raw.githubusercontent.com/jonaslejon/ad-autopwn/main/userenum-cldap.py
sudo chmod +x /usr/local/bin/userenum-cldap

# ad-autopwn itself
sudo cp ad-autopwn.py /usr/local/bin/ad-autopwn
sudo chmod +x /usr/local/bin/ad-autopwn
```

`check_prerequisites()` runs at the top of every invocation and prints
a green ✅ / yellow ⚠️ status for every tool the script touches, with
install hints for anything missing.

## Tested against

- **GOAD-Light** (Game of Active Directory, Orange Cyberdefense)
  on AWS `eu-west-1` — full v4.10.0 phase coverage verified
  end-to-end. Auto-discovery on AWS now works with literally just
  `--no-arp --no-wpad` (everything else — interface, attacker IP,
  domain, DC IP, DC FQDN — is auto-detected via subnet sweep + dig
  fallback to `@<dc_ip>`).
- BloodHound auto-action chain proven against the canonical
  `stannis.baratheon → GenericAll → KINGSLANDING$` edge: from a single
  low-priv credential to admin TGS on the DC in 5 seconds.
- DCSync extracted 20 credentials including `krbtgt` — golden ticket viable.

## Safety

- `--dry-run` prints every command (foreground **and** background) without
  executing — won't spawn ARP spoofers, mitm6, Responder, or ntlmrelayx.
- ESC4 template modifications are wrapped in `try/finally` with `os.chdir`
  to ensure restore lands in the right directory on any exit path.
- AD CS / RBCD / ghost-SPN chains attempt cleanup of planted records on
  completion (DNS records, Trusted-For-Delegation UAC bits, ghost SPNs).
  Machine accounts you create stay in AD — see operator notes in the
  run output for cleanup commands.
- `--no-cleanup` keeps everything for forensic review.

## Disclaimer

**For authorized penetration testing and security research only.**

This tool is designed for use by security professionals during
authorized engagements. Unauthorized access to computer systems is
illegal. Always obtain written permission before testing.

## Author

Triop AB — [https://triop.se](https://triop.se)

## License

MIT
